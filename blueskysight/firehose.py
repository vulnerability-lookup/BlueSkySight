import asyncio
import json
import struct
import typing as t
from base64 import b32encode
from io import BytesIO

import websockets

from blueskysight import config
from blueskysight.utils import (
    extract_vulnerability_ids,
    get_post_url,
    push_sighting_to_vulnerability_lookup,
)

BSKY_FIREHOSE = "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos"


class JSONEncoderWithBytes(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        return super().default(obj)


def read_uvarint(stream: t.IO[bytes]) -> int:
    """
    Read a multiformats unsigned varint from the given stream.

    See the specification at https://github.com/multiformats/unsigned-varint

    And the reference Go implementation at https://github.com/multiformats/go-varint
    """
    shift = 0
    result = 0

    while True:
        byte = stream.read(1)
        if not byte:
            raise ValueError("Unexpected end of input while parsing varint.")
        byte_val = byte[0]
        result |= (byte_val & 0x7F) << shift
        shift += 7
        if not (byte_val & 0x80):
            break

    return result


def multibase_encode_b(b: bytes) -> str:
    """
    Encode the given byte string using RFC 4648 base32 encoding, case-insensitive,
    without padding. Add a multibase prefix 'b' to indicate the encoding.

    See the raw encoding specification at https://tools.ietf.org/html/rfc4648#section-6

    See the multibase specification at https://github.com/multiformats/multibase
    """
    b32_str = b32encode(b).decode("ascii").replace("=", "").lower()
    return f"b{b32_str}"


def encode_dag_cbor_cid(value: bytes) -> str:
    """
    Convert a CID tag value to a base32 encoded CID string with a multibase prefix.

    This is the default representation for CIDs used elsewhere in the ATProto,
    and in examples, so it should be familiar.

    A CID (Content Identifier) is a multiformats self-describing
    content-addressed identifier.

    See the specification for CIDs in general at:
    https://github.com/multiformats/cid

    See the specification for CIDs found in DAG_CBOR (aka tag 42) at:
    https://github.com/ipld/cid-cbor/

    Other useful details about CIDs can be found at:
    https://docs.ipfs.tech/concepts/content-addressing/#cid-versions

    And the reference Go implementation at: https://github.com/ipfs/go-cid
    """
    if len(value) != 37:
        raise NotImplementedError("Only DAG_CBOR encoded CIDs are supported.")
    multibase_prefix = value[0]
    if multibase_prefix != 0x00:  # Multibase identity prefix
        raise ValueError("DAG_CBOR CIDs must have a multibase identity prefix.")
    cid_data = value[1:]
    return multibase_encode_b(cid_data)


# See the IANA registry for CBOR tags at
# https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
CID_CBOR_TAG = 42


def read_dag_cbor(stream: t.IO[bytes]) -> t.Any:
    """
    Decodes a DAG_CBOR encoded byte string from the given stream.

    The base CBOR specification is RFC 8949; details at https://cbor.io

    There's a useful CBOR playground at https://cbor.me

    DAG_CBOR is a more restrictive variant of CBOR defined in IPLD; see:
    https://ipld.io/specs/codecs/dag-cbor/spec/

    """
    initial_byte = stream.read(1)
    if not initial_byte:
        raise ValueError("Unexpected end of input while decoding CBOR.")
    initial_value = initial_byte[0]

    major_type = initial_value >> 5
    additional_info = initial_value & 0x1F

    if major_type == 0:  # Unsigned integer
        return read_cbor_uint(stream, additional_info)
    elif major_type == 1:  # Negative integer
        return -1 - read_cbor_uint(stream, additional_info)
    elif major_type == 2:  # Byte string
        length = read_cbor_uint(stream, additional_info)
        return stream.read(length)
    elif major_type == 3:  # Text string
        length = read_cbor_uint(stream, additional_info)
        return stream.read(length).decode("utf-8")
    elif major_type == 4:  # Array
        length = read_cbor_uint(stream, additional_info)
        return [read_dag_cbor(stream) for _ in range(length)]
    elif major_type == 5:  # Map
        length = read_cbor_uint(stream, additional_info)
        return {read_dag_cbor(stream): read_dag_cbor(stream) for _ in range(length)}
    elif major_type == 6:  # Tagged item
        # DAG_CBOR *requires* all tags to be of type 42 (IPLD CID)
        # We convert these to base32 CID strings by default
        tag = read_cbor_uint(stream, additional_info)
        if tag != CID_CBOR_TAG:
            raise ValueError(f"Unsupported CBOR tag {tag} in DAG_CBOR.")
        value = read_dag_cbor(stream)
        return encode_dag_cbor_cid(value)
    elif major_type == 7:  # Simple values and floats
        if additional_info == 20:  # False
            return False
        elif additional_info == 21:  # True
            return True
        elif additional_info == 22:  # Null
            return None
        elif additional_info == 23:  # Undefined
            # Technically, this is not supported in DAG_CBOR. But we'll allow it.
            return None  # CBOR 'undefined' is translated as None
        elif additional_info == 25:  # Half-precision float (not implemented)
            raise NotImplementedError("Half-precision floats are not supported.")
        elif additional_info == 26:  # Single-precision float
            return struct.unpack(">f", stream.read(4))[0]
        elif additional_info == 27:  # Double-precision float
            return struct.unpack(">d", stream.read(8))[0]
        else:
            raise ValueError(
                f"Unsupported simple value with additional info {additional_info}."
            )
    else:
        raise ValueError(f"Unsupported DAG_CBOR major type {major_type}.")


def read_cbor_uint(stream: t.IO[bytes], additional_info: int) -> int:
    """
    Parses an unsigned integer from the stream based on the additional information.

    See https://cbor.io/spec.html#ints for details.
    """
    if additional_info < 24:
        return additional_info
    elif additional_info == 24:
        return struct.unpack(">B", stream.read(1))[0]
    elif additional_info == 25:
        return struct.unpack(">H", stream.read(2))[0]
    elif additional_info == 26:
        return struct.unpack(">I", stream.read(4))[0]
    elif additional_info == 27:
        return struct.unpack(">Q", stream.read(8))[0]
    else:
        raise ValueError(
            f"Unsupported additional information for integer parsing: {additional_info}."
        )


def read_carv1(stream: t.IO[bytes]) -> t.Any:
    """
    Decodes a CARv1 encoded byte string from the given stream.

    CARv1 is a format used for content-addressed archives in IPLD.

    See the specification at: https://ipld.io/specs/transport/car/carv2/
    (This is the CARv2 specification, but CARv1 is a subset of it.)

    See the reference Go implementation at: https://github.com/ipld/go-car
    """
    # Dict containing the CAR header, with a 'roots' and a 'version' key
    header = read_car_header(stream)
    car_version = header["version"]
    if car_version != 1:
        raise ValueError(f"Unsupported CAR version {car_version}.")
    blocks = []
    while True:
        try:
            node = read_car_node(stream)
            blocks.append(node)
        except ValueError:
            break
    return {"header": header, "blocks": blocks}


def read_car_header(stream: t.IO[bytes]) -> dict:
    """Read the header of any CAR version from the given stream."""
    cbor_bytes = read_car_ld(stream)
    with BytesIO(cbor_bytes) as bio:
        return read_dag_cbor(bio)


def read_car_node(stream: t.IO[bytes]) -> dict:
    """Read a single CAR node from the given stream."""
    bytes = read_car_ld(stream)
    cid_bytes = bytes[:36]
    cid_str = encode_dag_cbor_cid(b"\00" + cid_bytes)
    data_cbor = bytes[36:]
    data = read_dag_cbor(BytesIO(data_cbor))
    return {"cid": cid_str, "data": data}


def read_car_ld(stream: t.IO[bytes]) -> bytes:
    """Read the CAR link data section from the given stream."""
    length = read_uvarint(stream)
    return stream.read(length)


def read_firehose_frame(frame: bytes) -> tuple[dict, dict]:
    """
    Read a single frame from the BSKY firehose stream.

    Each frame contains two CBOR-encoded DAG structures: the header,
    and the body of the message.
    """
    with BytesIO(frame) as bio:
        # Read the frame header and body.
        #
        # The header is a dict that contains the message type, which is one of:
        # "#commit", "#account", "#identity", "#handle", "#tombstone"
        #
        # The body is a dict that contains the message data, which is specific
        # to the type. If you're interested, for instances, in posts, you want
        # "#commit" messages that contain a "create" operation to the
        # "app.bsky.feed.post/*" path.
        header, body = read_dag_cbor(bio), read_dag_cbor(bio)
        # If this frame contains an op that includes blocks
        # (for instance, a repo #commit), we need to decode the
        # blocks from CARv1 format
        #
        # The CAR header will contain a "root" reference (CID) to
        # the top-level data object, which is described in "Commit Objects"
        # in the atproto documentation, here:
        #
        # https://atproto.com/specs/repository
        #
        # Our code returns a sequence of nodes in the order they appear
        # in the archive; from them and their various CID references, you
        # could construct a full MST tree as described in that link.
        # This would be useful if you wanted to fully verify the message.
        #
        # On the other hand, you can also easily just filter through the
        # blocks to find something you're looking for, like a specific
        # type of object like a post (where "$type" is "app.bsky.feed.post")
        body_blocks = body.get("blocks")
        if isinstance(body_blocks, bytes):
            body["blocks"] = read_carv1(BytesIO(body_blocks))
        return header, body


async def firehose():
    """
    Connects to the Bluesky firehose WebSocket stream, processes frames,
    and extracts vulnerability sightings from textual content.
    """
    while True:
        try:
            print("Connecting to the Bluesky firehose…")
            async with websockets.connect(
                BSKY_FIREHOSE, ping_interval=20, ping_timeout=10
            ) as ws:
                print("Connection established.")
                await process_firehose(ws)
        except websockets.ConnectionClosedError as e:
            print(f"Connection closed unexpectedly: {e}. Reconnecting…")
        except Exception as e:
            print(f"Unexpected error: {e}. Reconnecting…")
        finally:
            await asyncio.sleep(5)  # Delay before attempting reconnection


async def process_firehose(ws):
    """
    Processes incoming frames from the WebSocket stream.
    """
    while True:
        try:
            cbor_frame = await ws.recv()
            header, body = read_firehose_frame(cbor_frame)
            if (
                header.get("t") == "#commit"
                and body.get("repo", "") not in config.ignore
            ):
                await process_commit_frame(body)
        except websockets.ConnectionClosedError:
            print("WebSocket connection lost during processing.")
            raise
        except Exception as e:
            print(f"Error while processing frame: {e}")


async def process_commit_frame(body):
    """
    Processes a #commit frame to extract relevant textual content and vulnerability sightings.
    """
    repo = body.get("repo", "")
    ops = body.get("ops", [])
    blocks = body.get("blocks", {}).get("blocks", [])

    for op in ops:
        if op.get("action") == "create" and op.get("path", "").startswith(
            "app.bsky.feed.post/"
        ):
            uri = f'at://{repo}/{op["path"]}'
            await process_blocks(uri, blocks)


async def process_blocks(uri, blocks):
    """
    Processes blocks to find textual content and extract vulnerability sightings.
    """
    # Extract only blocks containing textual content
    textual_blocks = extract_textual_content(blocks)

    for block in textual_blocks:
        content = block["data"]["text"]
        if content:
            vulnerability_ids = extract_vulnerability_ids(content)
            if vulnerability_ids:
                print(f"Post content: {content}")
                url = await get_post_url(uri)
                print(f"Post URL: {url}")
                print(f"Vulnerability IDs detected: {', '.join(vulnerability_ids)}")
                push_sighting_to_vulnerability_lookup(url, vulnerability_ids)


def extract_textual_content(blocks):
    """
    Filters blocks to extract only those containing textual content.
    """
    return [
        block
        for block in blocks
        if block["data"].get("$type") == "app.bsky.feed.post"
        and "text" in block["data"]
    ]


def main():
    asyncio.run(firehose())


if __name__ == "__main__":
    main()
