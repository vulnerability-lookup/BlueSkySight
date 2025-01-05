import argparse
import asyncio
import json
import os
import platform
import typing as t
import websockets
from pathlib import Path
from urllib.parse import urlencode

import zstandard as zstd

from blueskysight.utils import (
    extract_vulnerability_ids,
    get_post_url,
    push_sighting_to_vulnerability_lookup,
)

PUBLIC_URL_FMT = "wss://jetstream{instance}.{geo}.bsky.network/subscribe"


def get_public_jetstream_base_url(
    geo: t.Literal["us-west", "us-east"] = "us-west",
    instance: int = 1,
) -> str:
    """Return a public Jetstream URL with the given options."""
    return PUBLIC_URL_FMT.format(geo=geo, instance=instance)


def get_jetstream_query_url(
    base_url: str,
    collections: t.Sequence[str],
    dids: t.Sequence[str],
    cursor: int,
    compress: bool,
) -> str:
    """Return a Jetstream URL with the given query parameters."""
    query = [("wantedCollections", collection) for collection in collections]
    query += [("wantedDids", did) for did in dids]
    if cursor:  # Only include the cursor if it is non-zero.
        query.append(("cursor", str(cursor)))
    if compress:
        query.append(("compress", "true"))
    query_enc = urlencode(query)
    return f"{base_url}?{query_enc}" if query_enc else base_url


#
# Utilities to manage zstd decompression of data (use the --compress flag to enable)
#

# Jetstream uses a custom zstd dict to improve compression; here's where to find it:
ZSTD_DICT_URL = "https://raw.githubusercontent.com/bluesky-social/jetstream/main/pkg/models/zstd_dictionary"


def get_cache_directory(app_name: str) -> Path:
    """
    Determines the appropriate cache directory for the application, cross-platform.

    Args:
        app_name (str): The name of your application.

    Returns:
        Path: The path to the cache directory.
    """
    if platform.system() == "Windows":
        # Use %LOCALAPPDATA% for Windows
        base_cache_dir = os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local")
    else:
        # Use XDG_CACHE_HOME or fallback to ~/.cache for Unix-like systems
        base_cache_dir = os.getenv("XDG_CACHE_HOME", Path.home() / ".cache")

    cache_dir = Path(base_cache_dir) / app_name
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def download_zstd_dict(zstd_dict_path: Path):
    """
    Download the Zstandard dictionary from the Jetstream repository.

    Args:
        zstd_dict_path (Path): The path to save the Zstandard dictionary.
    """
    import httpx

    with httpx.stream("GET", ZSTD_DICT_URL) as response:
        with zstd_dict_path.open("wb") as f:
            for chunk in response.iter_bytes():
                f.write(chunk)


def get_zstd_decompressor() -> zstd.ZstdDecompressor:
    """Get a Zstandard decompressor with a pre-trained dictionary."""
    cache_dir = get_cache_directory("jetstream")
    cache_dir.mkdir(parents=True, exist_ok=True)
    zstd_dict_path = cache_dir / "zstd_dict.bin"

    if not zstd_dict_path.exists():
        download_zstd_dict(zstd_dict_path)

    with zstd_dict_path.open("rb") as f:
        zstd_dict = f.read()

    dict_data = zstd.ZstdCompressionDict(zstd_dict)
    return zstd.ZstdDecompressor(dict_data=dict_data)


#
# Code to resolve an ATProto handle to a DID
#


def raw_handle(handle: str) -> str:
    """Returns a raw ATProto handle, without the @ prefix."""
    return handle[1:] if handle.startswith("@") else handle


def resolve_handle_to_did_dns(handle: str) -> str | None:
    """
    Resolves an ATProto handle to a DID using DNS.

    Returns None if the handle is not found.

    Raises exceptions if network requests fail.
    """
    import dns.resolver

    try:
        answers = dns.resolver.resolve(f"_atproto.{handle}", "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None

    for answer in answers:
        txt = answer.to_text()
        if txt.startswith('"did='):
            return txt[5:-1]

    return None


def resolve_handle_to_did_well_known(handle: str) -> str | None:
    """
    Resolves an ATProto handle to a DID using a well-known endpoint.

    Returns None if the handle is not found.

    Raises exceptions if network requests fail.
    """
    import httpx

    try:
        response = httpx.get(f"https://{handle}/.well-known/atproto-did", timeout=5)
        response.raise_for_status()
    except (httpx.ConnectError, httpx.HTTPStatusError, httpx.TimeoutException):
        return None

    return response.text.strip()


def resolve_handle_to_did(handle: str) -> str | None:
    """
    Resolves an ATProto handle, like @bsky.app, to a DID.

    We resolve as follows:

    1. Check the _atproto DNS TXT record for the handle.
    2. If not found, query for a .well-known/atproto-did

    Returns None if the handle is not found.

    Raises exceptions if network requests fail.
    """
    handle = raw_handle(handle)
    maybe_did = resolve_handle_to_did_dns(handle)
    maybe_did = maybe_did or resolve_handle_to_did_well_known(handle)
    return maybe_did


def require_resolve_handle_to_did(handle: str) -> str:
    """
    Resolves an ATProto handle to a DID, raising an error if not found.

    Raises a ValueError if the handle is not found.
    """
    did = resolve_handle_to_did(handle)
    if did is None:
        raise ValueError(f"Could not resolve handle '{handle}' to a DID.")
    return did


async def jetstream(
    collections: t.Sequence[str] = ["app.bsky.feed.post"],
    dids: t.Sequence[str] = [],
    handles: t.Sequence[str] = [],
    cursor: int = 0,
    base_url: str | None = None,
    geo: t.Literal["us-west", "us-east"] = "us-west",
    instance: int = 1,
    compress: bool = False,
):
    """Emit Jetstream JSON messages, one per line, with reconnection handling."""
    # Resolve handles and form the final list of DIDs to subscribe to.
    handle_dids = [require_resolve_handle_to_did(handle) for handle in handles]
    dids = list(dids) + handle_dids

    # Build the Zstandard decompressor if compression is enabled.
    decompressor = get_zstd_decompressor() if compress else None

    # Form the Jetstream URL to connect to.
    base_url = base_url or get_public_jetstream_base_url(geo, instance)
    url = get_jetstream_query_url(base_url, collections, dids, cursor, compress)

    while True:
        try:
            print(f"Connecting to the Bluesky Jetstream at {url}…")
            async with websockets.connect(url, ping_interval=20, ping_timeout=10) as ws:
                print("Connection established. Listening for messages…")
                while True:
                    try:
                        if compress and decompressor:
                            message = await ws.recv()
                            with decompressor.stream_reader(message) as reader:
                                message = reader.read()
                            message = message.decode("utf-8")
                        else:
                            message = await ws.recv()

                        json_message = json.loads(message)

                        # Process the incoming message
                        await process_jetstream_message(json_message)

                    except websockets.ConnectionClosedError as e:
                        print(f"WebSocket connection closed: {e}")
                        break  # Exit to reconnect
                    except Exception as e:
                        print(f"Error processing message: {e}")

        except Exception as e:
            print(f"Connection error: {e}. Reconnecting in 5 seconds…")
            await asyncio.sleep(5)


async def process_jetstream_message(json_message):
    """
    Processes a Jetstream message and extracts vulnerabilities.
    """
    if "commit" in json_message and json_message["commit"]["operation"] == "create":
        content = json_message["commit"]["record"].get("text", "")
        if content:
            vulnerability_ids = extract_vulnerability_ids(content)
            if vulnerability_ids:
                uri = f'at://{json_message["did"]}/app.bsky.feed.post/{json_message["commit"]["rkey"]}'
                url = await get_post_url(uri)
                print(f"Post content: {content}")
                print(f"Post URL: {url}")
                print(f"Vulnerability IDs detected: {', '.join(vulnerability_ids)}")
                push_sighting_to_vulnerability_lookup(url, vulnerability_ids)


def main():
    parser = argparse.ArgumentParser(
        prog="BlueSkySight-Jetstream", description="Connect to a Jetstream service."
    )
    parser.add_argument(
        "--collections",
        default=["app.bsky.feed.post"],
        help="The collections to subscribe to. If not provided, subscribe to all.",
    )
    parser.add_argument(
        "--geo",
        default="us-west",
        choices=["us-east", "us-west"],
        help="Region of the Jetstream service.",
    )
    parser.add_argument(
        "--instance",
        default="1",
        choices=["1", "2"],
        help="Instance of the Jetstream service.",
    )

    arguments = parser.parse_args()

    asyncio.run(
        jetstream(
            collections=arguments.collections,
            geo=arguments.geo,
            instance=arguments.instance,
        )
    )


if __name__ == "__main__":
    main()
