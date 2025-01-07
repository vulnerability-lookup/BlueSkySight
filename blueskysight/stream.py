import asyncio
import io

import websockets

from blueskysight.utils import (
    enumerate_mst_records,
    extract_vulnerability_ids,
    get_post_url,
    parse_car,
    parse_dag_cbor_object,
    push_sighting_to_vulnerability_lookup,
)


async def stream():
    """
    Connects to the Bluesky firehose WebSocket stream, processes incoming frames,
    and extracts vulnerability sightings.
    Includes automatic reconnection handling.
    """
    while True:
        try:
            print("Connecting to Bluesky firehose…")
            async with websockets.connect(
                "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos",
                ping_interval=20,
                ping_timeout=10,
            ) as websocket:
                print("Connection established.")
                await process_stream(websocket)
        except websockets.ConnectionClosedError as e:
            print(f"Connection closed unexpectedly: {e}. Reconnecting…")
        except Exception as e:
            print(f"Unexpected error: {e}. Reconnecting…")
        finally:
            await asyncio.sleep(5)  # Delay before retrying to connect


async def process_stream(websocket):
    """
    Processes the WebSocket stream and extracts relevant data.
    """
    while True:
        try:
            res = await websocket.recv()
            stream = io.BytesIO(res)

            # Parse the header of the DAG CBOR object
            head = await parse_dag_cbor_object(stream)
            if head.get("t") == "#commit":
                # Parse the body of the DAG CBOR object
                body = await parse_dag_cbor_object(stream)
                root, nodes = await parse_car(
                    io.BytesIO(body["blocks"]), len(body["blocks"])
                )

                for op in body.get("ops", []):
                    if (
                        op["path"].startswith("app.bsky.feed.post/")
                        and op["action"] == "create"
                    ):
                        await process_op(op, body, root, nodes)
        except websockets.ConnectionClosedError:
            print("WebSocket connection lost during streaming.")
            raise
        except Exception as e:
            print(f"Error while processing stream: {e}")


async def process_op(op, body, root, nodes):
    """
    Processes an operation from the stream and extracts vulnerabilities.
    """
    signed_commit = nodes[root]
    records = await enumerate_mst_records(nodes, nodes[signed_commit["data"]])
    post = nodes[records[op["path"].encode()]]
    uri = f'at://{body["repo"]}/{op["path"]}'
    content = post.get("text", "")

    if content:
        vulnerability_ids = extract_vulnerability_ids(content)
        if vulnerability_ids:
            url = await get_post_url(uri)
            print(f"Post URL: {url}")
            print(
                "Vulnerability IDs detected:",
                ", ".join(vulnerability_ids),
            )
            push_sighting_to_vulnerability_lookup(url, vulnerability_ids)


def main():
    asyncio.run(stream())


if __name__ == "__main__":
    main()
