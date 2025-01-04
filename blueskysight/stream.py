import asyncio
import io
import re

import websockets
from pyvulnerabilitylookup import PyVulnerabilityLookup

from blueskysight import config
from blueskysight.utils import (
    enumerate_mst_records,
    get_post_url,
    parse_car,
    parse_dag_cbor_object,
    remove_case_insensitive_duplicates,
)

vulnerability_pattern = re.compile(
    r"\b(CVE-\d{4}-\d{4,})\b"  # CVE pattern
    r"|\b(GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4})\b"  # GHSA pattern
    r"|\b(PYSEC-\d{4}-\d{2,5})\b"  # PYSEC pattern
    r"|\b(GSD-\d{4}-\d{4,5})\b"  # GSD pattern
    r"|\b(wid-sec-w-\d{4}-\d{4})\b"  # CERT-Bund pattern
    r"|\b(cisco-sa-\d{8}-[a-zA-Z0-9]+)\b"  # CISCO pattern
    r"|\b(RHSA-\d{4}:\d{4})\b",  # RedHat pattern
    re.IGNORECASE,
)


def push_sighting_to_vulnerability_lookup(status_uri, vulnerability_ids):
    """Create a sighting from an incoming status and push it to the Vulnerability Lookup instance."""
    print("Pushing sighting to Vulnerability Lookup…")
    vuln_lookup = PyVulnerabilityLookup(
        config.vulnerability_lookup_base_url, token=config.vulnerability_auth_token
    )
    for vuln in vulnerability_ids:
        # Create the sighting
        sighting = {"type": "seen", "source": status_uri, "vulnerability": vuln}

        # Post the JSON to Vulnerability Lookup
        try:
            r = vuln_lookup.create_sighting(sighting=sighting)
            if "message" in r:
                print(r["message"])
        except Exception as e:
            print(
                f"Error when sending POST request to the Vulnerability Lookup server:\n{e}"
            )


async def stream():
    """
    Connects to the Bluesky firehose WebSocket stream, processes incoming frames,
    and extracts vulnerability sightings.
    Includes automatic reconnection handling.
    """
    while True:
        try:
            print("Connecting to Bluesky firehose...")
            async with websockets.connect(
                "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos",
                ping_interval=20,
                ping_timeout=10,
            ) as websocket:
                print("Streaming Bluesky firehose…")
                await process_stream(websocket)
        except websockets.ConnectionClosedError as e:
            print(f"Connection closed unexpectedly: {e}. Reconnecting...")
        except Exception as e:
            print(f"Unexpected error: {e}. Reconnecting...")
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
        # Match vulnerabilities in the content
        matches = vulnerability_pattern.findall(content)
        vulnerability_ids = [
            match for match_tuple in matches for match in match_tuple if match
        ]
        vulnerability_ids = remove_case_insensitive_duplicates(vulnerability_ids)

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
