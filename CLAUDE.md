# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

BlueSkySight is a client that consumes Bluesky posts, scans them for vulnerability identifiers (CVE, GHSA, PYSEC, GSD, CERT-Bund, Cisco, RHSA, MSRC, CERT-FR — see `vulnerability_patterns` in `blueskysight/conf_sample.py`), and pushes each match as a "sighting" to a [Vulnerability-Lookup](https://github.com/vulnerability-lookup/vulnerability-lookup) instance via `pyvulnerabilitylookup`.

Three console-script entry points (declared in `pyproject.toml`):

- `BlueSkySight-Firehose` → `blueskysight/firehose.py` — current default. Connects to `wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos`, decodes DAG-CBOR + CARv1 frames inline, and processes `#commit` messages with `app.bsky.feed.post/*` create ops.
- `BlueSkySight-Firehose-v1` → `blueskysight/stream.py` — legacy implementation kept for compatibility. Same firehose, but uses the async DAG-CBOR/CAR parsers and `enumerate_mst_records` from `utils.py` to walk the MST and resolve the actual post record from `op["path"]`.
- `BlueSkySight-Jetstream` → `blueskysight/jetstream.py` — JSON-based alternative via Bluesky's Jetstream relays (`wss://jetstream{instance}.{geo}.bsky.network/subscribe`). Supports optional zstd compression with a remotely fetched dictionary, plus DNS / `.well-known` handle→DID resolution.

When changing the streaming pipeline, remember that `firehose.py` and `stream.py` contain **two independent CBOR/CAR decoder implementations** (sync in `firehose.py`, async in `utils.py`). Don't assume a fix in one applies to the other.

## Configuration loading

`blueskysight/config.py` runs at import time: it `importlib`-loads the path in the `BLUESKYSIGHT_CONFIG` env var (falling back to `blueskysight/conf_sample.py`), then re-exports the names the rest of the code consumes. Required keys: `vulnerability_lookup_base_url`, `vulnerability_auth_token`, `vulnerability_patterns`. Optional: `ignore` (DID denylist used by the firehose), and the Valkey trio `valkey_host` / `valkey_port` / `expiration_period` — if all three are present, `heartbeat_enabled` is set to True and `utils.py` opens a `valkey.Valkey` client at module import.

Implication: importing `blueskysight.utils` with heartbeat keys present will attempt a Valkey connection. Tests / scripts that don't need it should point `BLUESKYSIGHT_CONFIG` at a config without those keys.

## Heartbeat / error reporting

`utils.heartbeat()` writes a timestamp to a Valkey key (default `process_heartbeat_BlueskySight`, overridden to `process_heartbeat_BlueskySight-Jetstream` for jetstream) every 30s with TTL `expiration_period`. `utils.report_error()` rpush'es log entries to `process_logs_BlueskySight` (24h TTL). Both `firehose.py` and `jetstream.py` expose a `launch_with_hearbeat()` that runs the streamer + heartbeat under one `asyncio.gather` and cancels the heartbeat if the streamer raises. `stream.py` (the v1 entry point) does **not** support heartbeat.

## Common commands

```bash
# Install (dev)
poetry install --with dev

# Run a streamer (requires BLUESKYSIGHT_CONFIG to point at a config file)
export BLUESKYSIGHT_CONFIG=$PWD/blueskysight/conf_sample.py
poetry run BlueSkySight-Firehose
poetry run BlueSkySight-Jetstream --geo us-west --instance 1

# Lint / format / type-check (configured in .pre-commit-config.yaml and pyproject.toml)
poetry run pre-commit run --all-files       # black, isort, flake8 (max-line-length=120), pyupgrade, pip-audit
poetry run mypy blueskysight                 # strict_optional, check_untyped_defs, warn_unreachable, etc.

# Build / publish (publish runs from the GitHub `release` workflow on tag publish)
poetry build
```

There is no test suite in the repo.

## Things to know before editing

- **Don't commit `blueskysight/conf.py` or `conf1.py`** — these are local, untracked operator configs. The shipped sample is `conf_sample.py`, which is also listed in `pyproject.toml` `[tool.poetry] include`.
- The Docker image (`Dockerfile`, `docker-compose.yml`) `pipx install BlueSkySight` from PyPI — it does **not** build from the local checkout. Local source changes won't appear in the container until a release is published.
- AT-URI → public bsky.app URL conversion (`utils.get_post_url`) calls `https://plc.directory/{did}` per post. If that resolution fails, the AT-URI is used as the sighting source instead of a `bsky.app` URL.
- `extract_vulnerability_ids` deduplicates case-insensitively but preserves the *last* occurrence's case (see `remove_case_insensitive_duplicates`).
