# Changelog

## Release 1.0.0 (2025-02-13)

This release introduces the capability to report errors, warnings,
and heartbeats to a Valkey datastore, facilitating centralized monitoring.
Events are reported using Python coroutines, with the heartbeat integrated
into the main event loop.


## Release 0.5.0 (2025-01-06)

The initial code for connecting to BlueSky's firehose has been replaced with
a better implementation. However, the original code is still available and can
be executed using the command `BlueSkySight-Firehose-v1`, while the new default
implementation can be executed with `BlueSkySight-Firehose`.

The command to connect to BlueSky's firehose via Jetstream remains unchanged.


## Release 0.4.0 (2025-01-06)

### New

- Added a function (and new command) to connect to Bluesky's firehose via Jetstream.
  ([c800d31](https://github.com/CIRCL/BlueSkySight/commit/c800d31))

### Improvements

- Automatically reconnects when the server closes the connection.
  ([1ec09a6](https://github.com/CIRCL/BlueSkySight/commit/1ec09a6))
- Improved function to parse Bluesky's firehose.
  ([c03a461](https://github.com/CIRCL/BlueSkySight/commit/c03a461))
- The list of regular expressions is now in the configuration file.
  ([612c1ec](https://github.com/CIRCL/BlueSkySight/commit/612c1ec))


## Release 0.3.0 (2024-12-25)

- If the resolution of the DID to a handle fails, simply return the AT URI (with the DID).


## Release 0.2.0 (2024-12-19)

- Various small improvements.

## Release 0.1.0 (2024-12-19)

- First working prototype uploaded to PyPI.
