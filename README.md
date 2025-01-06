# BlueSkySight

A client to gather vulnerability-related information from Bluesky.
The collected data is then sent to the
[Vulnerability-Lookup](https://github.com/cve-search/vulnerability-lookup) API as sightings.


### Installation

[pipx](https://github.com/pypa/pipx) is an easy way to install and run Python applications in isolated environments.
It's easy to [install](https://github.com/pypa/pipx?tab=readme-ov-file#on-linux).

```bash
$ pipx install BlueSkySight
$ export BLUESKYSIGHT_CONFIG=~/.BlueSkySight/conf.py
```

The configuration should be defined in a Python file (e.g., ``~/.BlueSkySight/conf.py``).
You must then set an environment variable (``BLUESKYSIGHT_CONFIG``) with the full path to this file.

You can have a look at [this example](https://github.com/CIRCL/BlueSkySight/blob/main/blueskysight/conf_sample.py) of configuration.


### Streaming the Firehose

``BlueSkySight-Firehose`` streams data from the Bluesky's firehose and uses PyVulnerabilityLookup to create sightings in Vulnerability-Lookup.

```bash
$ BlueSkySight-Firehose   
Connecting to the Bluesky firehose…
Connection established.
```

### Streaming a Jetstream service

``BlueSkySight-Jetstream`` connects to Bluesky's firehose via Jetstream.

```bash
$ BlueSkySight-Jetstream --help
usage: BlueSkySight-Jetstream [-h] [--collections COLLECTIONS] [--geo {us-east,us-west}] [--instance {1,2}]

Connect to a Jetstream service.

options:
  -h, --help            show this help message and exit
  --collections COLLECTIONS
                        The collections to subscribe to. If not provided, subscribe to all.
  --geo {us-east,us-west}
                        Region of the Jetstream service.
  --instance {1,2}      Instance of the Jetstream service.


$ BlueSkySight-Jetstream 
Connecting to the Bluesky Jetstream at wss://jetstream1.us-west.bsky.network/subscribe?wantedCollections=app.bsky.feed.post…
Connection established. Listening for messages…
```


## License

[BlueSkySight](https://github.com/CIRCL/BlueSkySight) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2024-2025 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2024-2025 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~
