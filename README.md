# BlueSkySight

A client to gather vulnerability-related information from the Bluesky.
The gathered data is subsequently transmitted to the
[Vulnerability-Lookup](https://github.com/cve-search/vulnerability-lookup) API.


### Installation

[pipx](https://github.com/pypa/pipx) is an easy way to install and run Python applications in isolated environments.
It's easy to [install](https://github.com/pypa/pipx?tab=readme-ov-file#on-linux).

```bash
$ pipx install BlueSkySight
$ export BLUESKYSIGHT_CONFIG=~/.BlueSkySight/conf.py
```

The configuration for BlueSkySight should be defined in a Python file (e.g., ``~/.BlueSkySight/conf.py``).
You must then set an environment variable (``BLUESKYSIGHT_CONFIG``) with the full path to this file.

You can have a look at [this example](https://github.com/CIRCL/BlueSkySight/blob/main/blueskysight/conf_sample.py) of configuration.

### Streaming


``BlueSkySight-Stream`` streams data from the Bluesky firehose and uses PyVulnerabilityLookup to create sightings in Vulnerability-Lookup.

```bash
$ BlueSkySight-Stream   
Streaming Bluesky firehose…
```


## License

[BlueSkySight](https://github.com/CIRCL/BlueSkySight) is licensed under
[GNU General Public License version 3](https://www.gnu.org/licenses/gpl-3.0.html)

~~~
Copyright (c) 2024 Computer Incident Response Center Luxembourg (CIRCL)
Copyright (C) 2024 Cédric Bonhomme - https://github.com/cedricbonhomme
~~~
