# xdp-shield datasets

Local datasets are loaded at firewall startup from:

- `datasets/blacklist/`

Use `make datasets` to populate blacklist files from public threat feeds.

Current sources:

- FireHOL level1: `https://iplists.firehol.org/files/firehol_level1.netset`
- Spamhaus DROP: `https://www.spamhaus.org/drop/drop.txt`
- Spamhaus EDROP: `https://www.spamhaus.org/drop/edrop.txt`
- Tor exit nodes: `https://check.torproject.org/torbulkexitlist`
- abuse.ch Feodo Tracker: `https://feodotracker.abuse.ch/downloads/ipblocklist.txt`

Files contain IPv4 addresses and CIDR ranges, one entry per line. Blank lines
and `#` comments are ignored by the loader.

The active firewall path is blacklist-only. Non-public IPv4 ranges such as
`10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` are ignored during
blacklist loading so local LAN and bridged VM traffic can pass normally.

Default enforcement is intentionally conservative. High-confidence categories
such as malware, botnet, Tor exits, and local/custom unknown entries are
hard-dropped by the XDP program. Broader abuse/spam reputation feeds are loaded
as threat intelligence but are not hard-dropped by default, because large public
feeds can include cloud/provider ranges that normal sites use.

Port blocking is handled by firewall rules, not dataset files yet.
