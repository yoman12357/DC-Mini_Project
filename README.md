# xdp-shield

xdp-shield is an XDP-based packet filtering and threat defense project for Linux.
It combines an eBPF firewall with runtime attack detection, IP reputation feeds, dynamic rule management, and a honeypot redirect mode for suspicious traffic.

## Features

- eBPF/XDP firewall for high-performance packet filtering
- Support for `generic` and `native` XDP attach modes
- Rule engine with allow/drop policies and priority-based matching
- Runtime thresholds for SYN flood, UDP flood, ICMP flood, port scan, and connection rate detection
- Temporary bans for suspicious sources
- Honeypot redirect support using XDP devmap forwarding
- Local dataset loader for reputation feeds and blacklists
- Configurable via file and CLI commands
- Systemd service support for deployment

## Repository layout

- `Makefile` - build and installation targets
- `bpf/` - eBPF firewall program sources and shared headers
- `src/` - control-plane CLI, config loader, dataset loader, honeypot monitor, rule manager
- `datasets/` - blacklist dataset sources used by the firewall
- `packaging/systemd/` - systemd unit and environment files
- `rules.conf` - sample rule file format and comments
- `xdp-shield.conf` - sample runtime configuration file
- `scripts/update-datasets.sh` - dataset update helper

## Prerequisites

- Linux with XDP support
- `clang` and a C compiler (`cc`) for user-space build
- `libbpf`, `libelf`, and `zlib` development headers
- `iproute2` for XDP detach operations
- Root privileges to attach/detach XDP programs

## Build

From the repository root:

```sh
make all
```

For lab/testing builds with relaxed thresholds:

```sh
make lab
```

## Usage

The built binary is `./xdp-shield`.

### Attach XDP firewall

```sh
sudo ./xdp-shield attach <interface>
```

Optionally choose XDP mode:

```sh
sudo ./xdp-shield attach <interface> --mode generic
sudo ./xdp-shield attach <interface> --mode native
```

### Detach XDP firewall

```sh
sudo ./xdp-shield detach <interface>
```

### Backward-compatible firewall command

```sh
sudo ./xdp-shield firewall attach <interface>
sudo ./xdp-shield firewall detach <interface>
```

### Manage rules

Add a rule:

```sh
sudo ./xdp-shield rule add --id 1 --action drop --src 198.51.100.0/24 --priority 20 --type cidr
```

Update a rule:

```sh
sudo ./xdp-shield rule update --id 1 --action allow --dst 203.0.113.10
```

Delete a rule:

```sh
sudo ./xdp-shield rule delete 1
```

Enable / disable rules:

```sh
sudo ./xdp-shield rule enable 1
sudo ./xdp-shield rule disable 1
```

List or clear rules:

```sh
sudo ./xdp-shield rule list
sudo ./xdp-shield rule clear
```

### Config commands

Load config file into control plane:

```sh
sudo ./xdp-shield config load /path/to/xdp-shield.conf
```

Show current config defaults:

```sh
sudo ./xdp-shield config show
```

Set a pinned runtime config option:

```sh
sudo ./xdp-shield config set <name> <value>
```

### Help and version

```sh
./xdp-shield help
./xdp-shield version
```

## Configuration

Default config values are loaded from `xdp-shield.conf` when the service starts.
The runtime config supports keys such as:

- `interface` / `ifname`
- `object_path`
- `rules_path`
- `xdp_mode` (`generic` or `native`)
- `attach_skb_mode`
- `log_sample_rate`
- `default_ban_seconds`
- `syn_threshold`
- `udp_threshold`
- `icmp_threshold`
- `port_scan_threshold`
- `connection_threshold`
- `window_ms`
- `ban_seconds`
- `honeypot_enabled`
- `honeypot_ifname`
- `honeypot_ip`
- `honeypot_mac`
- `honeypot_port`
- `honeypot_redirect_seconds`
- `honeypot_log_path`
- `honeypot_ban_on_interaction`
- `canary_ports`

See `xdp-shield.conf` for an example configuration.

## Rule format

`rules.conf` is one rule per line using key/value pairs.
Supported keys:

- `id`
- `action` (`allow` or `drop`)
- `src` (IPv4 or CIDR)
- `dst` (IPv4 or CIDR)
- `sport` (source port)
- `dport` (destination port)
- `proto` (`any`, `tcp`, `udp`, `icmp`, `icmpv6`, or numeric protocol)
- `priority`
- `type` (`exact`, `cidr`, `port`, `protocol`, `composite`)
- `enabled`

Example:

```text
id=1 action=drop src=203.0.113.10 priority=10 type=exact
id=2 action=drop src=198.51.100.0/24 priority=20 type=cidr
id=3 action=drop dport=23 proto=tcp priority=30 type=port
```

## Datasets

Blacklist datasets are stored under `datasets/blacklist/`.
Use the update helper to refresh feeds:

```sh
sh scripts/update-datasets.sh
```

## Install

Install binaries, BPF objects, config, and datasets:

```sh
sudo make install
```

Install systemd support:

```sh
sudo make install-systemd
```

The systemd unit loads environment values from `/etc/xdp-shield/xdp-shield.env` and runs `xdp-shield attach` on startup.

## Notes

- Root privileges are required to attach/detach XDP programs.
- The project expects a Linux environment with XDP and libbpf support.
- `xdp-shield` can run directly from the repo after `make all`.

## License

This repository does not include an explicit license file.
Add a license if you plan to redistribute or publish.
