# xdp-shield

A Linux XDP-based packet firewall with runtime threat detection, dynamic rule control, and honeypot redirection.

---

## The Problem

Modern Linux network defense requires high-throughput packet filtering and adaptive response to active threats. Traditional iptables or userspace firewalls place decision logic outside the fast path, making it harder to enforce low-latency filtering for factors like reputation feeds, temporary bans, or honeypot-triggered redirect behavior.

---

## Our Solution

xdp-shield moves the firewall decision pipeline into eBPF/XDP while keeping runtime policy and detection configuration in userspace. It combines:

- an XDP firewall for packet-level policy enforcement,
- runtime thresholds for traffic anomalies and temporary bans,
- local blacklist ingestion for reputation-based drops,
- an interactive rule manager over pinned BPF maps,
- optional canary-port honeypot redirect and Cowrie log monitoring.

This design keeps packet handling fast, while enabling operators to tune detection parameters and update rules without recompiling the BPF program.

---

## Architecture

| Component | Responsibility |
|-----------|----------------|
| `src/main.c` | Application entrypoint, lifecycle manager, attach/detach loop, logger and honeypot monitoring orchestration. |
| `src/cli.c` | Command-line parser and dispatcher for attach/detach, rule operations, and runtime config commands. |
| `src/loader.c` | Loads the compiled BPF object, opens required maps, pins them under bpffs, and attaches/detaches the XDP program. |
| `src/config.c` | Parses runtime configuration, applies defaults, updates pinned runtime config maps, and configures honeypot state. |
| `src/rules.c` | Manages canonical rule storage and derived rule index maps, updates BPF maps atomically, and loads rules from text files. |
| `src/dataset.c` | Loads local blacklist datasets into the threat feed map, validates CIDR entries, and deduplicates entries before insertion. |
| `src/honeypot.c` | Monitors honeypot log output, promotes suspicious sources to temporary bans, and supports Cowrie event parsing. |
| `src/logger.c` | Subscribes to the BPF event ring buffer and prints structured firewall event summaries. |
| `bpf/firewall.bpf.c` | eBPF firewall program entrypoint with packet parse/inspection, threat detection, rule matching, and honeypot redirect logic. |
| `bpf/common.h` | Shared ABI types and constants used by both user space and BPF programs. |
| `bpf/maps.h` | Defines the BPF map layout for rules, threat feeds, temporary bans, detection state, stats, and honeypot forwarding. |
| `bpf/parser.c` | Packet parser for Ethernet, VLAN, IPv4, IPv6, TCP, UDP, ICMP, and fragment handling inside BPF. |
| `bpf/engine.c` | Runtime detection engine implementing fixed-window flood, port scan, and connection-rate detection. |
| `bpf/rules.c` | In-BPF rule lookup and decision evaluation using exact and CIDR indexes. |
| `Makefile` | Build targets for BPF object, user-space binary, systemd install, and dataset updates. |

---

## How It Works

### Initialization

When `xdp-shield` starts with `attach`, it:

1. parses CLI arguments and configuration (`src/cli.c`, `src/config.c`),
2. loads the compiled BPF object (`bpf/firewall.bpf.o`) into the kernel via `libbpf` (`src/loader.c`),
3. resolves all required BPF maps and pins them under `/sys/fs/bpf/xdp-shield`,
4. initializes runtime config and honeypot state into BPF maps,
5. loads text rules from `rules.conf` into the canonical rule map and derived indexes,
6. loads local blacklist datasets into the threat feed map,
7. attaches the XDP program to the protected interface and, if enabled, the honeypot interface.

### Data Flow

- Packets enter the kernel at the selected interface and are handed to the XDP program.
- The BPF parser extracts metadata for IPv4/IPv6, transport ports, and packet flags.
- The firewall then evaluates the packet against three major sources:
  - threat feed blacklist map,
  - runtime detection engine state,
  - rule index maps derived from the canonical rule map.
- Events and statistics are written to BPF maps and a ring buffer for userspace monitoring.
- If honeypot deception is enabled, suspicious hosts hitting canary ports are redirected through a devmap to an isolated honeypot interface.

### Core Processing

The XDP program implements a layered decision pipeline:

- `packet_is_blacklisted` drops packets matching fed blacklist prefixes.
- `run_detection_engine` maintains per-source fixed-window counters for SYN flood, UDP flood, ICMP flood, port scan, and connection rate.
- `check_rules` evaluates explicit rules by looking up exact IP, CIDR, port, and protocol indexes and applying priority-based decisions.
- If the packet matches a deny rule, the packet is dropped; otherwise it is passed.

### Rule and Runtime State Management

- `src/rules.c` stores rules in a canonical map keyed by rule ID.
- Derived index maps (`src_ipv4_rule_map`, `dst_port_rule_map`, etc.) enable fast BPF lookups without scanning all rules.
- Rule updates rebuild these indexes on every add/update/delete operation so BPF lookup remains simple.
- `src/config.c` writes runtime thresholds into a single-entry config map, allowing live tuning of flood and ban parameters.
- `src/loader.c` pins BPF maps so CLI rule and config operations can open them later without restarting the firewall.

### Honeypot and Deception

- Canary ports are configured from `xdp-shield.conf`.
- When a packet hits a configured canary port, the source is trapped and redirected to a honeypot interface.
- `src/honeypot.c` watches a Cowrie-style log file and promotes hosts that interact with the honeypot into a temporary ban map.
- Redirected return traffic is rewritten by BPF so the original source and destination semantics are preserved.

### Observability

- `src/logger.c` attaches to the BPF ring buffer and prints event summaries for drops, temporary bans, threat hits, rule matches, honeypot redirects, and canary ports.
- Runtime counters are available in the BPF stats map and are printed periodically by the control process.

---

## Configuration

- `xdp-shield.conf` is the runtime configuration file.
- `rules.conf` defines one firewall rule per line using key=value tokens.
- `scripts/update-datasets.sh` refreshes local threat feeds stored under `datasets/blacklist/`.

Key runtime options:

- `interface` / `ifname` — protected interface to attach XDP to.
- `xdp_mode` — `generic` or `native` XDP attach mode.
- `honeypot_enabled` — enable honeypot redirection.
- `honeypot_ifname` — isolated honeypot return interface.
- `honeypot_ip` / `honeypot_mac` / `honeypot_port` — rewrite target for redirected traffic.
- `canary_ports` — comma-separated TCP/UDP ports used to trap suspicious scanners.
- `syn_threshold`, `udp_threshold`, `icmp_threshold`, `port_scan_threshold`, `connection_threshold` — live detection thresholds.
- `window_ms` — detection window duration in milliseconds.
- `ban_seconds` — default temporary ban duration.
- `log_sample_rate` — sample rate used by userspace logging.

CLI runtime config commands:

- `config show` prints pinned runtime threshold values.
- `config set <name> <value>` updates the runtime config map while the firewall is running.

---

## Installation

Prerequisites:

- Linux kernel with XDP support.
- `clang` for BPF object compilation.
- `cc` or compatible C compiler for the userspace binary.
- `libbpf`, `libelf`, and `zlib` development headers.
- `iproute2` for interface XDP detach operations.
- root privileges for attaching and detaching XDP programs.

Build commands from repository root:

```sh
make all
```

Install:

```sh
sudo make install
```

Install systemd support:

```sh
sudo make install-systemd
```

Platform notes:

- The project targets Linux only.
- `generic` XDP mode is used by default for broad NIC compatibility.
- `native` mode may be required on supported hardware for best performance.

---

## Usage

Attach the firewall to an interface:

```sh
sudo ./xdp-shield attach eth0
```

Detach the firewall:

```sh
sudo ./xdp-shield detach eth0
```

Rule operations:

```sh
sudo ./xdp-shield rule add --id 1 --action drop --src 198.51.100.0/24 --priority 20 --type cidr
sudo ./xdp-shield rule update --id 1 --action allow --dst 203.0.113.10
sudo ./xdp-shield rule delete 1
sudo ./xdp-shield rule enable 1
sudo ./xdp-shield rule disable 1
sudo ./xdp-shield rule list
sudo ./xdp-shield rule clear
```

Config commands:

```sh
sudo ./xdp-shield config show
sudo ./xdp-shield config set syn_threshold 5000
```

Help:

```sh
./xdp-shield help
```

Note: `attach` and `detach` operations require root privileges because they modify kernel XDP state.

---

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Use XDP/eBPF for the firewall datapath | Keeps packet filtering in the kernel fast path and avoids expensive userspace packet inspection. |
| Separate rule management from BPF execution | Canonical rule storage plus derived indexes let userspace update rules without rebuilding the BPF program. |
| Pin BPF maps under `/sys/fs/bpf/xdp-shield` | Allows later CLI operations to modify rules and runtime config while the firewall remains attached. |
| Runtime config in a BPF map | Enables live tuning of thresholds and ban durations without reloading the eBPF program. |
| Honeypot devmap forwarding | Supports transparent redirection to an isolated honeypot interface while preserving original reply paths. |


---
