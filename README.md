# Data Communication Project Prototype

This repository implements a software-first prototype of the project described in
`Data_Communication_Project.pdf`.

The implementation follows the same logical pipeline from the paper:

1. Parse packet metadata
2. Compute a 32-bit hash
3. Look up the control map
4. Apply an action: `PASS`, `DROP`, or `STEER`
5. Update the monitoring map

Because this environment does not include a Netronome SmartNIC, Mininet, or
privileged packet I/O, the project is implemented as a practical demonstration
that can run on a Linux workstation. The code keeps the paper's architecture,
while making the hardware parts explicit as future work.

## Project Layout

- `dc_project/models.py`: shared data structures
- `dc_project/store.py`: persistent rule and metrics storage
- `dc_project/dataplane.py`: software data-plane pipeline
- `dc_project/control_api.py`: control-plane API for slice rules
- `dc_project/monitor_api.py`: monitoring API
- `dc_project/traffic.py`: synthetic traffic generator
- `dc_project/demo.py`: end-to-end demonstration runner
- `ebpf/xdp_slice_kern.c`: eBPF/XDP skeleton mapped to the paper

## Features Implemented

- Intent-based slice creation with bandwidth, priority, and service metadata
- Control map with 32-bit hash keys
- Monitoring map with counters, bytes, average packet size, drop/pass/steer stats
- Packet metadata parsing for Ethernet, IP, TCP, UDP, and VXLAN-like traffic
- Rule insertion, deletion, lookup, and persistence
- Demo traffic for multiple Industry 4.0 use cases
- JSON APIs for control and monitoring

## Quick Start

Create the runtime files and run the demo:

```bash
python3 -m dc_project.demo
```

Run the control API:

```bash
python3 -m dc_project.control_api
```

Run the monitoring API:

```bash
python3 -m dc_project.monitor_api
```

## Mininet Demonstration

This project also includes a Mininet-based demonstration topology aligned with
the PDF's recommended software prototype path.

Run it with:

```bash
sudo python3 -m dc_project.mininet_demo
```

If you only want to verify startup without entering the Mininet CLI:

```bash
sudo python3 -m dc_project.mininet_demo --no-cli
```

The Mininet demo creates:

- `h1`: AGV video traffic source
- `h2`: PLC control source
- `h3`: Animal tracking source
- `h4`: Baggage robot source
- `h5`: Edge service host
- `s1`: edge switch

Inside the Mininet CLI, you can use:

```bash
nodes
net
h1 ping -c 3 h5
h2 ping -c 3 h5
h1 curl -I http://10.0.0.2:8000
h4 curl -I http://10.0.0.2:8000
exit
```

## Visual Demonstration Stack

You can show the project visually in three parallel views:

1. Mininet live topology and traffic
2. Browser dashboard with colored slicing links and live metrics
3. Terminal monitor with continuously updating actions and counters

Start the dashboard:

```bash
python3 -m dc_project.dashboard
```

Open:

```text
http://127.0.0.1:5002
```

Start the terminal live monitor:

```bash
python3 -m dc_project.live_monitor
```

Then start the Mininet demo:

```bash
sudo python3 -m dc_project.mininet_demo
```

To use a real XDP program on the Mininet switch-facing interfaces instead of the
software replay loop:

```bash
sudo python3 -m dc_project.mininet_demo --real-xdp
```

If you want to drive the visuals without Mininet, use the traffic replayer:

```bash
python3 -m dc_project.visual_replay
```

## Real XDP Mode

The repository now includes an actual attachable XDP program in
[`ebpf/xdp_runtime_kern.c`](/home/kali/Documents/DC/ebpf/xdp_runtime_kern.c)
and a Python loader/controller in
[`dc_project/xdp_runtime.py`](/home/kali/Documents/DC/dc_project/xdp_runtime.py).

When you run:

```bash
sudo python3 -m dc_project.mininet_demo --real-xdp
```

the project will:

- compile the eBPF/XDP program with `clang`
- attach it to `s1-eth1` through `s1-eth4` in Mininet using `libbpf`
- install real BPF control-map rules
- read live packet counters back from the monitor map
- mirror that state into the dashboard and terminal monitor

In real XDP mode:

- `h1 ping -c 3 h5` should be classified as `STEER`
- `h2 ping -c 3 h5` should be classified as `STEER`
- `h3 ping -c 3 h5` should fail because XDP drops it
- `h1 curl -I http://10.0.0.2:8000` should be classified as `STEER`
- `h4 curl -I http://10.0.0.2:8000` should be classified as `PASS`

The real XDP parser now supports:

- ICMP, TCP, and UDP matching
- VXLAN detection on UDP port `4789`
- GTP-U detection on UDP port `2152`
- tunnel-aware hash generation

## XDP Control Service

For dynamic rule insertion and deletion against a live XDP program, you can run
the dedicated XDP service:

```bash
sudo python3 -m dc_project.xdp_service --interfaces s1-eth1 s1-eth2 s1-eth3 s1-eth4
```

Then use:

```bash
curl -X POST http://127.0.0.1:5003/attach
curl http://127.0.0.1:5003/rules
curl -X POST http://127.0.0.1:5003/sync
curl -X POST http://127.0.0.1:5003/rules \
  -H "Content-Type: application/json" \
  -d '{
    "service": "custom-drop",
    "source_host": "h3",
    "destination_host": "h5",
    "source_ip": "10.0.0.30",
    "destination_ip": "10.0.0.2",
    "protocol": "icmp",
    "destination_port": 0,
    "action": "DROP",
    "queue": 0,
    "service_priority": 4,
    "max_bandwidth": 0.5,
    "minimum_bandwidth": 0.1
  }'
```

## Remaining Limitation

The only major software-side paper feature that is still not included here is a
full AF_XDP socket data path. That is possible in principle, but it depends on
interface and driver support and is less reliable on Mininet/veth than the real
XDP path implemented here.

## Example Control API Calls

Insert a slice intent:

```bash
curl -X POST http://127.0.0.1:5000/intents \
  -H 'Content-Type: application/json' \
  -d '{
    "service": "agv-video",
    "service_priority": 9,
    "MaxAllowedBandwidth": 3.0,
    "MinimumGuaranteedBandwidth": 1.5,
    "resources": {
      "network_properties": ["low-latency", "high-reliability"]
    },
    "match": {
      "outer_src_ip": "10.0.0.1",
      "outer_dst_ip": "10.0.0.2",
      "transport_protocol": 17,
      "outer_dst_port": 4789
    },
    "action": "STEER",
    "queue": 3
  }'
```

List current rules:

```bash
curl http://127.0.0.1:5000/rules
```

Read monitoring metrics:

```bash
curl http://127.0.0.1:5001/metrics
```

## What Matches the PDF

- Parser -> hasher -> matcher -> executor pipeline
- Intent-based messages
- Control and monitoring maps
- User-space control and monitoring applications
- Industry 4.0 traffic classes
- Software prototype path recommended in the PDF

## What Is Not Hardware-Equivalent

- No SmartNIC offload
- No AF_XDP queue steering in hardware
- No Mininet topology execution in this environment
- Performance numbers from the paper are not reproduced here

This should be presented as a functional prototype aligned with the assignment,
not as a SmartNIC-performance replication.
