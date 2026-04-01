# Mininet Demo Guide

This guide shows how to demonstrate the project with Mininet.

## What the Demo Shows

- An emulated network topology with multiple service hosts
- Different traffic classes that map to the Industry 4.0 use cases
- Slice rules installed in the software control map
- Packet-classification decisions from the prototype data plane
- Interactive Mininet connectivity tests

## Topology

- `h1`: AGV video source
- `h2`: PLC control source
- `h3`: Animal tracking source
- `h4`: Airport baggage robot source
- `h5`: Edge service endpoint
- `s1`: Edge switch

## Run the Demo

From `/home/kali/Documents/DC`:

```bash
python3 -m dc_project.dashboard
```

Open `http://127.0.0.1:5002` in your browser.

In another terminal:

```bash
python3 -m dc_project.live_monitor
```

In a third terminal:

```bash
sudo python3 -m dc_project.mininet_demo --real-xdp
```

For a shorter non-interactive run:

```bash
sudo python3 -m dc_project.mininet_demo --no-cli
```

## Suggested Presentation Flow

1. Start the Mininet demo.
2. Show that the slice rules were installed.
3. Point to the printed packet classification summary:
   - AGV video -> `STEER`
   - PLC control -> `STEER`
   - Animal tracking -> `DROP`
   - Baggage robot -> `PASS`
4. In the Mininet CLI, run:

```bash
nodes
net
h1 ping -c 3 h5
h2 ping -c 3 h5
h3 ping -c 3 h5
h4 ping -c 3 h5
h1 curl -I http://10.0.0.2:8000
h4 curl -I http://10.0.0.2:8000
```

Expected behavior in `--real-xdp` mode:

- `h1` and `h2` traffic is counted as `STEER`
- `h3` traffic is dropped by the XDP program
- `h4` traffic is counted as `PASS`

The real XDP path now includes deeper parsing support for:

- ICMP
- TCP
- UDP
- VXLAN
- GTP-U

5. Explain that Mininet demonstrates the topology and software slicing logic,
   while SmartNIC offload remains future work.

## Alternative Visual Replay Without Mininet

If you want the dashboard and terminal monitor to update without launching
Mininet, run:

```bash
python3 -m dc_project.visual_replay
```

## Important Framing

This demo is valid for the PDF because the assignment itself recommends a
Mininet-based software prototype when dedicated SmartNIC hardware is not
available. It should be described as:

"A functional software demonstration of parser, hash, control-map lookup,
action execution, and monitoring, integrated with a Mininet emulated topology."
