# Implementation Notes

This project is implemented as the software-only prototype recommended by the
PDF for a laptop or workstation environment.

## Mapping to the PDF

### Layer 1: Hardware

- The SmartNIC path is represented by [`ebpf/xdp_slice_kern.c`](/home/kali/Documents/DC/ebpf/xdp_slice_kern.c).
- The file defines the control map, monitoring map, metadata structure, and the
  high-level XDP action flow.
- Hardware queue redirection is documented but not executed in this prototype.

### Layer 2: Kernel Space

- A custom NFP driver is out of scope for this environment.
- The prototype models the same behavior in software through the
  [`DataPlane`](/home/kali/Documents/DC/dc_project/dataplane.py) pipeline.

### Layer 3: User Space

- The control application is implemented in
  [`dc_project/control_api.py`](/home/kali/Documents/DC/dc_project/control_api.py).
- The monitoring application is implemented in
  [`dc_project/monitor_api.py`](/home/kali/Documents/DC/dc_project/monitor_api.py).
- Shared persistent state is implemented in
  [`dc_project/store.py`](/home/kali/Documents/DC/dc_project/store.py).

## Implemented Packet Flow

The current runnable pipeline is:

1. Build or receive packet metadata
2. Compute CRC32-based 32-bit key
3. Look up the rule in the control map
4. Apply `DROP`, `STEER`, or default `PASS`
5. Update monitoring counters

The main entrypoint for this flow is
[`dc_project/dataplane.py`](/home/kali/Documents/DC/dc_project/dataplane.py).

## Industry 4.0 Demonstration Traffic

The prototype includes four demonstration traffic classes in
[`dc_project/traffic.py`](/home/kali/Documents/DC/dc_project/traffic.py):

- AGV video
- PLC control
- Animal tracking
- Airport baggage robot

The demo runner in [`dc_project/demo.py`](/home/kali/Documents/DC/dc_project/demo.py)
installs example rules and processes these packets end to end.

## Current Limitations

- No real XDP attachment
- No AF_XDP sockets
- No SmartNIC hardware offload
- No Mininet topology execution in this workspace
- No packet-performance benchmarking against the paper

## Suggested Presentation Framing

Describe this implementation as:

"A functional software prototype of the paper's control plane, monitoring plane,
and packet-classification pipeline, designed for workstation-based demonstration
before SmartNIC deployment."
