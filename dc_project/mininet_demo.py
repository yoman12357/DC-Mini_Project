from __future__ import annotations

import argparse
import json
import threading
import time
from typing import Iterable

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch

from dc_project.dataplane import DataPlane
from dc_project.models import Action, ControlRule, SliceIntent
from dc_project.store import JsonStateStore
from dc_project.traffic import build_demo_flows, build_demo_traffic
from dc_project.mininet_topology import SlicingDemoTopo
from dc_project.xdp_runtime import XDPManager


def _seed_demo_rules(dataplane: DataPlane, store: JsonStateStore) -> list[ControlRule]:
    packets = dict(build_demo_traffic())

    agv = packets["agv-video"].to_hash_input()
    plc = packets["plc-control"].to_hash_input()
    farm = packets["animal-tracking"].to_hash_input()

    rules = [
        ControlRule(
            key=dataplane.build_key_from_match(agv),
            intent=SliceIntent(
                service="agv-video",
                resources={"network_properties": ["low-latency", "high-bandwidth"]},
                service_priority=9,
                max_allowed_bandwidth=3.0,
                minimum_guaranteed_bandwidth=1.5,
                match=agv,
                action=Action.STEER,
                queue=3,
            ),
        ),
        ControlRule(
            key=dataplane.build_key_from_match(plc),
            intent=SliceIntent(
                service="plc-control",
                resources={"network_properties": ["ultra-reliable", "deterministic"]},
                service_priority=10,
                max_allowed_bandwidth=1.0,
                minimum_guaranteed_bandwidth=0.5,
                match=plc,
                action=Action.STEER,
                queue=1,
            ),
        ),
        ControlRule(
            key=dataplane.build_key_from_match(farm),
            intent=SliceIntent(
                service="animal-tracking",
                resources={"network_properties": ["best-effort", "monitoring"]},
                service_priority=4,
                max_allowed_bandwidth=0.5,
                minimum_guaranteed_bandwidth=0.1,
                match=farm,
                action=Action.DROP,
                queue=0,
            ),
        ),
    ]

    for rule in rules:
        store.upsert_rule(rule)

    return rules


def replay_demo_packets(dataplane: DataPlane) -> list[dict]:
    results = []
    for flow in build_demo_flows():
        service = str(flow["service"])
        packet = flow["packet"]
        result = dataplane.process_packet(
            packet,
            service=service,
            source=str(flow["source"]),
            destination=str(flow["destination"]),
        )
        result["service"] = service
        results.append(result)
    return results


def _start_live_replay(dataplane: DataPlane, stop_event: threading.Event, interval: float) -> threading.Thread:
    def runner() -> None:
        while not stop_event.is_set():
            for flow in build_demo_flows():
                if stop_event.is_set():
                    break
                dataplane.process_packet(
                    flow["packet"],
                    service=str(flow["service"]),
                    source=str(flow["source"]),
                    destination=str(flow["destination"]),
                )
                time.sleep(interval)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread


def print_demo_summary(results: Iterable[dict], store: JsonStateStore) -> None:
    print("\nPacket classification summary:")
    for result in results:
        print(
            f"- {result['service']}: action={result['action']} "
            f"queue={result['queue']} hash={result['hash']}"
        )

    print("\nCurrent monitoring metrics:")
    print(json.dumps([entry.to_dict() for entry in store.list_metrics()], indent=2))


def configure_hosts(net: Mininet) -> None:
    h1, h2, h3, h4, h5 = [net.get(name) for name in ("h1", "h2", "h3", "h4", "h5")]

    h5.cmd("python3 -m http.server 8000 >/tmp/dc_http.log 2>&1 &")
    h1.cmd("ping -c 2 10.0.0.2")
    h2.cmd("ping -c 2 10.0.0.2")
    h3.cmd("ping -c 2 10.0.0.2")
    h4.cmd("ping -c 2 10.0.0.2")

    print("\nHost mapping:")
    print("- h1: AGV video source")
    print("- h2: PLC control source")
    print("- h3: Animal tracking source")
    print("- h4: Baggage robot source")
    print("- h5: Edge service host")

    print("\nSuggested live demo commands inside Mininet:")
    print("- h1 curl -I http://10.0.0.2:8000")
    print("- h2 ping -c 3 10.0.0.2")
    print("- h3 ping -c 3 10.0.0.2")
    print("- h4 curl -I http://10.0.0.2:8000")


def _start_xdp_sync(manager: XDPManager, stop_event: threading.Event) -> threading.Thread:
    def runner() -> None:
        while not stop_event.is_set():
            manager.sync_runtime_state()
            time.sleep(1.0)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread


def run_demo(start_cli: bool, replay_interval: float, real_xdp: bool) -> None:
    store = JsonStateStore()
    store.reset()
    dataplane = DataPlane(store=store)
    rules = _seed_demo_rules(dataplane, store)

    print("Installed demo slice rules:")
    print(json.dumps([rule.to_dict() for rule in rules], indent=2))

    results = replay_demo_packets(dataplane)
    print_demo_summary(results, store)

    print("\nStarting Mininet topology...")
    net = Mininet(
        topo=SlicingDemoTopo(),
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
    )

    try:
        net.start()
        configure_hosts(net)
        stop_event = threading.Event()
        if real_xdp:
            xdp_manager = XDPManager(
                interfaces=["s1-eth1", "s1-eth2", "s1-eth3", "s1-eth4"],
                store=store,
            )
            xdp_manager.attach_and_seed()
            sync_thread = _start_xdp_sync(xdp_manager, stop_event)
            print("\nReal XDP is attached to Mininet switch interfaces in skb mode.")
            print("Live state is now coming from the XDP monitor map.")
        else:
            replay_thread = _start_live_replay(dataplane, stop_event, replay_interval)
            print("\nLive visual state is now updating in runtime files for the dashboard and terminal monitor.")
        if start_cli:
            print("\nDropping into Mininet CLI. Type 'exit' when finished.")
            CLI(net)
    finally:
        stop_event.set()
        if "replay_thread" in locals():
            replay_thread.join(timeout=1.0)
        if "sync_thread" in locals():
            sync_thread.join(timeout=1.0)
        if "xdp_manager" in locals():
            xdp_manager.detach()
        net.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Data Communication Mininet demo")
    parser.add_argument(
        "--no-cli",
        action="store_true",
        help="start and stop Mininet without opening the CLI",
    )
    parser.add_argument(
        "--replay-interval",
        type=float,
        default=1.0,
        help="seconds between live replayed packets for the dashboard and terminal monitor",
    )
    parser.add_argument(
        "--real-xdp",
        action="store_true",
        help="attach a real XDP program to Mininet interfaces and sync live counters from BPF maps",
    )
    args = parser.parse_args()

    setLogLevel("warning")
    run_demo(start_cli=not args.no_cli, replay_interval=args.replay_interval, real_xdp=args.real_xdp)


if __name__ == "__main__":
    main()
