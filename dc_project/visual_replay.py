from __future__ import annotations

import argparse
import time

from dc_project.dataplane import DataPlane
from dc_project.demo import install_demo_rules
from dc_project.store import JsonStateStore
from dc_project.traffic import build_demo_flows


def main() -> None:
    parser = argparse.ArgumentParser(description="Continuously replay demo traffic for visual monitors")
    parser.add_argument("--interval", type=float, default=1.0, help="seconds between packets")
    parser.add_argument(
        "--keep-state",
        action="store_true",
        help="do not reset rules and metrics before replay starts",
    )
    args = parser.parse_args()

    store = JsonStateStore()
    if not args.keep_state:
        store.reset()
    dataplane = DataPlane(store=store)
    if not store.list_rules():
        install_demo_rules(dataplane, store)

    print("Replaying demo flows. Press Ctrl+C to stop.")
    try:
        while True:
            for flow in build_demo_flows():
                result = dataplane.process_packet(
                    flow["packet"],
                    service=str(flow["service"]),
                    source=str(flow["source"]),
                    destination=str(flow["destination"]),
                )
                print(
                    f"{flow['service']}: action={result['action']} queue={result['queue']} "
                    f"hash={result['hash']}"
                )
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nReplay stopped.")


if __name__ == "__main__":
    main()
