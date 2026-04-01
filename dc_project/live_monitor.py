from __future__ import annotations

import argparse
import os
import time
from collections import defaultdict
from datetime import datetime

from dc_project.store import JsonStateStore


ACTION_COLOR = {
    "PASS": "\033[92m",
    "STEER": "\033[94m",
    "DROP": "\033[91m",
}
RESET = "\033[0m"


def clear_screen() -> None:
    os.system("clear")


def summarize_by_service(events: list[dict]) -> list[dict]:
    summary: dict[str, dict] = {}
    for event in events:
        service = event["service"]
        current = summary.setdefault(
            service,
            {
                "service": service,
                "source": event["source"],
                "destination": event["destination"],
                "action": event["action"],
                "queue": event["queue"],
                "packets": 0,
            },
        )
        current["action"] = event["action"]
        current["queue"] = event["queue"]
        current["packets"] += 1
    return list(summary.values())


def print_table(rows: list[dict]) -> None:
    print("Service            Source   Dest   Action  Queue  Packets")
    print("---------------------------------------------------------")
    for row in rows:
        color = ACTION_COLOR.get(row["action"], "")
        action = f"{color}{row['action']:<6}{RESET}"
        print(
            f"{row['service']:<18} {row['source']:<7} {row['destination']:<6} "
            f"{action} {row['queue']:<6} {row['packets']:<7}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Live terminal monitor for slice actions and counters")
    parser.add_argument("--interval", type=float, default=1.0, help="refresh interval in seconds")
    args = parser.parse_args()

    store = JsonStateStore()
    try:
        while True:
            clear_screen()
            events = [event.to_dict() for event in store.list_events()]
            metrics = [metric.to_dict() for metric in store.list_metrics()]
            totals = defaultdict(int)
            for metric in metrics:
                totals["packets"] += metric["packet_count"]
                totals["bytes"] += metric["total_bytes"]
                totals["drops"] += metric["dropped_packets"]
                totals["passes"] += metric["passed_packets"]
                totals["steers"] += metric["steered_packets"]

            print("Data Communication Project Live Monitor")
            print(f"Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(
                f"Totals: packets={totals['packets']} bytes={totals['bytes']} "
                f"pass={totals['passes']} steer={totals['steers']} drop={totals['drops']}"
            )
            print()
            print_table(summarize_by_service(events[-40:]))
            print()
            print("Recent events")
            print("-------------")
            for event in events[-8:]:
                color = ACTION_COLOR.get(event["action"], "")
                action = f"{color}{event['action']}{RESET}"
                timestamp = datetime.fromtimestamp(event["timestamp"]).strftime("%H:%M:%S")
                print(
                    f"{timestamp}  {event['service']:<16} {event['source']}->{event['destination']} "
                    f"{action:<12} queue={event['queue']} len={event['packet_length']}"
                )
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")


if __name__ == "__main__":
    main()
