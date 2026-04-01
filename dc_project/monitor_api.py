from __future__ import annotations

from flask import Flask

from dc_project.store import JsonStateStore


app = Flask(__name__)
store = JsonStateStore()


@app.get("/health")
def health() -> tuple[dict, int]:
    return {"status": "ok", "service": "monitor-plane"}, 200


@app.get("/metrics")
def metrics() -> tuple[dict, int]:
    entries = [entry.to_dict() for entry in store.list_metrics()]
    totals = {
        "tracked_rules": len(entries),
        "packet_count": sum(item["packet_count"] for item in entries),
        "total_bytes": sum(item["total_bytes"] for item in entries),
        "dropped_packets": sum(item["dropped_packets"] for item in entries),
        "passed_packets": sum(item["passed_packets"] for item in entries),
        "steered_packets": sum(item["steered_packets"] for item in entries),
    }
    return {"totals": totals, "entries": entries}, 200


def main() -> None:
    app.run(host="127.0.0.1", port=5001, debug=False)


if __name__ == "__main__":
    main()
