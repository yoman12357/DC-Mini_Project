from __future__ import annotations

import argparse
import atexit
import threading
import time

from flask import Flask, request

from dc_project.xdp_runtime import XDPManager, default_xdp_rules, rule_from_payload, rule_to_payload


app = Flask(__name__)
manager: XDPManager | None = None
sync_thread: threading.Thread | None = None
sync_stop = threading.Event()


def _sync_loop() -> None:
    assert manager is not None
    while not sync_stop.is_set():
        manager.sync_runtime_state()
        time.sleep(1.0)


def start_sync() -> None:
    global sync_thread
    if sync_thread and sync_thread.is_alive():
        return
    sync_stop.clear()
    sync_thread = threading.Thread(target=_sync_loop, daemon=True)
    sync_thread.start()


def stop_sync() -> None:
    sync_stop.set()
    if sync_thread and sync_thread.is_alive():
        sync_thread.join(timeout=1.0)


@app.get("/health")
def health() -> tuple[dict, int]:
    return {"status": "ok", "service": "xdp-service", "attached": manager is not None and manager.obj is not None}, 200


@app.post("/attach")
def attach() -> tuple[dict, int]:
    assert manager is not None
    if manager.obj is not None:
        return {"message": "already attached"}, 200
    manager.attach_and_seed(default_xdp_rules())
    start_sync()
    return {"message": "xdp attached", "interfaces": manager.interfaces}, 201


@app.post("/detach")
def detach() -> tuple[dict, int]:
    assert manager is not None
    stop_sync()
    manager.detach()
    return {"message": "xdp detached"}, 200


@app.get("/rules")
def list_rules() -> tuple[dict, int]:
    assert manager is not None
    return {"rules": [rule_to_payload(key, rule) for key, rule in sorted(manager.rules.items())]}, 200


@app.post("/rules")
def create_rule() -> tuple[dict, int]:
    assert manager is not None
    payload = request.get_json(force=True)
    rule = rule_from_payload(payload)
    key = manager.upsert_rule(rule)
    return {"message": "xdp rule installed", "rule": rule_to_payload(key, rule)}, 201


@app.delete("/rules/<int:key>")
def delete_rule(key: int) -> tuple[dict, int]:
    assert manager is not None
    manager.delete_rule(key)
    return {"message": "xdp rule deleted", "key": key}, 200


@app.post("/sync")
def sync_once() -> tuple[dict, int]:
    assert manager is not None
    manager.sync_runtime_state()
    return {"message": "runtime state synchronized"}, 200


def cleanup() -> None:
    if manager is not None:
        stop_sync()
        manager.detach()


def main() -> None:
    global manager
    parser = argparse.ArgumentParser(description="Root-run XDP control service for the Mininet demo")
    parser.add_argument("--interfaces", nargs="+", required=True, help="interfaces to attach the XDP program to")
    parser.add_argument("--host", default="127.0.0.1", help="bind host")
    parser.add_argument("--port", type=int, default=5003, help="bind port")
    args = parser.parse_args()

    manager = XDPManager(interfaces=args.interfaces)
    atexit.register(cleanup)
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
