from __future__ import annotations

from flask import Flask, jsonify, request

from dc_project.dataplane import DataPlane
from dc_project.models import Action, ControlRule, SliceIntent
from dc_project.store import JsonStateStore


app = Flask(__name__)
store = JsonStateStore()
dataplane = DataPlane(store=store)


def parse_intent(payload: dict) -> SliceIntent:
    return SliceIntent(
        service=payload["service"],
        resources=payload.get("resources", {}),
        service_priority=int(payload["service_priority"]),
        max_allowed_bandwidth=float(payload["MaxAllowedBandwidth"]),
        minimum_guaranteed_bandwidth=float(payload["MinimumGuaranteedBandwidth"]),
        match=payload["match"],
        action=Action[payload.get("action", "PASS").upper()],
        queue=int(payload.get("queue", 0)),
    )


@app.get("/health")
def health() -> tuple[dict, int]:
    return {"status": "ok", "service": "control-plane"}, 200


@app.get("/rules")
def list_rules() -> tuple[dict, int]:
    return {"rules": [rule.to_dict() for rule in store.list_rules()]}, 200


@app.post("/intents")
def create_intent() -> tuple[dict, int]:
    payload = request.get_json(force=True)
    intent = parse_intent(payload)
    key = dataplane.build_key_from_match(intent.match)
    rule = ControlRule(key=key, intent=intent)
    store.upsert_rule(rule)
    return {"message": "intent stored", "rule": rule.to_dict()}, 201


@app.delete("/rules/<int:key>")
def delete_rule(key: int) -> tuple[dict, int]:
    deleted = store.delete_rule(key)
    status = 200 if deleted else 404
    return {"deleted": deleted, "key": key}, status


@app.post("/reset")
def reset_state() -> tuple[dict, int]:
    store.reset()
    return {"message": "runtime state cleared"}, 200


def main() -> None:
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
