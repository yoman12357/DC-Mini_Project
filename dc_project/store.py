from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any

from dc_project.models import Action, ControlRule, FlowEvent, MonitorEntry, SliceIntent


BASE_DIR = Path(__file__).resolve().parent.parent
RUNTIME_DIR = BASE_DIR / "runtime"
RULES_PATH = RUNTIME_DIR / "control_rules.json"
METRICS_PATH = RUNTIME_DIR / "monitor_metrics.json"
EVENTS_PATH = RUNTIME_DIR / "flow_events.json"


class JsonStateStore:
    def __init__(self) -> None:
        self._lock = Lock()
        RUNTIME_DIR.mkdir(exist_ok=True)
        if not RULES_PATH.exists():
            RULES_PATH.write_text("[]", encoding="utf-8")
        if not METRICS_PATH.exists():
            METRICS_PATH.write_text("[]", encoding="utf-8")
        if not EVENTS_PATH.exists():
            EVENTS_PATH.write_text("[]", encoding="utf-8")

    def _read_json(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        raw = path.read_text(encoding="utf-8").strip()
        return json.loads(raw) if raw else []

    def _write_json(self, path: Path, payload: list[dict[str, Any]]) -> None:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def list_rules(self) -> list[ControlRule]:
        with self._lock:
            payload = self._read_json(RULES_PATH)
        rules: list[ControlRule] = []
        for item in payload:
            intent_raw = item["intent"]
            intent = SliceIntent(
                service=intent_raw["service"],
                resources=intent_raw["resources"],
                service_priority=intent_raw["service_priority"],
                max_allowed_bandwidth=intent_raw["max_allowed_bandwidth"],
                minimum_guaranteed_bandwidth=intent_raw["minimum_guaranteed_bandwidth"],
                match=intent_raw["match"],
                action=Action[intent_raw["action"]],
                queue=intent_raw.get("queue", 0),
            )
            rules.append(ControlRule(key=item["key"], intent=intent))
        return rules

    def upsert_rule(self, rule: ControlRule) -> None:
        with self._lock:
            payload = self._read_json(RULES_PATH)
            filtered = [item for item in payload if item["key"] != rule.key]
            filtered.append(rule.to_dict())
            filtered.sort(key=lambda item: item["key"])
            self._write_json(RULES_PATH, filtered)

    def delete_rule(self, key: int) -> bool:
        with self._lock:
            payload = self._read_json(RULES_PATH)
            filtered = [item for item in payload if item["key"] != key]
            changed = len(filtered) != len(payload)
            if changed:
                self._write_json(RULES_PATH, filtered)
            return changed

    def get_rule(self, key: int) -> ControlRule | None:
        for rule in self.list_rules():
            if rule.key == key:
                return rule
        return None

    def list_metrics(self) -> list[MonitorEntry]:
        with self._lock:
            payload = self._read_json(METRICS_PATH)
        entries: list[MonitorEntry] = []
        for item in payload:
            entries.append(
                MonitorEntry(
                    key=item["key"],
                    packet_count=item["packet_count"],
                    total_bytes=item["total_bytes"],
                    dropped_packets=item["dropped_packets"],
                    passed_packets=item["passed_packets"],
                    steered_packets=item["steered_packets"],
                    last_action=item["last_action"],
                    queues=item.get("queues", {}),
                )
            )
        return entries

    def update_metric(self, entry: MonitorEntry) -> None:
        with self._lock:
            payload = self._read_json(METRICS_PATH)
            filtered = [item for item in payload if item["key"] != entry.key]
            filtered.append(entry.to_dict())
            filtered.sort(key=lambda item: item["key"])
            self._write_json(METRICS_PATH, filtered)

    def get_metric(self, key: int) -> MonitorEntry | None:
        for metric in self.list_metrics():
            if metric.key == key:
                return metric
        return None

    def list_events(self) -> list[FlowEvent]:
        with self._lock:
            payload = self._read_json(EVENTS_PATH)
        return [FlowEvent(**item) for item in payload]

    def append_event(self, event: FlowEvent, limit: int = 200) -> None:
        with self._lock:
            payload = self._read_json(EVENTS_PATH)
            payload.append(event.to_dict())
            payload = payload[-limit:]
            self._write_json(EVENTS_PATH, payload)

    def reset(self) -> None:
        with self._lock:
            self._write_json(RULES_PATH, [])
            self._write_json(METRICS_PATH, [])
            self._write_json(EVENTS_PATH, [])
