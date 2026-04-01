from __future__ import annotations

import json
import time
import zlib
from dataclasses import asdict
from typing import Any

from dc_project.models import Action, FlowEvent, MonitorEntry, PacketMeta
from dc_project.store import JsonStateStore


def compute_hash(meta: PacketMeta) -> int:
    payload = json.dumps(meta.to_hash_input(), sort_keys=True).encode("utf-8")
    return zlib.crc32(payload) & 0xFFFFFFFF


def extract_metadata(packet: Any) -> PacketMeta:
    if isinstance(packet, PacketMeta):
        return packet
    if isinstance(packet, dict):
        return PacketMeta(**packet)
    raise TypeError("packet must be a PacketMeta or metadata dictionary")


class DataPlane:
    def __init__(self, store: JsonStateStore | None = None) -> None:
        self.store = store or JsonStateStore()

    def _match_rule(self, meta: PacketMeta) -> tuple[int, Action, int, dict[str, Any] | None]:
        key = compute_hash(meta)
        rule = self.store.get_rule(key)
        if rule is None:
            return key, Action.PASS, 0, None
        return key, rule.intent.action, rule.intent.queue, rule.intent.to_dict()

    def _update_monitor(self, key: int, packet_length: int, action: Action, queue: int) -> None:
        entry = self.store.get_metric(key) or MonitorEntry(key=key)
        entry.update(packet_length=packet_length, action=action, queue=queue)
        self.store.update_metric(entry)

    def process_packet(
        self,
        packet: Any,
        *,
        service: str = "unknown-flow",
        source: str = "unknown",
        destination: str = "unknown",
    ) -> dict[str, Any]:
        meta = extract_metadata(packet)
        key, action, queue, rule = self._match_rule(meta)
        self._update_monitor(key=key, packet_length=meta.packet_length, action=action, queue=queue)
        self.store.append_event(
            FlowEvent(
                timestamp=time.time(),
                service=service,
                source=source,
                destination=destination,
                action=action.name,
                queue=queue,
                packet_length=meta.packet_length,
                hash_key=key,
            )
        )
        return {
            "hash": key,
            "action": action.name,
            "queue": queue,
            "metadata": asdict(meta),
            "matched_rule": rule,
        }

    def build_key_from_match(self, match: dict[str, Any]) -> int:
        meta = PacketMeta(**match)
        return compute_hash(meta)
