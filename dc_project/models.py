from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Action(IntEnum):
    DROP = 0
    STEER = 1
    PASS = 2


@dataclass
class PacketMeta:
    outer_src_mac: str = "00:00:00:00:00:00"
    outer_dst_mac: str = "00:00:00:00:00:00"
    inner_src_mac: str = "00:00:00:00:00:00"
    inner_dst_mac: str = "00:00:00:00:00:00"
    outer_src_ip: str = "0.0.0.0"
    outer_dst_ip: str = "0.0.0.0"
    inner_src_ip: str = "0.0.0.0"
    inner_dst_ip: str = "0.0.0.0"
    outer_src_port: int = 0
    outer_dst_port: int = 0
    inner_src_port: int = 0
    inner_dst_port: int = 0
    link_protocol: int = 0
    transport_protocol: int = 0
    vxlan_id: int = 0
    gtp_id: int = 0
    packet_length: int = 0

    def to_hash_input(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("packet_length", None)
        return data


@dataclass
class SliceIntent:
    service: str
    resources: dict[str, Any]
    service_priority: int
    max_allowed_bandwidth: float
    minimum_guaranteed_bandwidth: float
    match: dict[str, Any]
    action: Action
    queue: int = 0

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["action"] = self.action.name
        return payload


@dataclass
class ControlRule:
    key: int
    intent: SliceIntent

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "intent": self.intent.to_dict(),
        }


@dataclass
class MonitorEntry:
    key: int
    packet_count: int = 0
    total_bytes: int = 0
    dropped_packets: int = 0
    passed_packets: int = 0
    steered_packets: int = 0
    last_action: str = "PASS"
    queues: dict[str, int] = field(default_factory=dict)

    def update(self, packet_length: int, action: Action, queue: int) -> None:
        self.packet_count += 1
        self.total_bytes += packet_length
        self.last_action = action.name
        self.queues[str(queue)] = self.queues.get(str(queue), 0) + 1
        if action == Action.DROP:
            self.dropped_packets += 1
        elif action == Action.STEER:
            self.steered_packets += 1
        else:
            self.passed_packets += 1

    def to_dict(self) -> dict[str, Any]:
        average_packet_size = self.total_bytes / self.packet_count if self.packet_count else 0.0
        drop_rate = self.dropped_packets / self.packet_count if self.packet_count else 0.0
        return {
            "key": self.key,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "average_packet_size": average_packet_size,
            "drop_rate": drop_rate,
            "dropped_packets": self.dropped_packets,
            "passed_packets": self.passed_packets,
            "steered_packets": self.steered_packets,
            "last_action": self.last_action,
            "queues": self.queues,
        }


@dataclass
class FlowEvent:
    timestamp: float
    service: str
    source: str
    destination: str
    action: str
    queue: int
    packet_length: int
    hash_key: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
