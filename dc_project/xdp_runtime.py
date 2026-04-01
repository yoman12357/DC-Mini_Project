from __future__ import annotations

import ctypes
import json
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from dc_project.models import Action, ControlRule, FlowEvent, MonitorEntry, SliceIntent
from dc_project.store import JsonStateStore


BASE_DIR = Path(__file__).resolve().parent.parent
XDP_SOURCE = BASE_DIR / "ebpf" / "xdp_runtime_kern.c"
XDP_OBJECT = BASE_DIR / "ebpf" / "xdp_runtime_kern.o"
XDP_FLAGS_SKB_MODE = 1 << 1


class XDPControlValue(ctypes.Structure):
    _fields_ = [
        ("action", ctypes.c_uint32),
        ("queue", ctypes.c_uint32),
    ]


class XDPMonitorValue(ctypes.Structure):
    _fields_ = [
        ("packet_count", ctypes.c_uint64),
        ("total_bytes", ctypes.c_uint64),
        ("dropped_packets", ctypes.c_uint64),
        ("passed_packets", ctypes.c_uint64),
        ("steered_packets", ctypes.c_uint64),
        ("last_action", ctypes.c_uint32),
        ("last_queue", ctypes.c_uint32),
    ]


@dataclass
class XDPFlowRule:
    service: str
    source_host: str
    destination_host: str
    source_ip: str
    destination_ip: str
    protocol: int
    destination_port: int
    action: Action
    queue: int
    service_priority: int
    max_bandwidth: float
    minimum_bandwidth: float
    tunnel_id: int = 0


def flow_hash(
    source_ip: str,
    destination_ip: str,
    protocol: int,
    destination_port: int,
    tunnel_id: int = 0,
) -> int:
    src = struct.unpack("!I", socket.inet_aton(source_ip))[0]
    dst = struct.unpack("!I", socket.inet_aton(destination_ip))[0]
    value = 2166136261
    for word in (src, dst, ((protocol & 0xFF) << 16) | (destination_port & 0xFFFF), tunnel_id & 0xFFFFFFFF):
        value = ((value ^ word) * 16777619) & 0xFFFFFFFF
    return value


def protocol_number(value: str | int) -> int:
    if isinstance(value, int):
        return value
    mapping = {"icmp": 1, "tcp": 6, "udp": 17}
    return mapping[value.lower()]


def default_xdp_rules() -> list[XDPFlowRule]:
    return [
        XDPFlowRule(
            service="agv-video-icmp",
            source_host="h1",
            destination_host="h5",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            protocol=1,
            destination_port=0,
            tunnel_id=0,
            action=Action.STEER,
            queue=3,
            service_priority=9,
            max_bandwidth=3.0,
            minimum_bandwidth=1.5,
        ),
        XDPFlowRule(
            service="plc-control-icmp",
            source_host="h2",
            destination_host="h5",
            source_ip="10.0.0.10",
            destination_ip="10.0.0.2",
            protocol=1,
            destination_port=0,
            tunnel_id=0,
            action=Action.STEER,
            queue=1,
            service_priority=10,
            max_bandwidth=1.0,
            minimum_bandwidth=0.5,
        ),
        XDPFlowRule(
            service="animal-tracking-icmp",
            source_host="h3",
            destination_host="h5",
            source_ip="10.0.0.30",
            destination_ip="10.0.0.2",
            protocol=1,
            destination_port=0,
            tunnel_id=0,
            action=Action.DROP,
            queue=0,
            service_priority=4,
            max_bandwidth=0.5,
            minimum_bandwidth=0.1,
        ),
        XDPFlowRule(
            service="agv-video-http",
            source_host="h1",
            destination_host="h5",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            protocol=6,
            destination_port=8000,
            tunnel_id=0,
            action=Action.STEER,
            queue=3,
            service_priority=9,
            max_bandwidth=3.0,
            minimum_bandwidth=1.5,
        ),
        XDPFlowRule(
            service="baggage-robot-http",
            source_host="h4",
            destination_host="h5",
            source_ip="10.0.0.40",
            destination_ip="10.0.0.2",
            protocol=6,
            destination_port=8000,
            tunnel_id=0,
            action=Action.PASS,
            queue=0,
            service_priority=6,
            max_bandwidth=2.0,
            minimum_bandwidth=0.5,
        ),
    ]


class XDPManager:
    def __init__(self, interfaces: list[str], store: JsonStateStore | None = None) -> None:
        self.interfaces = interfaces
        self.store = store or JsonStateStore()
        self.lib = ctypes.CDLL("libbpf.so.1", use_errno=True)
        self._configure_libbpf()
        self.obj = None
        self.control_fd = None
        self.monitor_fd = None
        self.rules: dict[int, XDPFlowRule] = {}
        self._last_counts: dict[int, int] = {}

    def _configure_libbpf(self) -> None:
        self.lib.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        self.lib.bpf_object__open_file.restype = ctypes.c_void_p
        self.lib.libbpf_get_error.argtypes = [ctypes.c_void_p]
        self.lib.libbpf_get_error.restype = ctypes.c_long
        self.lib.bpf_object__load.argtypes = [ctypes.c_void_p]
        self.lib.bpf_object__load.restype = ctypes.c_int
        self.lib.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.lib.bpf_object__find_program_by_name.restype = ctypes.c_void_p
        self.lib.bpf_program__fd.argtypes = [ctypes.c_void_p]
        self.lib.bpf_program__fd.restype = ctypes.c_int
        self.lib.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.lib.bpf_object__find_map_by_name.restype = ctypes.c_void_p
        self.lib.bpf_map__fd.argtypes = [ctypes.c_void_p]
        self.lib.bpf_map__fd.restype = ctypes.c_int
        self.lib.bpf_xdp_attach.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p]
        self.lib.bpf_xdp_attach.restype = ctypes.c_int
        self.lib.bpf_xdp_detach.argtypes = [ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p]
        self.lib.bpf_xdp_detach.restype = ctypes.c_int
        self.lib.bpf_map_update_elem.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulonglong,
        ]
        self.lib.bpf_map_update_elem.restype = ctypes.c_int
        self.lib.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        self.lib.bpf_map_lookup_elem.restype = ctypes.c_int
        self.lib.bpf_map_get_next_key.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        self.lib.bpf_map_get_next_key.restype = ctypes.c_int
        self.lib.bpf_object__close.argtypes = [ctypes.c_void_p]
        self.lib.bpf_object__close.restype = None

    def compile(self) -> None:
        cmd = [
            "clang",
            "-O2",
            "-g",
            "-target",
            "bpf",
            "-I/usr/include/x86_64-linux-gnu",
            "-c",
            str(XDP_SOURCE),
            "-o",
            str(XDP_OBJECT),
        ]
        subprocess.run(cmd, check=True)

    def load(self) -> None:
        self.compile()
        obj = self.lib.bpf_object__open_file(str(XDP_OBJECT).encode(), None)
        if self.lib.libbpf_get_error(obj):
            raise RuntimeError("failed to open XDP object")
        if self.lib.bpf_object__load(obj) != 0:
            raise RuntimeError("failed to load XDP object")
        prog = self.lib.bpf_object__find_program_by_name(obj, b"xdp_runtime_prog")
        if not prog:
            raise RuntimeError("failed to find XDP program in object")
        prog_fd = self.lib.bpf_program__fd(prog)
        control_map = self.lib.bpf_object__find_map_by_name(obj, b"control_map")
        monitor_map = self.lib.bpf_object__find_map_by_name(obj, b"monitor_map")
        self.control_fd = self.lib.bpf_map__fd(control_map)
        self.monitor_fd = self.lib.bpf_map__fd(monitor_map)
        self.obj = obj
        for interface in self.interfaces:
            ifindex = socket.if_nametoindex(interface)
            if self.lib.bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, None) != 0:
                raise RuntimeError(f"failed to attach XDP to {interface}")

    def attach_and_seed(self, flow_rules: list[XDPFlowRule] | None = None) -> None:
        self.load()
        rules = flow_rules or default_xdp_rules()
        self.store.reset()
        for rule in rules:
            self.upsert_rule(rule)

    def upsert_rule(self, rule: XDPFlowRule) -> int:
        key_int = flow_hash(
            rule.source_ip,
            rule.destination_ip,
            rule.protocol,
            rule.destination_port,
            rule.tunnel_id,
        )
        key = ctypes.c_uint32(key_int)
        action_value = int(rule.action)
        value = XDPControlValue(action=action_value, queue=rule.queue)
        if self.lib.bpf_map_update_elem(self.control_fd, ctypes.byref(key), ctypes.byref(value), 0) != 0:
            raise RuntimeError(f"failed to insert XDP rule for {rule.service}")
        self.rules[key_int] = rule
        intent = SliceIntent(
            service=rule.service,
            resources={"network_properties": ["real-xdp"]},
            service_priority=rule.service_priority,
            max_allowed_bandwidth=rule.max_bandwidth,
            minimum_guaranteed_bandwidth=rule.minimum_bandwidth,
            match={
                "outer_src_ip": rule.source_ip,
                "outer_dst_ip": rule.destination_ip,
                "transport_protocol": rule.protocol,
                "outer_dst_port": rule.destination_port,
                "tunnel_id": rule.tunnel_id,
            },
            action=rule.action,
            queue=rule.queue,
        )
        self.store.upsert_rule(ControlRule(key=key_int, intent=intent))
        return key_int

    def delete_rule(self, key_int: int) -> None:
        key = ctypes.c_uint32(key_int)
        if hasattr(self.lib, "bpf_map_delete_elem"):
            self.lib.bpf_map_delete_elem.argtypes = [ctypes.c_int, ctypes.c_void_p]
            self.lib.bpf_map_delete_elem.restype = ctypes.c_int
            if self.lib.bpf_map_delete_elem(self.control_fd, ctypes.byref(key)) != 0:
                raise RuntimeError(f"failed to delete XDP rule {key_int}")
        self.rules.pop(key_int, None)
        self.store.delete_rule(key_int)

    def detach(self) -> None:
        for interface in self.interfaces:
            try:
                ifindex = socket.if_nametoindex(interface)
                self.lib.bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, None)
            except OSError:
                continue
        if self.obj:
            self.lib.bpf_object__close(self.obj)
            self.obj = None

    def read_monitor_map(self) -> dict[int, XDPMonitorValue]:
        entries: dict[int, XDPMonitorValue] = {}
        current_key = ctypes.c_uint32()
        next_key = ctypes.c_uint32()
        key_ptr = None
        while self.lib.bpf_map_get_next_key(
            self.monitor_fd,
            key_ptr,
            ctypes.byref(next_key),
        ) == 0:
            value = XDPMonitorValue()
            if self.lib.bpf_map_lookup_elem(self.monitor_fd, ctypes.byref(next_key), ctypes.byref(value)) == 0:
                entries[int(next_key.value)] = value
            current_key = ctypes.c_uint32(next_key.value)
            key_ptr = ctypes.byref(current_key)
        return entries

    def sync_runtime_state(self) -> None:
        metrics = self.read_monitor_map()
        for key, value in metrics.items():
            action_name = {
                0: "DROP",
                1: "STEER",
                2: "PASS",
            }.get(value.last_action, "PASS")
            entry = MonitorEntry(
                key=key,
                packet_count=int(value.packet_count),
                total_bytes=int(value.total_bytes),
                dropped_packets=int(value.dropped_packets),
                passed_packets=int(value.passed_packets),
                steered_packets=int(value.steered_packets),
                last_action=action_name,
                queues={str(value.last_queue): int(value.packet_count)} if value.packet_count else {},
            )
            self.store.update_metric(entry)

            delta = int(value.packet_count) - self._last_counts.get(key, 0)
            if delta > 0:
                rule = self.rules.get(key)
                service = rule.service if rule else "unmatched-flow"
                source = rule.source_host if rule else "unknown"
                destination = rule.destination_host if rule else "unknown"
                for _ in range(min(delta, 4)):
                    self.store.append_event(
                        FlowEvent(
                            timestamp=time.time(),
                            service=service,
                            source=source,
                            destination=destination,
                            action=action_name,
                            queue=int(value.last_queue),
                            packet_length=0,
                            hash_key=key,
                        )
                    )
            self._last_counts[key] = int(value.packet_count)


def rule_from_payload(payload: dict) -> XDPFlowRule:
    return XDPFlowRule(
        service=payload["service"],
        source_host=payload.get("source_host", "unknown"),
        destination_host=payload.get("destination_host", "unknown"),
        source_ip=payload["source_ip"],
        destination_ip=payload["destination_ip"],
        protocol=protocol_number(payload["protocol"]),
        destination_port=int(payload.get("destination_port", 0)),
        tunnel_id=int(payload.get("tunnel_id", 0)),
        action=Action[payload.get("action", "PASS").upper()],
        queue=int(payload.get("queue", 0)),
        service_priority=int(payload.get("service_priority", 1)),
        max_bandwidth=float(payload.get("max_bandwidth", 1.0)),
        minimum_bandwidth=float(payload.get("minimum_bandwidth", 0.1)),
    )


def rule_to_payload(key: int, rule: XDPFlowRule) -> dict:
    return {
        "key": key,
        "service": rule.service,
        "source_host": rule.source_host,
        "destination_host": rule.destination_host,
        "source_ip": rule.source_ip,
        "destination_ip": rule.destination_ip,
        "protocol": rule.protocol,
        "destination_port": rule.destination_port,
        "tunnel_id": rule.tunnel_id,
        "action": rule.action.name,
        "queue": rule.queue,
        "service_priority": rule.service_priority,
        "max_bandwidth": rule.max_bandwidth,
        "minimum_bandwidth": rule.minimum_bandwidth,
    }


def rules_to_json(rules: dict[int, XDPFlowRule]) -> str:
    return json.dumps([rule_to_payload(key, rule) for key, rule in sorted(rules.items())], indent=2)
