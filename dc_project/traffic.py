from __future__ import annotations

from dc_project.models import PacketMeta


FLOW_HOST_MAP = {
    "agv-video": {"source": "h1", "destination": "h5"},
    "plc-control": {"source": "h2", "destination": "h5"},
    "animal-tracking": {"source": "h3", "destination": "h5"},
    "baggage-robot": {"source": "h4", "destination": "h5"},
}


def build_vxlan_packet(
    outer_src_ip: str,
    outer_dst_ip: str,
    inner_src_ip: str,
    inner_dst_ip: str,
    outer_dst_port: int = 4789,
    inner_dst_port: int = 9000,
    vni: int = 100,
    payload_size: int = 128,
) -> PacketMeta:
    return PacketMeta(
        outer_src_mac="02:00:00:00:10:01",
        outer_dst_mac="02:00:00:00:20:01",
        inner_src_mac="02:00:00:00:30:01",
        inner_dst_mac="02:00:00:00:40:01",
        outer_src_ip=outer_src_ip,
        outer_dst_ip=outer_dst_ip,
        inner_src_ip=inner_src_ip,
        inner_dst_ip=inner_dst_ip,
        outer_src_port=40000,
        outer_dst_port=outer_dst_port,
        inner_src_port=50000,
        inner_dst_port=inner_dst_port,
        link_protocol=2048,
        transport_protocol=17,
        vxlan_id=vni,
        packet_length=payload_size,
    )


def build_tcp_packet(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    payload_size: int = 64,
) -> PacketMeta:
    return PacketMeta(
        outer_src_mac="02:00:00:00:50:01",
        outer_dst_mac="02:00:00:00:60:01",
        outer_src_ip=src_ip,
        outer_dst_ip=dst_ip,
        outer_src_port=12345,
        outer_dst_port=dst_port,
        link_protocol=2048,
        transport_protocol=6,
        packet_length=payload_size,
    )

def build_demo_traffic() -> list[tuple[str, PacketMeta]]:
    return [
        (
            "agv-video",
            build_vxlan_packet(
                outer_src_ip="10.0.0.1",
                outer_dst_ip="10.0.0.2",
                inner_src_ip="172.16.0.1",
                inner_dst_ip="172.16.0.2",
                payload_size=512,
                vni=101,
            ),
        ),
        (
            "plc-control",
            build_tcp_packet(
                src_ip="10.1.0.10",
                dst_ip="10.1.0.20",
                dst_port=502,
                payload_size=48,
            ),
        ),
        (
            "animal-tracking",
            build_tcp_packet(
                src_ip="10.2.0.10",
                dst_ip="10.2.0.20",
                dst_port=1883,
                payload_size=96,
            ),
        ),
        (
            "baggage-robot",
            build_vxlan_packet(
                outer_src_ip="10.3.0.1",
                outer_dst_ip="10.3.0.2",
                inner_src_ip="172.20.0.1",
                inner_dst_ip="172.20.0.2",
                payload_size=384,
                vni=202,
            ),
        ),
    ]


def build_demo_flows() -> list[dict[str, object]]:
    flows: list[dict[str, object]] = []
    for service, packet in build_demo_traffic():
        flow_meta = FLOW_HOST_MAP[service]
        flows.append(
            {
                "service": service,
                "source": flow_meta["source"],
                "destination": flow_meta["destination"],
                "packet": packet,
            }
        )
    return flows
