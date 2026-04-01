from __future__ import annotations

import json

from dc_project.dataplane import DataPlane, extract_metadata
from dc_project.models import Action, ControlRule, SliceIntent
from dc_project.store import JsonStateStore
from dc_project.traffic import build_demo_flows, build_demo_traffic


def install_demo_rules(dataplane: DataPlane, store: JsonStateStore) -> list[ControlRule]:
    traffic = dict(build_demo_traffic())

    agv_meta = extract_metadata(traffic["agv-video"])
    plc_meta = extract_metadata(traffic["plc-control"])
    animal_meta = extract_metadata(traffic["animal-tracking"])

    rules = [
        ControlRule(
            key=dataplane.build_key_from_match(agv_meta.to_hash_input()),
            intent=SliceIntent(
                service="agv-video",
                resources={"network_properties": ["low-latency", "high-bandwidth"]},
                service_priority=9,
                max_allowed_bandwidth=3.0,
                minimum_guaranteed_bandwidth=1.5,
                match=agv_meta.to_hash_input(),
                action=Action.STEER,
                queue=3,
            ),
        ),
        ControlRule(
            key=dataplane.build_key_from_match(plc_meta.to_hash_input()),
            intent=SliceIntent(
                service="plc-control",
                resources={"network_properties": ["ultra-reliable", "deterministic"]},
                service_priority=10,
                max_allowed_bandwidth=1.0,
                minimum_guaranteed_bandwidth=0.5,
                match=plc_meta.to_hash_input(),
                action=Action.STEER,
                queue=1,
            ),
        ),
        ControlRule(
            key=dataplane.build_key_from_match(animal_meta.to_hash_input()),
            intent=SliceIntent(
                service="animal-tracking",
                resources={"network_properties": ["best-effort", "monitoring"]},
                service_priority=4,
                max_allowed_bandwidth=0.5,
                minimum_guaranteed_bandwidth=0.1,
                match=animal_meta.to_hash_input(),
                action=Action.DROP,
                queue=0,
            ),
        ),
    ]
    for rule in rules:
        store.upsert_rule(rule)
    return rules


def main() -> None:
    store = JsonStateStore()
    store.reset()
    dataplane = DataPlane(store=store)
    rules = install_demo_rules(dataplane, store)

    print("Installed rules:")
    print(json.dumps([rule.to_dict() for rule in rules], indent=2))

    print("\nProcessing demo traffic:")
    for flow in build_demo_flows():
        service = str(flow["service"])
        packet = flow["packet"]
        result = dataplane.process_packet(
            packet,
            service=service,
            source=str(flow["source"]),
            destination=str(flow["destination"]),
        )
        print(f"- {service}: {result['action']} queue={result['queue']} hash={result['hash']}")

    print("\nMonitoring snapshot:")
    print(json.dumps([entry.to_dict() for entry in store.list_metrics()], indent=2))


if __name__ == "__main__":
    main()
