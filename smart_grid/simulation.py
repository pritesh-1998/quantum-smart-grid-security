"""Repeatable toy topology for the project demonstration."""

from __future__ import annotations

from smart_grid.models import GridLink, GridMessage, GridNode, NodeRole
from smart_grid.network import SmartGridNetwork, Transmission


def demo_nodes() -> list[GridNode]:
    return [
        GridNode("control-center-1", NodeRole.CONTROL_CENTER, "control_center"),
        GridNode("substation-1", NodeRole.SUBSTATION, "substation"),
        GridNode("meter-1", NodeRole.SMART_METER, "distribution"),
        GridNode("rtu-1", NodeRole.RTU, "substation"),
    ]


def run_demo_communications() -> list[Transmission]:
    network = SmartGridNetwork(demo_nodes())
    messages = [
        GridMessage(
            "control-center-1",
            "substation-1",
            GridLink.CONTROL_WAN,
            {"command": "set_voltage_target", "value_kv": 11.0},
        ),
        GridMessage(
            "substation-1",
            "rtu-1",
            GridLink.SUBSTATION_GOOSE,
            {"event": "breaker_status", "closed": True},
        ),
        GridMessage(
            "meter-1",
            "control-center-1",
            GridLink.METER_AMI,
            {"reading_kwh": 12.75},
        ),
    ]
    return [network.transmit(message) for message in messages]
