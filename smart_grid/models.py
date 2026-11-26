"""Small typed models for simulated smart-grid communications."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from time import perf_counter_ns
from typing import Any
from uuid import uuid4


class GridLink(StrEnum):
    CONTROL_WAN = "control_wan"
    SUBSTATION_GOOSE = "substation_goose"
    METER_AMI = "meter_ami"


class NodeRole(StrEnum):
    CONTROL_CENTER = "control_center"
    SUBSTATION = "substation"
    SMART_METER = "smart_meter"
    RTU = "rtu"


@dataclass(frozen=True, slots=True)
class GridNode:
    node_id: str
    role: NodeRole
    region: str


@dataclass(frozen=True, slots=True)
class GridMessage:
    source: str
    destination: str
    link: GridLink
    payload: dict[str, Any]
    message_id: str = field(default_factory=lambda: str(uuid4()))
    created_at_ns: int = field(default_factory=perf_counter_ns)

    def serialize(self) -> bytes:
        import json

        return json.dumps(
            {
                "message_id": self.message_id,
                "source": self.source,
                "destination": self.destination,
                "link": self.link.value,
                "payload": self.payload,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
