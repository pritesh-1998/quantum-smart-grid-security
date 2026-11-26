"""In-process network and replay checks for the testbed."""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter_ns

from smart_grid.models import GridMessage, GridNode


class DuplicateMessageError(ValueError):
    """Raised when a previously accepted message ID is received again."""


class UnknownNodeError(ValueError):
    """Raised when a message references a node outside the simulated topology."""


class ReplayProtector:
    """In-memory replay guard for demonstrations; not a production protocol."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def accept(self, message_id: str) -> None:
        if message_id in self._seen:
            raise DuplicateMessageError(f"duplicate message ID: {message_id}")
        self._seen.add(message_id)


@dataclass(frozen=True, slots=True)
class Transmission:
    message: GridMessage
    wire_bytes: int
    processing_us: float


class SmartGridNetwork:
    """A local message router; it does not emulate IEC 61850 or a real network."""

    def __init__(self, nodes: list[GridNode]) -> None:
        self._nodes = {node.node_id: node for node in nodes}
        if len(self._nodes) != len(nodes):
            raise ValueError("node IDs must be unique")

    def transmit(
        self,
        message: GridMessage,
        replay_protector: ReplayProtector | None = None,
    ) -> Transmission:
        if message.source not in self._nodes:
            raise UnknownNodeError(f"unknown source node: {message.source}")
        if message.destination not in self._nodes:
            raise UnknownNodeError(f"unknown destination node: {message.destination}")

        start = perf_counter_ns()
        wire_bytes = len(message.serialize())
        if replay_protector is not None:
            replay_protector.accept(message.message_id)
        elapsed_us = (perf_counter_ns() - start) / 1_000
        return Transmission(message, wire_bytes, elapsed_us)
