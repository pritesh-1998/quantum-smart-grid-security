import pytest

from experiments.attack_test import run_attack_demonstrations
from security.qkd_bb84 import simulate_bb84
from security.qrng import simulated_quantum_bits
from smart_grid.models import GridLink, GridMessage, GridNode, NodeRole
from smart_grid.network import (
    DuplicateMessageError,
    ReplayProtector,
    SmartGridNetwork,
    UnknownNodeError,
)
from smart_grid.simulation import run_demo_communications


def test_bb84_intercept_resend_is_detected_in_seeded_simulation():
    no_eavesdropper = simulate_bb84(10_000, intercept_fraction=0, seed=6640)
    intercept_resend = simulate_bb84(10_000, intercept_fraction=1, seed=6640)

    assert no_eavesdropper.estimated_qber == 0
    assert intercept_resend.estimated_qber > 0.11
    assert intercept_resend.detected_eavesdropper
    assert intercept_resend.remaining_sifted_bits == 0


def test_qrng_simulator_is_seeded_and_returns_requested_bits():
    first = simulated_quantum_bits(64, seed=17)

    assert len(first) == 64
    assert set(first) <= {"0", "1"}
    assert simulated_quantum_bits(64, seed=17) == first


def test_replay_guard_and_unknown_nodes_are_explicit():
    replay = ReplayProtector()
    replay.accept("event-1")
    with pytest.raises(DuplicateMessageError):
        replay.accept("event-1")

    network = SmartGridNetwork([GridNode("meter", NodeRole.SMART_METER, "distribution")])
    message = GridMessage("meter", "missing", GridLink.METER_AMI, {"kwh": 1})
    with pytest.raises(UnknownNodeError):
        network.transmit(message)


def test_demo_topology_routes_all_three_link_types():
    transmissions = run_demo_communications()

    assert len(transmissions) == 3
    assert {item.message.link for item in transmissions} == set(GridLink)
    assert all(item.wire_bytes > 0 for item in transmissions)


def test_attack_demonstrations_detect_synthetic_tamper_and_replay():
    result = run_attack_demonstrations()

    assert result["aes_gcm_tamper_rejected"]
    assert result["signature_tamper_rejected"]
    assert result["duplicate_id_rejected"]
