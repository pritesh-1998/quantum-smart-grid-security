"""Monte Carlo BB84 protocol model; no quantum hardware is used."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(frozen=True, slots=True)
class Bb84Result:
    transmitted_bits: int
    sifted_bits: int
    sample_bits: int
    estimated_qber: float
    detected_eavesdropper: bool
    remaining_sifted_bits: int
    intercept_fraction: float
    simulation_seed: int | None


def simulate_bb84(
    bit_count: int = 2_000,
    *,
    intercept_fraction: float = 0.0,
    qber_threshold: float = 0.11,
    sample_fraction: float = 0.2,
    seed: int | None = 6640,
) -> Bb84Result:
    if bit_count < 100:
        raise ValueError("bit_count must be at least 100 for parameter estimation")
    if not 0.0 <= intercept_fraction <= 1.0:
        raise ValueError("intercept_fraction must be between 0 and 1")
    if not 0.0 < sample_fraction < 1.0:
        raise ValueError("sample_fraction must be between 0 and 1")
    if not 0.0 <= qber_threshold <= 1.0:
        raise ValueError("qber_threshold must be between 0 and 1")

    rng = np.random.default_rng(seed)
    alice_bits = rng.integers(0, 2, size=bit_count, dtype=np.int8)
    alice_basis = rng.integers(0, 2, size=bit_count, dtype=np.int8)
    bob_basis = rng.integers(0, 2, size=bit_count, dtype=np.int8)
    bob_bits = alice_bits.copy()

    intercepted = rng.random(bit_count) < intercept_fraction
    eve_basis = rng.integers(0, 2, size=bit_count, dtype=np.int8)
    eve_wrong_basis = intercepted & (eve_basis != alice_basis)

    bob_matching_basis = bob_basis == alice_basis
    random_bob_measurement = eve_wrong_basis & bob_matching_basis
    bob_bits[random_bob_measurement] = rng.integers(
        0, 2, size=int(random_bob_measurement.sum()), dtype=np.int8
    )

    sifted = np.flatnonzero(bob_matching_basis)
    if len(sifted) < 2:
        raise RuntimeError("too few sifted bits to estimate QBER")
    sample_count = max(1, int(len(sifted) * sample_fraction))
    sample_indices = rng.choice(sifted, size=sample_count, replace=False)
    errors = int(np.count_nonzero(alice_bits[sample_indices] != bob_bits[sample_indices]))
    qber = errors / sample_count
    remaining = len(sifted) - sample_count
    detected = qber > qber_threshold
    return Bb84Result(
        transmitted_bits=bit_count,
        sifted_bits=len(sifted),
        sample_bits=sample_count,
        estimated_qber=qber,
        detected_eavesdropper=detected,
        remaining_sifted_bits=0 if detected else remaining,
        intercept_fraction=intercept_fraction,
        simulation_seed=seed,
    )
