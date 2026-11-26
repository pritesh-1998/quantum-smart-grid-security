"""Quantum-measurement randomness demonstration using a classical simulator."""

from __future__ import annotations

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator


def simulated_quantum_bits(bit_count: int = 256, *, seed: int = 6640) -> str:
    """Generate simulator measurement bits; this is not physical QRNG output."""
    if not 1 <= bit_count <= 4_096:
        raise ValueError("bit_count must be between 1 and 4096")
    circuit = QuantumCircuit(bit_count, bit_count)
    circuit.h(range(bit_count))
    circuit.measure(range(bit_count), range(bit_count))
    backend = AerSimulator(method="stabilizer", seed_simulator=seed)
    counts = backend.run(circuit, shots=1).result().get_counts()
    measured = next(iter(counts))
    return measured.replace(" ", "")
