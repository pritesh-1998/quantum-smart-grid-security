"""Reproducible local cryptographic and protocol-model measurements."""

from __future__ import annotations

import json
import os
import platform
import statistics
import sys
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from time import perf_counter_ns
from typing import Callable

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from experiments.attack_test import run_attack_demonstrations
from security.classical import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    derive_ecdh_key,
    generate_ecdh_key_pair,
    generate_signing_key_pair,
    hmac_sha256,
    sign,
    verify_hmac_sha256,
    verify_signature,
)
from security.hybrid import complete_hybrid_key, establish_hybrid_key
from security.pqc import (
    ML_DSA_65_SIZES,
    ML_KEM_768_SIZES,
    ml_dsa_65_keygen,
    ml_dsa_65_sign,
    ml_dsa_65_verify,
    ml_kem_768_decapsulate,
    ml_kem_768_encapsulate,
    ml_kem_768_keygen,
)
from security.qkd_bb84 import simulate_bb84
from security.qrng import simulated_quantum_bits
from smart_grid.models import GridLink, GridMessage
from smart_grid.network import ReplayProtector, SmartGridNetwork
from smart_grid.models import GridNode, NodeRole

DEFAULT_PAYLOAD_BYTES = 256
SUBSTATION_DEADLINE_MS = 3.0


def _measure(
    mechanism: str,
    operation: str,
    function: Callable[[], object],
    iterations: int,
    *,
    payload_bytes: int = 0,
    public_key_bytes: int = 0,
    ciphertext_bytes: int = 0,
    signature_bytes: int = 0,
    deadline_ms: float | None = None,
) -> dict[str, object]:
    samples: list[float] = []
    for _ in range(iterations):
        started = perf_counter_ns()
        function()
        samples.append((perf_counter_ns() - started) / 1_000)
    ordered = sorted(samples)
    p95_index = min(len(ordered) - 1, int(0.95 * len(ordered)))
    row: dict[str, object] = {
        "mechanism": mechanism,
        "operation": operation,
        "iterations": iterations,
        "median_us": statistics.median(samples),
        "p95_us": ordered[p95_index],
        "payload_bytes": payload_bytes,
        "public_key_bytes": public_key_bytes,
        "ciphertext_bytes": ciphertext_bytes,
        "signature_bytes": signature_bytes,
        "deadline_ms": deadline_ms,
        "deadline_met_rate_pct": None,
    }
    if deadline_ms is not None:
        row["deadline_met_rate_pct"] = (
            100 * sum(sample <= deadline_ms * 1_000 for sample in samples) / len(samples)
        )
    return row


def run_benchmarks(
    *,
    iterations: int = 25,
    payload_bytes: int = DEFAULT_PAYLOAD_BYTES,
    timing_trials: int = 500,
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, object]]:
    if iterations < 1:
        raise ValueError("iterations must be at least one")
    if payload_bytes < 0:
        raise ValueError("payload_bytes cannot be negative")
    if timing_trials < 1:
        raise ValueError("timing_trials must be at least one")

    message = b"g" * payload_bytes
    rows: list[dict[str, object]] = []

    rows.append(
        _measure(
            "X25519",
            "keygen",
            generate_ecdh_key_pair,
            iterations,
            public_key_bytes=32,
        )
    )
    alice_private, _ = generate_ecdh_key_pair()
    _, bob_public = generate_ecdh_key_pair()

    def establish_classical_session() -> bytes:
        initiator_private, _ = generate_ecdh_key_pair()
        _, responder_public = generate_ecdh_key_pair()
        return derive_ecdh_key(initiator_private, responder_public)

    rows.append(
        _measure(
            "X25519",
            "two_party_session_establishment",
            establish_classical_session,
            iterations,
            public_key_bytes=64,
        )
    )
    rows.append(
        _measure(
            "X25519",
            "derive_session_key",
            lambda: derive_ecdh_key(alice_private, bob_public),
            iterations,
            public_key_bytes=32,
        )
    )

    for algorithm, keygen in (
        ("RSA-2048", lambda: generate_signing_key_pair("RSA-2048")),
        ("ECDSA-P256", lambda: generate_signing_key_pair("ECDSA-P256")),
    ):
        rows.append(_measure(algorithm, "keygen", keygen, iterations))
        private_key, public_key = keygen()
        signature = sign(private_key, message)
        rows.append(
            _measure(
                algorithm,
                "sign",
                lambda private_key=private_key: sign(private_key, message),
                iterations,
                payload_bytes=payload_bytes,
                public_key_bytes=len(public_key),
                signature_bytes=len(signature),
            )
        )
        rows.append(
            _measure(
                algorithm,
                "verify",
                lambda algorithm=algorithm, public_key=public_key, signature=signature: verify_signature(
                    algorithm, public_key, message, signature
                ),
                iterations,
                payload_bytes=payload_bytes,
                public_key_bytes=len(public_key),
                signature_bytes=len(signature),
            )
        )

    rows.append(
        _measure(
            "ML-KEM-768",
            "keygen",
            ml_kem_768_keygen,
            iterations,
            public_key_bytes=ML_KEM_768_SIZES["public_key_bytes"],
        )
    )
    kem_keys = ml_kem_768_keygen()
    rows.append(
        _measure(
            "ML-KEM-768",
            "encapsulate",
            lambda: ml_kem_768_encapsulate(kem_keys.public_key),
            iterations,
            public_key_bytes=len(kem_keys.public_key),
            ciphertext_bytes=ML_KEM_768_SIZES["ciphertext_bytes"],
        )
    )
    kem_ciphertext, _ = ml_kem_768_encapsulate(kem_keys.public_key)
    rows.append(
        _measure(
            "ML-KEM-768",
            "decapsulate",
            lambda: ml_kem_768_decapsulate(kem_keys.secret_key, kem_ciphertext),
            iterations,
            ciphertext_bytes=len(kem_ciphertext),
        )
    )

    rows.append(
        _measure(
            "ML-DSA-65",
            "keygen",
            ml_dsa_65_keygen,
            iterations,
            public_key_bytes=ML_DSA_65_SIZES["public_key_bytes"],
        )
    )
    dsa_keys = ml_dsa_65_keygen()
    dsa_signature = ml_dsa_65_sign(dsa_keys.secret_key, message)
    rows.append(
        _measure(
            "ML-DSA-65",
            "sign",
            lambda: ml_dsa_65_sign(dsa_keys.secret_key, message),
            iterations,
            payload_bytes=payload_bytes,
            public_key_bytes=len(dsa_keys.public_key),
            signature_bytes=len(dsa_signature),
        )
    )
    rows.append(
        _measure(
            "ML-DSA-65",
            "verify",
            lambda: ml_dsa_65_verify(dsa_keys.public_key, message, dsa_signature),
            iterations,
            payload_bytes=payload_bytes,
            public_key_bytes=len(dsa_keys.public_key),
            signature_bytes=len(dsa_signature),
        )
    )

    hybrid_initiator_private, _ = generate_ecdh_key_pair()
    hybrid_responder_private, hybrid_responder_public = generate_ecdh_key_pair()
    hybrid_kem_keys = ml_kem_768_keygen()

    def establish_hybrid_session() -> None:
        initiator_private, _ = generate_ecdh_key_pair()
        responder_private, responder_public = generate_ecdh_key_pair()
        responder_kem_keys = ml_kem_768_keygen()
        ciphertext, initiator_key = establish_hybrid_key(
            initiator_private, responder_public, responder_kem_keys.public_key
        )
        responder_key = complete_hybrid_key(
            responder_private,
            initiator_private.public_key(),
            responder_kem_keys.secret_key,
            responder_kem_keys.public_key,
            ciphertext,
        )
        if initiator_key != responder_key:
            raise RuntimeError("hybrid key agreement did not produce matching keys")

    rows.append(
        _measure(
            "X25519+ML-KEM-768 (experimental)",
            "two_party_session_establishment",
            establish_hybrid_session,
            iterations,
            public_key_bytes=64 + len(hybrid_kem_keys.public_key),
            ciphertext_bytes=ML_KEM_768_SIZES["ciphertext_bytes"],
        )
    )
    hybrid_ciphertext, hybrid_key = establish_hybrid_key(
        hybrid_initiator_private,
        hybrid_responder_public,
        hybrid_kem_keys.public_key,
    )
    hybrid_peer_key = complete_hybrid_key(
        hybrid_responder_private,
        hybrid_initiator_private.public_key(),
        hybrid_kem_keys.secret_key,
        hybrid_kem_keys.public_key,
        hybrid_ciphertext,
    )
    if hybrid_key != hybrid_peer_key:
        raise RuntimeError("hybrid key agreement did not produce matching keys")

    symmetric_key = bytes(range(32))
    rows.append(
        _measure(
            "AES-256-GCM",
            "encrypt",
            lambda: aes_gcm_encrypt(symmetric_key, message),
            iterations,
            payload_bytes=payload_bytes,
        )
    )
    sealed = aes_gcm_encrypt(symmetric_key, message)
    rows.append(
        _measure(
            "AES-256-GCM",
            "decrypt",
            lambda: aes_gcm_decrypt(symmetric_key, sealed),
            iterations,
            payload_bytes=payload_bytes,
            ciphertext_bytes=len(sealed),
        )
    )
    tag = hmac_sha256(symmetric_key, message)
    rows.append(
        _measure(
            "HMAC-SHA256",
            "authenticate_and_verify",
            lambda: verify_hmac_sha256(
                symmetric_key, message, hmac_sha256(symmetric_key, message)
            ),
            iterations,
            payload_bytes=payload_bytes,
            signature_bytes=len(tag),
        )
    )

    timing_nodes = [
        GridNode("control", NodeRole.CONTROL_CENTER, "control_center"),
        GridNode("substation", NodeRole.SUBSTATION, "substation"),
    ]
    network = SmartGridNetwork(timing_nodes)
    replay_protector = ReplayProtector()
    timing_payload = {"value": 123.45, "sequence": 1}

    def authenticated_substation_path() -> None:
        grid_message = GridMessage(
            source="control",
            destination="substation",
            link=GridLink.SUBSTATION_GOOSE,
            payload=timing_payload,
        )
        serialized = grid_message.serialize()
        encrypted = aes_gcm_encrypt(symmetric_key, serialized)
        tag_value = hmac_sha256(symmetric_key, encrypted)
        if not verify_hmac_sha256(symmetric_key, encrypted, tag_value):
            raise RuntimeError("HMAC verification failed")
        restored = aes_gcm_decrypt(symmetric_key, encrypted)
        if restored != serialized:
            raise RuntimeError("message decryption failed")
        network.transmit(grid_message, replay_protector)

    rows.append(
        _measure(
            "AES-256-GCM + HMAC-SHA256 (local simulation)",
            "authenticated_message_path",
            authenticated_substation_path,
            timing_trials,
            payload_bytes=payload_bytes,
            deadline_ms=SUBSTATION_DEADLINE_MS,
        )
    )

    crypto = pd.DataFrame(rows)
    qkd_rows: list[dict[str, object]] = []
    for intercept_fraction in (0.0, 0.25, 1.0):
        result = simulate_bb84(
            bit_count=10_000,
            intercept_fraction=intercept_fraction,
            seed=6_640 + int(intercept_fraction * 100),
        )
        qkd_rows.append(
            {
                "intercept_fraction": result.intercept_fraction,
                "transmitted_bits": result.transmitted_bits,
                "sifted_bits": result.sifted_bits,
                "sample_bits": result.sample_bits,
                "estimated_qber": result.estimated_qber,
                "detected_eavesdropper": result.detected_eavesdropper,
                "remaining_sifted_bits": result.remaining_sifted_bits,
                "simulation_seed": result.simulation_seed,
            }
        )
    qkd = pd.DataFrame(qkd_rows)

    qrng_bits = simulated_quantum_bits(4_096, seed=6_640)
    attacks = run_attack_demonstrations()
    metadata: dict[str, object] = {
        "benchmark_run_utc": datetime.now(timezone.utc).isoformat(),
        "classification": {
            "cryptographic_timing": "measured locally in this Python process",
            "message_deadline": "local processing only; excludes network and device I/O",
            "bb84": "Monte Carlo protocol simulation",
            "qrng": "Qiskit Aer pseudo-random measurement simulation, not physical QRNG",
            "security_validation": "functional tests only; not a certification",
        },
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor() or "not reported by host",
            "logical_cpu_count": os.cpu_count(),
            "packages": {
                name: version(name)
                for name in (
                    "cryptography",
                    "matplotlib",
                    "numpy",
                    "pandas",
                    "pqcrypto",
                    "qiskit",
                    "qiskit-aer",
                    "streamlit",
                )
            },
        },
        "benchmark_config": {
            "iterations": iterations,
            "payload_bytes": payload_bytes,
            "timing_trials": timing_trials,
            "substation_deadline_ms": SUBSTATION_DEADLINE_MS,
        },
        "qrng_simulation": {
            "bits": len(qrng_bits),
            "ones_fraction": qrng_bits.count("1") / len(qrng_bits),
            "seed": 6_640,
            "source": "Qiskit Aer simulator",
        },
        "attack_demonstrations": attacks,
    }
    return crypto, qkd, metadata


def write_results(
    crypto: pd.DataFrame,
    qkd: pd.DataFrame,
    metadata: dict[str, object],
    output_dir: Path,
) -> None:
    csv_dir = output_dir / "csv"
    figure_dir = output_dir / "figures"
    csv_dir.mkdir(parents=True, exist_ok=True)
    figure_dir.mkdir(parents=True, exist_ok=True)
    crypto.to_csv(csv_dir / "crypto_benchmarks.csv", index=False)
    qkd.to_csv(csv_dir / "qkd_experiment.csv", index=False)
    (output_dir / "metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    latency = crypto.loc[crypto["operation"].isin(["sign", "verify", "encapsulate", "decapsulate"])]
    fig, axis = plt.subplots(figsize=(10, 5))
    if not latency.empty:
        labels = latency["mechanism"] + "\n" + latency["operation"]
        axis.bar(labels, latency["median_us"])
        axis.set_ylabel("Median operation time (microseconds)")
        axis.set_title("Local cryptographic operation latency")
        axis.tick_params(axis="x", labelrotation=35)
        fig.tight_layout()
    fig.savefig(figure_dir / "crypto_latency.png", dpi=160)
    plt.close(fig)

    size_rows = crypto.loc[
        crypto["operation"].isin(["encapsulate", "sign"])
        & (crypto["public_key_bytes"] > 0)
    ]
    fig, axis = plt.subplots(figsize=(10, 5))
    if not size_rows.empty:
        axis.bar(
            size_rows["mechanism"],
            size_rows["public_key_bytes"],
            label="Public key",
        )
        axis.bar(
            size_rows["mechanism"],
            size_rows["signature_bytes"] + size_rows["ciphertext_bytes"],
            bottom=size_rows["public_key_bytes"],
            label="Signature + ciphertext",
        )
        axis.set_ylabel("Bytes")
        axis.set_title("Selected public-key and message overhead sizes")
        axis.legend()
        axis.tick_params(axis="x", labelrotation=25)
        fig.tight_layout()
    fig.savefig(figure_dir / "communication_overhead.png", dpi=160)
    plt.close(fig)

    fig, axis = plt.subplots(figsize=(7, 4))
    axis.plot(qkd["intercept_fraction"] * 100, qkd["estimated_qber"] * 100, "o-")
    axis.axhline(11, linestyle="--", color="red", label="Illustrative 11% threshold")
    axis.set_xlabel("Intercepted signals (%)")
    axis.set_ylabel("Estimated QBER (%)")
    axis.set_title("BB84 Monte Carlo eavesdropping demonstration")
    axis.legend()
    fig.tight_layout()
    fig.savefig(figure_dir / "qkd_qber.png", dpi=160)
    plt.close(fig)
