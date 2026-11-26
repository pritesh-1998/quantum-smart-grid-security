"""Short, narrated live demo of the testbed.

Run from the project root:
    .venv/bin/python -m experiments.live_demo

It does not write anything to results/, so the saved results stay unchanged.
"""

from __future__ import annotations

import json
import statistics
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519

from security.classical import aes_gcm_decrypt, aes_gcm_encrypt
from security.hybrid import complete_hybrid_key, establish_hybrid_key
from security.pqc import ml_dsa_65_keygen, ml_dsa_65_sign, ml_kem_768_keygen
from security.qkd_bb84 import simulate_bb84
from smart_grid.network import DuplicateMessageError, ReplayProtector

ETHERNET_FRAME = 1500


def median_us(action, runs: int) -> float:
    """Median time of `action` in microseconds, after one warm-up run."""
    action()
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        action()
        samples.append((time.perf_counter() - start) * 1e6)
    return statistics.median(samples)


def step(number: int, title: str) -> None:
    input(f"\n[Press Enter for step {number}]")
    print(f"\n=== STEP {number}: {title} ===")


def main() -> None:
    print("Quantum-safe smart grid - live demo")
    print("Control center  <->  Substation")

    step(1, "Hybrid key setup (X25519 + ML-KEM-768), done once per session")
    control_x = x25519.X25519PrivateKey.generate()
    substation_x = x25519.X25519PrivateKey.generate()
    substation_kem = ml_kem_768_keygen()
    ciphertext, control_key = establish_hybrid_key(
        control_x, substation_x.public_key(), substation_kem.public_key
    )
    substation_key = complete_hybrid_key(
        substation_x,
        control_x.public_key(),
        substation_kem.secret_key,
        substation_kem.public_key,
        ciphertext,
    )
    elapsed_us = median_us(
        lambda: complete_hybrid_key(
            substation_x,
            control_x.public_key(),
            substation_kem.secret_key,
            substation_kem.public_key,
            establish_hybrid_key(control_x, substation_x.public_key(), substation_kem.public_key)[0],
        ),
        runs=25,
    )
    print(f"ML-KEM public key: {len(substation_kem.public_key)} bytes")
    print(f"ML-KEM ciphertext: {len(ciphertext)} bytes")
    print(f"Control center key: {control_key.hex()[:32]}...")
    print(f"Substation key:     {substation_key.hex()[:32]}...")
    print(f"Keys match: {control_key == substation_key}  (median {elapsed_us:.0f} us)")

    step(2, "Protect a grid command with AES-256-GCM, done on every message")
    command = {"message_id": "msg-001", "command": "trip_breaker", "breaker": "B-12"}
    plaintext = json.dumps(command).encode()
    sealed = aes_gcm_encrypt(control_key, plaintext)
    elapsed_us = median_us(lambda: aes_gcm_encrypt(control_key, plaintext), runs=200)
    print(f"Command:   {command}")
    print(f"Encrypted: {sealed.hex()[:48]}...")
    print(f"Size: {len(plaintext)} -> {len(sealed)} bytes (+28: nonce and tag)")
    print(f"Encrypt time (median): {elapsed_us:.1f} us  (budget is 3,000 us)")
    print(f"Substation decrypts: {json.loads(aes_gcm_decrypt(substation_key, sealed))}")

    step(3, "Attack 1 - an attacker flips one bit of the message")
    tampered = sealed[:-1] + bytes([sealed[-1] ^ 1])
    try:
        aes_gcm_decrypt(substation_key, tampered)
        print("Accepted (this should not happen)")
    except InvalidTag:
        print("REJECTED: the authentication tag does not match")

    step(4, "Attack 2 - an attacker replays an old 'trip breaker' message")
    guard = ReplayProtector()
    guard.accept(command["message_id"])
    print("First copy of msg-001: accepted")
    try:
        guard.accept(command["message_id"])
        print("Accepted (this should not happen)")
    except DuplicateMessageError:
        print("Second copy of msg-001: REJECTED as a replay")

    step(5, "Why not sign every message with ML-DSA-65?")
    signer = ml_dsa_65_keygen()
    signature = ml_dsa_65_sign(signer.secret_key, plaintext)
    elapsed_us = median_us(lambda: ml_dsa_65_sign(signer.secret_key, plaintext), runs=10)
    print(f"ML-DSA sign time (median): {elapsed_us:,.0f} us  (budget is 3,000 us)")
    print(f"Signature size: {len(signature):,} bytes  (one Ethernet frame is ~{ETHERNET_FRAME:,})")
    print("-> Use PQC for setup and firmware, a fast symmetric check per message.")

    step(6, "BB84 quantum key distribution - can we catch an eavesdropper?")
    for fraction in (0.0, 1.0):
        result = simulate_bb84(10_000, intercept_fraction=fraction, seed=6640 + int(fraction * 100))
        verdict = "EVE DETECTED, abort" if result.detected_eavesdropper else "channel clean, keep key"
        print(f"Eve intercepts {fraction:.0%}: error rate {result.estimated_qber:.2%} -> {verdict}")
    print("Threshold: 11%. Eve measuring every photon causes ~25% errors.")

    print("\nDemo finished. All attacks were rejected.")


if __name__ == "__main__":
    main()
