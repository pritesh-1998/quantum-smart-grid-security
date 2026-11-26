"""Safe, local demonstrations of tamper and replay detection."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag

from security.classical import aes_gcm_decrypt, aes_gcm_encrypt, generate_signing_key_pair, sign, verify_signature
from smart_grid.network import DuplicateMessageError, ReplayProtector


def run_attack_demonstrations() -> dict[str, object]:
    key = bytes(range(32))
    plaintext = b"synthetic smart-grid telemetry"
    sealed = aes_gcm_encrypt(key, plaintext)
    altered = sealed[:-1] + bytes([sealed[-1] ^ 1])
    try:
        aes_gcm_decrypt(key, altered)
    except InvalidTag:
        tamper_rejected = True
    else:
        raise RuntimeError("modified AES-GCM ciphertext was accepted")

    private_key, public_key = generate_signing_key_pair("ECDSA-P256")
    signature = sign(private_key, plaintext)
    altered_message = plaintext + b" altered"
    signature_tamper_rejected = not verify_signature(
        "ECDSA-P256", public_key, altered_message, signature
    )
    if not signature_tamper_rejected:
        raise RuntimeError("modified signed message was accepted")

    replay = ReplayProtector()
    replay.accept("synthetic-message-1")
    try:
        replay.accept("synthetic-message-1")
    except DuplicateMessageError:
        replay_rejected = True
    else:
        raise RuntimeError("duplicate message ID was accepted")
    return {
        "scenario": "synthetic local tamper and replay checks",
        "aes_gcm_tamper_rejected": tamper_rejected,
        "signature_tamper_rejected": signature_tamper_rejected,
        "duplicate_id_rejected": replay_rejected,
        "limitations": "not a network penetration test or IEC 61850 validation",
    }
