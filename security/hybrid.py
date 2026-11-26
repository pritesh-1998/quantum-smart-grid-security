"""Experimental X25519 + ML-KEM-768 key-establishment combiner."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from security.classical import derive_ecdh_key, raw_public_key
from security.pqc import ml_kem_768_decapsulate, ml_kem_768_encapsulate
from cryptography.hazmat.primitives.asymmetric import x25519


def establish_hybrid_key(
    initiator_private_key: x25519.X25519PrivateKey,
    responder_public_key: x25519.X25519PublicKey,
    kem_responder_public_key: bytes,
) -> tuple[bytes, bytes]:
    ciphertext, kem_secret = ml_kem_768_encapsulate(kem_responder_public_key)
    classical_secret = derive_ecdh_key(
        initiator_private_key,
        responder_public_key,
        info=b"smart-grid-hybrid-classical-v1",
    )
    transcript = (
        raw_public_key(initiator_private_key.public_key())
        + raw_public_key(responder_public_key)
        + kem_responder_public_key
        + ciphertext
    )
    key = _combine(classical_secret, kem_secret, transcript)
    return ciphertext, key


def complete_hybrid_key(
    responder_private_key: x25519.X25519PrivateKey,
    initiator_public_key: x25519.X25519PublicKey,
    kem_responder_secret_key: bytes,
    kem_responder_public_key: bytes,
    ciphertext: bytes,
) -> bytes:
    kem_secret = ml_kem_768_decapsulate(kem_responder_secret_key, ciphertext)
    classical_secret = derive_ecdh_key(
        responder_private_key,
        initiator_public_key,
        info=b"smart-grid-hybrid-classical-v1",
    )
    transcript = (
        raw_public_key(initiator_public_key)
        + raw_public_key(responder_private_key.public_key())
        + kem_responder_public_key
        + ciphertext
    )
    return _combine(classical_secret, kem_secret, transcript)


def _combine(classical_secret: bytes, kem_secret: bytes, transcript: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"smart-grid-experimental-hybrid-v1" + transcript,
    ).derive(classical_secret + kem_secret)
