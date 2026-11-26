"""NIST-standardized PQC wrappers provided by the pqcrypto package.

The package implementation is not represented as a FIPS-validated module.
"""

from __future__ import annotations

from dataclasses import dataclass

from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65


@dataclass(frozen=True, slots=True)
class KemKeyPair:
    public_key: bytes
    secret_key: bytes


@dataclass(frozen=True, slots=True)
class SignatureKeyPair:
    public_key: bytes
    secret_key: bytes


def ml_kem_768_keygen() -> KemKeyPair:
    public_key, secret_key = ml_kem_768.keygen()
    return KemKeyPair(public_key, secret_key)


def ml_kem_768_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    return ml_kem_768.encaps(public_key)


def ml_kem_768_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    return ml_kem_768.decaps(secret_key, ciphertext)


def ml_dsa_65_keygen() -> SignatureKeyPair:
    public_key, secret_key = ml_dsa_65.keygen()
    return SignatureKeyPair(public_key, secret_key)


def ml_dsa_65_sign(secret_key: bytes, message: bytes) -> bytes:
    return ml_dsa_65.sign(secret_key, message)


def ml_dsa_65_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        ml_dsa_65.verify(public_key, message, signature)
    except ValueError:
        return False
    return True


ML_KEM_768_SIZES = {
    "public_key_bytes": ml_kem_768.PUBLIC_KEY_SIZE,
    "secret_key_bytes": ml_kem_768.SECRET_KEY_SIZE,
    "ciphertext_bytes": ml_kem_768.CIPHERTEXT_SIZE,
    "shared_secret_bytes": ml_kem_768.SHARED_SECRET_SIZE,
}

ML_DSA_65_SIZES = {
    "public_key_bytes": ml_dsa_65.PUBLIC_KEY_SIZE,
    "secret_key_bytes": ml_dsa_65.SECRET_KEY_SIZE,
    "signature_bytes": ml_dsa_65.SIGNATURE_SIZE,
}
