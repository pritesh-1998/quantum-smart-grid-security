import pytest
from cryptography.exceptions import InvalidTag

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


def test_ecdh_parties_derive_the_same_session_key():
    alice_private, alice_public = generate_ecdh_key_pair()
    bob_private, bob_public = generate_ecdh_key_pair()

    assert derive_ecdh_key(alice_private, bob_public) == derive_ecdh_key(
        bob_private, alice_public
    )


def test_aes_gcm_detects_ciphertext_and_aad_tampering():
    key = bytes(range(32))
    sealed = aes_gcm_encrypt(key, b"telemetry", aad=b"meter-1")

    assert aes_gcm_decrypt(key, sealed, aad=b"meter-1") == b"telemetry"
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(key, sealed, aad=b"meter-2")
    altered = sealed[:-1] + bytes([sealed[-1] ^ 1])
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(key, altered, aad=b"meter-1")


def test_hmac_rejects_modified_message():
    key = b"test key"
    tag = hmac_sha256(key, b"original")

    assert verify_hmac_sha256(key, b"original", tag)
    assert not verify_hmac_sha256(key, b"modified", tag)


@pytest.mark.parametrize("algorithm", ["RSA-2048", "ECDSA-P256"])
def test_classical_signatures_validate_message_integrity(algorithm):
    private_key, public_key = generate_signing_key_pair(algorithm)
    signature = sign(private_key, b"event")

    assert verify_signature(algorithm, public_key, b"event", signature)
    assert not verify_signature(algorithm, public_key, b"altered event", signature)
