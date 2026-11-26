"""Classical cryptographic primitives used as the testbed baseline."""

from __future__ import annotations

from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SignatureAlgorithm = Literal["RSA-2048", "ECDSA-P256"]


def generate_ecdh_key_pair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    private_key = x25519.X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def raw_public_key(public_key: x25519.X25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def derive_ecdh_key(
    private_key: x25519.X25519PrivateKey,
    peer_public_key: x25519.X25519PublicKey,
    *,
    info: bytes = b"smart-grid-session-v1",
) -> bytes:
    shared_secret = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, *, aad: bytes = b"") -> bytes:
    """Return nonce || ciphertext || tag using a fresh 96-bit nonce."""
    import os

    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, sealed: bytes, *, aad: bytes = b"") -> bytes:
    if len(sealed) < 12 + 16:
        raise ValueError("AES-GCM input is shorter than nonce and authentication tag")
    return AESGCM(key).decrypt(sealed[:12], sealed[12:], aad)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    authenticator = hmac.HMAC(key, hashes.SHA256())
    authenticator.update(message)
    return authenticator.finalize()


def verify_hmac_sha256(key: bytes, message: bytes, tag: bytes) -> bool:
    authenticator = hmac.HMAC(key, hashes.SHA256())
    authenticator.update(message)
    try:
        authenticator.verify(tag)
    except InvalidSignature:
        return False
    return True


def generate_signing_key_pair(
    algorithm: SignatureAlgorithm,
) -> tuple[rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, bytes]:
    if algorithm == "RSA-2048":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif algorithm == "ECDSA-P256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError(f"unsupported signature algorithm: {algorithm}")
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key


def sign(
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    message: bytes,
) -> bytes:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    raise TypeError("unsupported signing key type")


def verify_signature(
    algorithm: SignatureAlgorithm,
    public_key_der: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    public_key = serialization.load_der_public_key(public_key_der)
    try:
        if algorithm == "RSA-2048" and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif algorithm == "ECDSA-P256" and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError("public key does not match the selected algorithm")
    except InvalidSignature:
        return False
    return True
