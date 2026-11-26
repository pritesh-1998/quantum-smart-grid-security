from security.hybrid import complete_hybrid_key, establish_hybrid_key
from security.pqc import (
    ml_dsa_65_keygen,
    ml_dsa_65_sign,
    ml_dsa_65_verify,
    ml_kem_768_decapsulate,
    ml_kem_768_encapsulate,
    ml_kem_768_keygen,
)
from security.classical import generate_ecdh_key_pair


def test_ml_kem_768_encapsulation_matches_decapsulation():
    keys = ml_kem_768_keygen()

    ciphertext, sender_secret = ml_kem_768_encapsulate(keys.public_key)

    assert sender_secret == ml_kem_768_decapsulate(keys.secret_key, ciphertext)


def test_ml_dsa_65_rejects_modified_message():
    keys = ml_dsa_65_keygen()
    signature = ml_dsa_65_sign(keys.secret_key, b"control event")

    assert ml_dsa_65_verify(keys.public_key, b"control event", signature)
    assert not ml_dsa_65_verify(keys.public_key, b"altered event", signature)


def test_experimental_hybrid_establishment_matches_on_both_sides():
    initiator_private, _ = generate_ecdh_key_pair()
    responder_private, responder_public = generate_ecdh_key_pair()
    kem_keys = ml_kem_768_keygen()

    ciphertext, initiator_key = establish_hybrid_key(
        initiator_private, responder_public, kem_keys.public_key
    )
    responder_key = complete_hybrid_key(
        responder_private,
        initiator_private.public_key(),
        kem_keys.secret_key,
        kem_keys.public_key,
        ciphertext,
    )

    assert initiator_key == responder_key
