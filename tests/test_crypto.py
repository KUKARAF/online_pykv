"""Unit tests for device-envelope decryption (online_pykv._crypto).

We build the encrypted envelope in-test the same way ``kv_manager``'s
``crypto.rs::wrap_for_device`` does (a locally generated device keypair as the
recipient), then assert the client's ``decrypt_envelope`` recovers the exact
plaintext token — covering both x25519 and p256, plus AAD binding.
"""

import base64
import os

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from online_pykv import _crypto

_SALT = b"\x00" * 32
_INFO = b"kv-device-wrap"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _wrap_for_device(public_key_b64: str, key_type: str, token: str, aad: bytes) -> dict:
    """Server-side wrap: produce an envelope decryptable by the device key.

    Mirrors kv_manager's scheme so the test's fixture is authoritative rather
    than a re-implementation of the code under test.
    """
    pub_bytes = base64.b64decode(public_key_b64)

    if key_type == "x25519":
        eph = X25519PrivateKey.generate()
        device_pub = X25519PublicKey.from_public_bytes(pub_bytes)
        shared = eph.exchange(device_pub)
        ephemeral_pub = eph.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    elif key_type == "p256":
        eph = ec.generate_private_key(ec.SECP256R1())
        device_pub = serialization.load_der_public_key(pub_bytes)
        shared = eph.exchange(ec.ECDH(), device_pub)
        ephemeral_pub = eph.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    else:
        raise ValueError(key_type)

    wrap_key = HKDF(algorithm=SHA256(), length=32, salt=_SALT, info=_INFO).derive(shared)

    dek = os.urandom(32)
    dek_nonce = os.urandom(12)
    encrypted_dek = AESGCM(wrap_key).encrypt(dek_nonce, dek, None)

    body_nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(body_nonce, token.encode(), aad)

    return {
        "nonce": _b64(body_nonce),
        "ciphertext": _b64(ciphertext),
        "aad": _b64(aad),
        "recipient": {
            "key_type": key_type,
            "ephemeral_pub": _b64(ephemeral_pub),
            "dek_nonce": _b64(dek_nonce),
            "encrypted_dek": _b64(encrypted_dek),
        },
    }


@pytest.mark.parametrize("key_type", ["x25519", "p256"])
def test_decrypt_envelope_roundtrip(key_type):
    priv_b64, pub_b64 = _crypto.generate_device_keypair(key_type)
    assert _crypto.key_type_of(priv_b64) == key_type
    # public_key_b64 recomputed from the stored private key must match the one
    # returned at generation time (this is what gets enrolled on the server).
    assert _crypto.public_key_b64(priv_b64) == pub_b64

    token = "kv_sess_" + "a1b2c3d4" * 4
    aad = b"11111111-2222-3333-4444-555555555555"  # request UUID, as server binds
    envelope = _wrap_for_device(pub_b64, key_type, token, aad)

    assert _crypto.decrypt_envelope(envelope, priv_b64) == token


def test_decrypt_rejects_wrong_device_key():
    priv_b64, pub_b64 = _crypto.generate_device_keypair("x25519")
    other_priv, _ = _crypto.generate_device_keypair("x25519")
    envelope = _wrap_for_device(pub_b64, "x25519", "secret-token", b"req-id")
    with pytest.raises(Exception):
        _crypto.decrypt_envelope(envelope, other_priv)


def test_decrypt_rejects_tampered_aad():
    priv_b64, pub_b64 = _crypto.generate_device_keypair("x25519")
    envelope = _wrap_for_device(pub_b64, "x25519", "secret-token", b"req-id-A")
    envelope["aad"] = _b64(b"req-id-B")  # AAD no longer matches -> GCM auth fail
    with pytest.raises(Exception):
        _crypto.decrypt_envelope(envelope, priv_b64)
