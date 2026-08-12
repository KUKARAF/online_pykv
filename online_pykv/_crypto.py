"""Device-key crypto for the session-request approval flow.

The server no longer returns a plaintext ``session_token`` from the
session-request status endpoint.  Instead the approved token is delivered
ECDH-wrapped to a device public key that was registered on the server.  This
module implements the client half of that scheme: generating/holding a device
keypair and decrypting the envelope back into the plaintext session token.

Scheme (must stay byte-compatible with ``kv_manager``'s device wrap):

1. ECDH between the device private key and a per-message ephemeral public key
   (x25519 raw keys, or NIST P-256 with DER-SPKI device key + SEC1 ephemeral).
2. HKDF-SHA256(shared, salt=32*0x00, info=b"kv-device-wrap", len=32) -> wrap_key.
3. AES-256-GCM unwrap of ``encrypted_dek`` (key=wrap_key, nonce=dek_nonce, no
   AAD) -> 32-byte DEK.
4. AES-256-GCM decrypt of ``ciphertext`` (key=DEK, nonce=nonce, aad=aad) ->
   the session-token bytes.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

_HKDF_SALT = b"\x00" * 32
_HKDF_INFO = b"kv-device-wrap"
_KEY_TYPES = ("x25519", "p256")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


# ---------------------------------------------------------------------------
# Device keypair generation / (de)serialization
# ---------------------------------------------------------------------------
#
# Private keys are persisted as base64(PKCS#8 DER); ``load_der_private_key``
# recovers the concrete key type on its own, so the config only needs to store
# the single opaque ``device_private_key`` string.  The public key handed to
# the human for enrolment is encoded the way the *server* expects it:
#   - x25519 -> raw 32-byte public key
#   - p256   -> DER SubjectPublicKeyInfo

def generate_device_keypair(key_type: str = "x25519") -> tuple[str, str]:
    """Generate a device keypair.

    Returns ``(private_key_b64, public_key_b64)`` where ``private_key_b64`` is
    base64(PKCS#8 DER) meant for local storage, and ``public_key_b64`` is the
    server-facing public key encoding to enrol.
    """
    if key_type not in _KEY_TYPES:
        raise ValueError(f"unsupported key_type {key_type!r}; use one of {_KEY_TYPES}")

    if key_type == "x25519":
        priv = X25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    else:  # p256
        priv = ec.generate_private_key(ec.SECP256R1())
        pub_bytes = priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    priv_der = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return _b64e(priv_der), _b64e(pub_bytes)


def _load_private_key(private_key_b64: str):
    return serialization.load_der_private_key(_b64d(private_key_b64), password=None)


def key_type_of(private_key_b64: str) -> str:
    """Report the key type ("x25519" | "p256") of a stored private key."""
    priv = _load_private_key(private_key_b64)
    if isinstance(priv, X25519PrivateKey):
        return "x25519"
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        return "p256"
    raise ValueError(f"unsupported private key type {type(priv).__name__}")


def public_key_b64(private_key_b64: str) -> str:
    """Recompute the server-facing public key encoding from a stored priv key."""
    priv = _load_private_key(private_key_b64)
    if isinstance(priv, X25519PrivateKey):
        return _b64e(
            priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        return _b64e(
            priv.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    raise ValueError(f"unsupported private key type {type(priv).__name__}")


# ---------------------------------------------------------------------------
# Envelope decryption
# ---------------------------------------------------------------------------

def _ecdh_shared(priv, key_type: str, ephemeral_pub: bytes) -> bytes:
    if key_type == "x25519":
        if not isinstance(priv, X25519PrivateKey):
            raise ValueError("envelope is x25519 but device key is not")
        pub = X25519PublicKey.from_public_bytes(ephemeral_pub)
        return priv.exchange(pub)
    if key_type == "p256":
        if not isinstance(priv, ec.EllipticCurvePrivateKey):
            raise ValueError("envelope is p256 but device key is not")
        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_pub
        )
        return priv.exchange(ec.ECDH(), pub)
    raise ValueError(f"unsupported key_type {key_type!r}")


def decrypt_envelope(envelope: dict, private_key_b64: str) -> str:
    """Decrypt a session-request envelope back into the session-token string.

    ``envelope`` is the server's ``{nonce, ciphertext, aad, recipient{...}}``
    object (all binary fields base64-standard).  ``private_key_b64`` is the
    stored device private key (base64 PKCS#8 DER).
    """
    recipient = envelope["recipient"]
    key_type = recipient["key_type"]
    if key_type not in _KEY_TYPES:
        raise ValueError(f"unsupported envelope key_type {key_type!r}")

    priv = _load_private_key(private_key_b64)
    ephemeral_pub = _b64d(recipient["ephemeral_pub"])
    shared = _ecdh_shared(priv, key_type, ephemeral_pub)

    wrap_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(shared)

    # Unwrap the DEK (no AAD). AESGCM expects ciphertext||tag concatenated,
    # which is exactly what the server emits.
    dek = AESGCM(wrap_key).decrypt(
        _b64d(recipient["dek_nonce"]),
        _b64d(recipient["encrypted_dek"]),
        None,
    )

    # Decrypt the body with the DEK, binding the AAD.
    token = AESGCM(dek).decrypt(
        _b64d(envelope["nonce"]),
        _b64d(envelope["ciphertext"]),
        _b64d(envelope["aad"]),
    )
    return token.decode()
