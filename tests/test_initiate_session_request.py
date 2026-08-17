"""Tests for the challenge-response session-request creation flow.

The server now requires proof of device-key possession before creating a
pending session request:
  1. POST /api/session-request/challenge {device_id} -> an envelope wrapping
     a random nonce to the device's public key.
  2. Decrypt the envelope locally, then POST /api/session-request
     {challenge_id, nonce, label, requested_duration_hours}.
A bare device_id is no longer accepted directly by /api/session-request.
"""

import json

from online_pykv import _crypto, client
from tests.test_crypto import _wrap_for_device


def test_initiate_session_request_does_challenge_then_create(monkeypatch):
    priv_b64, pub_b64 = _crypto.generate_device_keypair("x25519")
    device_id = "device-123"
    challenge_id = "challenge-abc"
    nonce = "the-plaintext-nonce"

    challenge_envelope = _wrap_for_device(
        pub_b64, "x25519", nonce, challenge_id.encode()
    )

    calls = []

    def fake_request(method, path, body=None, base_url=None):
        calls.append((method, path, json.loads(body) if body else None))
        if path == "/api/session-request/challenge":
            assert calls[-1][2] == {"device_id": device_id}
            return json.dumps(
                {
                    "challenge_id": challenge_id,
                    "envelope": challenge_envelope,
                    "expires_at": "2026-01-01T00:00:00Z",
                }
            )
        if path == "/api/session-request":
            body_dict = calls[-1][2]
            assert body_dict["challenge_id"] == challenge_id
            assert body_dict["nonce"] == nonce
            assert "device_id" not in body_dict
            return json.dumps(
                {
                    "id": "req-1",
                    "url": "https://kv.osmosis.page/admin/session-request.html?id=req-1",
                    "expires_at": "2026-01-01T00:15:00Z",
                    "poll_secret": "secret-xyz",
                }
            )
        raise AssertionError(f"unexpected path {path}")

    monkeypatch.setattr(client, "_unauthenticated_request", fake_request)

    result = client.initiate_session_request(
        label="test",
        show_qr=False,
        device_id=device_id,
        device_private_key=priv_b64,
    )

    assert result["id"] == "req-1"
    assert result["poll_secret"] == "secret-xyz"
    paths = [c[1] for c in calls]
    assert paths == ["/api/session-request/challenge", "/api/session-request"]


def test_initiate_session_request_requires_device_identity(monkeypatch, tmp_path):
    # Isolate from any real config/env so no device identity is found.
    monkeypatch.delenv("KV_DEVICE_ID", raising=False)
    monkeypatch.delenv("KV_DEVICE_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    try:
        client.initiate_session_request(
            device_id=None, device_private_key=None, base_url="https://example.invalid"
        )
        assert False, "expected KVError"
    except client.KVError as e:
        assert "device_id" in str(e) or "device_private_key" in str(e)
