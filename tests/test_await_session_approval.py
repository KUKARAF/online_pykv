"""Tests for the session-request approval polling flow (client-side).

Covers the server contract where the status endpoint returns a device-encrypted
one-time ``approval_envelope`` while pending (decrypted + printed once for the
operator to relay to their admin), and the final ``envelope`` carrying the
session token on ``approved``.

Envelopes are built in-test the same way ``kv_manager`` wraps them, reusing the
authoritative ``_wrap_for_device`` fixture from ``test_crypto``.
"""

import json

from online_pykv import _crypto, client
from tests.test_crypto import _wrap_for_device


def _make_poller(responses):
    """Return a fake ``_unauthenticated_request`` that yields ``responses``.

    Each entry is a dict serialized to JSON; the last is repeated if polling
    outlives the list.
    """
    calls = {"n": 0}

    def fake_request(method, path, body=None, base_url=None):
        i = min(calls["n"], len(responses) - 1)
        calls["n"] += 1
        return json.dumps(responses[i])

    return fake_request


def test_approval_token_printed_once_then_session_token_returned(monkeypatch, capsys):
    priv_b64, pub_b64 = _crypto.generate_device_keypair("x25519")
    request_id = "11111111-2222-3333-4444-555555555555"
    aad = request_id.encode()

    approval_token = "approve-me-42"
    session_token = "kv_sess_" + "abcdef01" * 4

    approval_env = _wrap_for_device(pub_b64, "x25519", approval_token, aad)
    session_env = _wrap_for_device(pub_b64, "x25519", session_token, aad)

    # Two pending polls (approval_envelope present), then approved.
    responses = [
        {"status": "pending", "approval_envelope": approval_env},
        {"status": "pending", "approval_envelope": approval_env},
        {"status": "approved", "envelope": session_env},
    ]
    monkeypatch.setattr(client, "_unauthenticated_request", _make_poller(responses))
    monkeypatch.setattr(client.time, "sleep", lambda *_: None)

    token = client.await_session_approval(
        request_id,
        poll_interval=0.0,
        save_to_config=False,
        device_private_key=priv_b64,
    )

    assert token == session_token

    err = capsys.readouterr().err
    # Approval code printed exactly once even though it polled while pending twice.
    assert err.count(f"Approval code: {approval_token}") == 1
    assert "relay this to your admin" in err
    # The session token must never be printed.
    assert session_token not in err
