"""Tests for the session-request approval polling flow (client-side).

Covers the current server contract: the status endpoint returns only
``status`` while pending (no ``approval_envelope`` — that design was
removed), and a device-encrypted ``envelope`` carrying the session token once
``approved``.

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


def test_pending_then_approved_returns_session_token(monkeypatch, capsys):
    priv_b64, pub_b64 = _crypto.generate_device_keypair("x25519")
    request_id = "11111111-2222-3333-4444-555555555555"
    aad = request_id.encode()

    session_token = "kv_sess_" + "abcdef01" * 4
    session_env = _wrap_for_device(pub_b64, "x25519", session_token, aad)

    # Two pending polls, then approved.
    responses = [
        {"status": "pending"},
        {"status": "pending"},
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
    # The session token must never be printed.
    assert session_token not in err


def test_rejected_raises(monkeypatch):
    priv_b64, _ = _crypto.generate_device_keypair("x25519")
    request_id = "11111111-2222-3333-4444-555555555555"

    responses = [{"status": "pending"}, {"status": "rejected"}]
    monkeypatch.setattr(client, "_unauthenticated_request", _make_poller(responses))
    monkeypatch.setattr(client.time, "sleep", lambda *_: None)

    try:
        client.await_session_approval(
            request_id,
            poll_interval=0.0,
            save_to_config=False,
            device_private_key=priv_b64,
        )
        assert False, "expected KVError"
    except client.KVError as e:
        assert "rejected" in str(e)
