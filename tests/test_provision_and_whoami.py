"""Tests for automated device enrolment (provision_device) and whoami."""

import json

import pytest

from online_pykv import client


def test_provision_device_polls_until_confirmed(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    calls = []

    def fake_request(method, path, body=None, base_url=None):
        calls.append((method, path, json.loads(body) if body else None))
        if path == "/api/devices/propose":
            assert calls[-1][2]["name"] == "my-host"
            assert calls[-1][2]["key_type"] == "x25519"
            return json.dumps(
                {
                    "id": "proposal-1",
                    "url": "https://kv.osmosis.page/admin/device-proposal.html?id=proposal-1",
                    "expires_at": "2026-01-01T00:30:00Z",
                    "poll_secret": "secret-abc",
                }
            )
        if path.startswith("/api/devices/propose/proposal-1/status"):
            assert "secret=secret-abc" in path
            n = sum(1 for c in calls if c[1].startswith("/api/devices/propose/proposal-1/status"))
            if n < 2:
                return json.dumps({"status": "pending"})
            return json.dumps({"status": "confirmed", "device_id": "dev-99"})
        raise AssertionError(f"unexpected path {path}")

    monkeypatch.setattr(client, "_unauthenticated_request", fake_request)
    monkeypatch.setattr(client.time, "sleep", lambda *_: None)

    result = client.provision_device(
        name="my-host",
        poll_interval=0.0,
        print_instructions=False,
    )

    assert result["device_id"] == "dev-99"
    assert result["private_key"]
    assert result["public_key"]

    saved = client.load_config()
    assert saved.device_id == "dev-99"
    assert saved.device_private_key == result["private_key"]


def test_provision_device_raises_on_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    def fake_request(method, path, body=None, base_url=None):
        if path == "/api/devices/propose":
            return json.dumps(
                {
                    "id": "proposal-2",
                    "url": "https://kv.osmosis.page/admin/device-proposal.html?id=proposal-2",
                    "expires_at": "2026-01-01T00:30:00Z",
                    "poll_secret": "secret-def",
                }
            )
        return json.dumps({"status": "rejected"})

    monkeypatch.setattr(client, "_unauthenticated_request", fake_request)
    monkeypatch.setattr(client.time, "sleep", lambda *_: None)

    with pytest.raises(client.KVError):
        client.provision_device(name="my-host", poll_interval=0.0, print_instructions=False)


def test_whoami_sends_bearer_and_parses_response(monkeypatch):
    captured = {}

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            return json.dumps(self._payload).encode()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        return FakeResponse({"device_id": "dev-1", "device_name": "bigboy"})

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)

    result = client.whoami(session_token="tok-123", base_url="https://kv.osmosis.page")

    assert result == {"device_id": "dev-1", "device_name": "bigboy"}
    assert captured["url"] == "https://kv.osmosis.page/api/admin/session/whoami"
    assert captured["headers"]["Authorization"] == "Bearer tok-123"
