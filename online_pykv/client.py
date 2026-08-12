import contextlib
import errno
import json
import sys
import time
import tomllib
import tomli_w
import urllib.request
import urllib.error
import urllib.parse
import qrcode
from cryptography.exceptions import InvalidTag
from typing import Callable, Optional
from ._config import Config, load_config, _config_path
from . import _crypto

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:  # pragma: no cover - non-POSIX platforms
    _HAS_FCNTL = False


class KVError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(f"HTTP {status}: {message}")


class NotFoundError(KVError):
    pass


class AuthError(KVError):
    pass


# ---------------------------------------------------------------------------
# Module-level helpers (no auth required)
# ---------------------------------------------------------------------------

def _resolve_base_url(base_url: str | None = None) -> str:
    if base_url:
        return base_url.rstrip("/")
    return load_config().base_url


def _unauthenticated_request(
    method: str,
    path: str,
    body: bytes | None = None,
    base_url: str | None = None,
) -> str:
    url = f"{_resolve_base_url(base_url)}{path}"
    headers: dict[str, str] = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode()
    except urllib.error.HTTPError as e:
        msg = e.read().decode()
        raise KVError(e.code, msg) from e


def initiate_session_request(
    label: str | None = None,
    base_url: str | None = None,
    show_qr: bool = True,
    device_id: str | None = None,
    requested_duration_hours: int | None = None,
) -> dict:
    """Create a KV session request (no auth required).

    Returns a dict with ``id``, ``url``, ``expires_at``, ``poll_secret`` and
    ``confirm_code``.  Prints the approval URL to stderr; optionally renders an
    ASCII QR code.

    Pass ``show_qr=False`` when a separate channel (e.g. Zulip) will carry
    the URL, so the terminal output stays clean.

    ``device_id`` is now REQUIRED by the server: the approved session token is
    ECDH-wrapped to that registered device's public key.  Falls back to the
    ``device_id`` in config / ``KV_DEVICE_ID``.  If none is configured, run
    :func:`provision_device` once and enrol the printed public key (see its
    docstring) to obtain a device id.
    """
    if device_id is None:
        device_id = load_config().device_id
    if not device_id:
        raise KVError(
            0,
            "No device_id configured. The server now wraps the approved "
            "session token to a registered device key. Run "
            "online_pykv.provision_device() once, enrol the printed public key "
            "in the web admin panel, then put the returned device_id in "
            "~/.config/kv/config.toml (or set KV_DEVICE_ID).",
        )

    payload: dict = {"label": label, "device_id": device_id}
    if requested_duration_hours is not None:
        payload["requested_duration_hours"] = requested_duration_hours
    body = json.dumps(payload).encode()
    raw = _unauthenticated_request("POST", "/api/session-request", body, base_url)
    data = json.loads(raw)

    print(f"\n  Approval URL:\n  {data['url']}", file=sys.stderr)
    print(f"  Expires: {data['expires_at']}\n", file=sys.stderr)

    if show_qr:
        qr = qrcode.QRCode(border=1)
        qr.add_data(data["url"])
        qr.make(fit=True)
        qr.print_ascii(out=sys.stderr)

    return data  # {id, url, expires_at}


def await_session_approval(
    request_id: str,
    base_url: str | None = None,
    poll_interval: float = 5.0,
    timeout: float = 900.0,
    save_to_config: bool = True,
    poll_secret: str | None = None,
    device_private_key: str | None = None,
) -> str:
    """Poll for approval of a session request (no auth required).

    Blocks until the request is approved, rejected, or timed out.
    Returns the session token string on success.
    Raises ``KVError`` on rejection, expiry, or timeout.

    ``poll_secret`` is the ``poll_secret`` field from the matching
    ``initiate_session_request`` response.  The server requires it on the
    status endpoint (it proves we created the request); without it every
    poll 400s and the loop would spin until timeout even after approval.

    The approved token is no longer returned in plaintext: it arrives as an
    ECDH ``envelope`` wrapped to the device public key, and is decrypted here
    with ``device_private_key`` (base64 PKCS#8 DER; falls back to config /
    ``KV_DEVICE_PRIVATE_KEY``).  The envelope is one-time-read on the server,
    so the very first ``approved`` poll must succeed at decrypting it.
    """
    if device_private_key is None:
        device_private_key = load_config().device_private_key
    if not device_private_key:
        raise KVError(
            0,
            "No device_private_key configured; cannot decrypt the approved "
            "session token. Run online_pykv.provision_device() once to create "
            "and store one.",
        )
    print("  Polling for approval…", file=sys.stderr)
    status_path = f"/api/session-request/{request_id}/status"
    if poll_secret:
        status_path += f"?secret={urllib.parse.quote(poll_secret, safe='')}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(poll_interval)
        try:
            raw = _unauthenticated_request("GET", status_path, base_url=base_url)
        except KVError:
            continue
        status_data = json.loads(raw)
        status = status_data.get("status", "")
        if status == "approved":
            envelope = status_data.get("envelope")
            if not envelope:
                # Server marked approved but the envelope is gone — most
                # likely a previous poll already consumed the one-time-read
                # envelope (status would normally be "delivered" by now).
                raise KVError(
                    0,
                    "server approved but returned no envelope (already "
                    "delivered / consumed?)",
                )
            try:
                token = _crypto.decrypt_envelope(envelope, device_private_key)
            except (KeyError, ValueError, InvalidTag) as e:
                raise KVError(
                    0, f"failed to decrypt approved session token: {e}"
                ) from e
            if save_to_config:
                _save_session_token(token)
            print("\n  ✅  Session approved.", file=sys.stderr)
            return token
        if status in ("rejected", "expired"):
            raise KVError(0, f"Session request {status}")
        print(".", end="", flush=True, file=sys.stderr)

    raise KVError(0, "Timed out waiting for session request approval")


# ---------------------------------------------------------------------------
# Cross-process session-renewal lock
# ---------------------------------------------------------------------------
#
# Multiple processes (e.g. hermes's main gateway + its dashboard subprocess)
# can independently discover a missing/expired session token at the same
# time. Without coordination, each would create its own session-request and
# send its own approval link/message for what should be a single logical
# refresh event. This lock serializes _renew_session() across processes so
# only one ever drives an approval at a time; the rest block until it's
# done, then adopt the token it obtained instead of requesting their own.

_KV_LOCK_TIMEOUT_SECONDS = 950.0  # slightly over await_session_approval's 900s default
_KV_LOCK_POLL_SECONDS = 0.2


def _kv_lock_path():
    return _config_path().with_suffix(".lock")


@contextlib.contextmanager
def _kv_session_lock(timeout_seconds: float = _KV_LOCK_TIMEOUT_SECONDS):
    """Cross-process advisory lock guarding session renewal.

    Held for the *entire* initiate+poll duration (not just the decision),
    so a sibling process blocks here until the in-flight approval finishes
    rather than racing in and firing a second, redundant request.
    """
    if not _HAS_FCNTL:
        # Best-effort on non-POSIX platforms — no cross-process guarantee,
        # but doesn't break single-process usage.
        yield
        return

    path = _kv_lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = open(path, "a+")
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            try:
                fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"Timed out waiting for KV session lock ({path})"
                    ) from e
                time.sleep(_KV_LOCK_POLL_SECONDS)
        yield
    finally:
        try:
            fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
        finally:
            fd.close()


# ---------------------------------------------------------------------------
# KVClient
# ---------------------------------------------------------------------------

class KVClient:
    """Synchronous KV Manager client.

    Parameters
    ----------
    session_token:
        Bearer token.  Falls back to ``KV_SESSION_TOKEN`` env var or the
        value in ``~/.config/kv/config.toml``.
    base_url:
        KV Manager base URL.  Falls back to config / env.
    on_auth_error:
        Callable that takes no arguments and returns a fresh session token.
        Called automatically whenever a request returns 401, or on the first
        request when no token is available.  The default behaviour (``None``)
        is to run the interactive terminal approval flow (print URL + QR code,
        poll until approved).
    request_label:
        Label shown on the approval page when using the default ``on_auth_error``.
    request_show_qr:
        Whether to render an ASCII QR code when using the default ``on_auth_error``.
    """

    def __init__(
        self,
        session_token: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        on_auth_error: Optional[Callable[[], str]] = None,
        request_label: str | None = None,
        request_show_qr: bool = True,
        device_id: str | None = None,
        device_private_key: str | None = None,
    ):
        cfg = load_config()
        self._base_url = (base_url or cfg.base_url).rstrip("/")
        self._session_token = session_token or cfg.session_token
        self._api_key = api_key or cfg.api_key
        self._on_auth_error = on_auth_error
        self._request_label = request_label
        self._request_show_qr = request_show_qr
        # Device identity used to obtain a session token via the approval flow.
        self._device_id = device_id or cfg.device_id
        self._device_private_key = device_private_key or cfg.device_private_key

        # Raise only if there's no way to recover at all
        if not self._session_token and not self._api_key and on_auth_error is None:
            raise AuthError(
                0,
                "No session token or API key found. Set KV_SESSION_TOKEN / KV_API_KEY "
                "or add session_token / api_key to ~/.config/kv/config.toml",
            )

    # ── Internal ─────────────────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        token = self._session_token or self._api_key
        return {"Authorization": f"Bearer {token}"}

    def _renew_session(self) -> None:
        """Acquire a new session token, blocking until approved.

        Guarded by a cross-process lock (see ``_kv_session_lock``) so that
        when multiple processes discover a missing/expired token at once,
        only one of them actually drives an approval — the rest block here
        and then adopt the token it wrote instead of requesting their own.
        """
        with _kv_session_lock():
            # Another process may have already refreshed the token while we
            # were waiting for the lock — adopt it instead of requesting a
            # second, redundant session.
            cfg = load_config()
            if cfg.session_token and cfg.session_token != self._session_token:
                self._session_token = cfg.session_token
                return

            if self._on_auth_error is not None:
                self._session_token = self._on_auth_error()
            else:
                # Default: interactive terminal flow
                result = initiate_session_request(
                    label=self._request_label,
                    base_url=self._base_url,
                    show_qr=self._request_show_qr,
                    device_id=self._device_id,
                )
                self._session_token = await_session_approval(
                    result["id"],
                    base_url=self._base_url,
                    save_to_config=True,
                    poll_secret=result.get("poll_secret"),
                    device_private_key=self._device_private_key,
                )

    def _do_request(self, method: str, path: str, body: bytes | None = None) -> str:
        url = f"{self._base_url}{path}"
        headers = self._headers()
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.read().decode()
        except urllib.error.HTTPError as e:
            msg = e.read().decode()
            if e.code == 404:
                raise NotFoundError(e.code, msg) from e
            if e.code == 401:
                raise AuthError(e.code, msg) from e
            raise KVError(e.code, msg) from e

    def _request(self, method: str, path: str, body: bytes | None = None) -> str:
        # Ensure we have a token before trying
        if not self._session_token and not self._api_key:
            self._renew_session()

        try:
            return self._do_request(method, path, body)
        except AuthError:
            # Token expired — try api_key fallback, then renew
            if self._api_key and not self._session_token:
                # We were using session_token; retry with api_key
                self._session_token = self._api_key
                try:
                    return self._do_request(method, path, body)
                except AuthError:
                    pass
            # Either api_key also failed or we were already using it
            self._renew_session()
            return self._do_request(method, path, body)

    # ── Public API ────────────────────────────────────────────────────────────

    def get(self, key: str) -> str:
        return self._request("GET", f"/kv/{key}")

    def get_or_default(self, key: str, default: str = "") -> str:
        try:
            return self.get(key)
        except NotFoundError:
            return default

    def initiate_session_request(
        self,
        label: str | None = None,
        show_qr: bool = True,
        device_id: str | None = None,
    ) -> dict:
        """Thin wrapper around the module-level ``initiate_session_request``."""
        return initiate_session_request(
            label=label,
            base_url=self._base_url,
            show_qr=show_qr,
            device_id=device_id or self._device_id,
        )

    def await_session_approval(
        self,
        request_id: str,
        poll_interval: float = 5.0,
        timeout: float = 900.0,
        save_to_config: bool = True,
        poll_secret: str | None = None,
        device_private_key: str | None = None,
    ) -> str:
        """Thin wrapper around the module-level ``await_session_approval``."""
        return await_session_approval(
            request_id,
            base_url=self._base_url,
            poll_interval=poll_interval,
            timeout=timeout,
            save_to_config=save_to_config,
            poll_secret=poll_secret,
            device_private_key=device_private_key or self._device_private_key,
        )

    def request_session(
        self,
        label: str | None = None,
        poll_interval: float = 5.0,
        timeout: float = 900.0,
        show_qr: bool = True,
        save_to_config: bool = True,
    ) -> str:
        """Convenience wrapper: initiate + await in one blocking call."""
        result = self.initiate_session_request(label=label, show_qr=show_qr)
        return self.await_session_approval(
            result["id"],
            poll_interval=poll_interval,
            timeout=timeout,
            save_to_config=save_to_config,
            poll_secret=result.get("poll_secret"),
        )


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

def _save_config_values(**values: str) -> None:
    """Merge ``values`` into the on-disk config TOML, preserving other keys."""
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict = {}
    if path.exists():
        with open(path, "rb") as f:
            data = tomllib.load(f)
    data.update(values)
    path.write_text(tomli_w.dumps(data))


def _save_session_token(token: str) -> None:
    _save_config_values(session_token=token)


# ---------------------------------------------------------------------------
# Device provisioning / enrolment
# ---------------------------------------------------------------------------
#
# Device registration on the server is WebAuthn-gated
# (POST /api/devices/register/begin|finish), which a headless Python client
# cannot perform — there is no passkey / authenticator here. So provisioning
# is split: this client generates the keypair and keeps the PRIVATE key
# locally; a human enrols the corresponding PUBLIC key through a
# WebAuthn-capable surface (the web admin panel) and reads back the assigned
# device_id, which then goes into config. We deliberately do NOT fabricate a
# WebAuthn assertion.

def provision_device(
    key_type: str = "x25519",
    save_to_config: bool = True,
    print_instructions: bool = True,
) -> dict:
    """Generate + store a device keypair and print enrolment instructions.

    Generates an ``x25519`` (default) or ``p256`` device keypair, saves the
    PRIVATE key to ``~/.config/kv/config.toml`` (``device_private_key``), and
    prints the PUBLIC key plus the manual steps to enrol it.

    Returns ``{key_type, public_key, private_key}`` (both keys base64).  The
    ``device_id`` is NOT set here — it is assigned by the server when a human
    enrols the public key via the WebAuthn-capable web admin panel; copy that
    id back into config (``device_id``) or set ``KV_DEVICE_ID``.
    """
    private_key, public_key = _crypto.generate_device_keypair(key_type)
    if save_to_config:
        _save_config_values(device_private_key=private_key)

    if print_instructions:
        print(
            "\n  Device keypair generated"
            + (" and private key saved to config." if save_to_config else ".")
            + f"\n\n  key_type:   {key_type}"
            + f"\n  public key: {public_key}\n"
            "\n  NEXT (manual, one-time): the server enrols devices via "
            "WebAuthn,\n  which this headless client cannot do. Open the web "
            "admin panel on\n  a passkey-capable device, register a new device "
            "with the public key\n  above, then copy the assigned device_id "
            "into ~/.config/kv/config.toml\n  (device_id = \"...\") or set "
            "KV_DEVICE_ID.\n",
            file=sys.stderr,
        )

    return {
        "key_type": key_type,
        "public_key": public_key,
        "private_key": private_key,
    }
