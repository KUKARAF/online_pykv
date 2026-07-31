import contextlib
import errno
import json
import sys
import time
import tomllib
import tomli_w
import urllib.request
import urllib.error
import qrcode
from typing import Callable, Optional
from ._config import Config, load_config, _config_path

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
) -> dict:
    """Create a KV session request (no auth required).

    Returns a dict with ``id``, ``url``, and ``expires_at``.
    Prints the approval URL to stderr; optionally renders an ASCII QR code.

    Pass ``show_qr=False`` when a separate channel (e.g. Zulip) will carry
    the URL, so the terminal output stays clean.
    """
    body = json.dumps({"label": label}).encode()
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
) -> str:
    """Poll for approval of a session request (no auth required).

    Blocks until the request is approved, rejected, or timed out.
    Returns the session token string on success.
    Raises ``KVError`` on rejection, expiry, or timeout.
    """
    print("  Polling for approval…", file=sys.stderr)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(poll_interval)
        try:
            raw = _unauthenticated_request(
                "GET", f"/api/session-request/{request_id}/status", base_url=base_url
            )
        except KVError:
            continue
        status_data = json.loads(raw)
        status = status_data.get("status", "")
        if status == "approved":
            token = status_data.get("session_token")
            if not token:
                raise KVError(0, "server approved but returned no token")
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
    ):
        cfg = load_config()
        self._base_url = (base_url or cfg.base_url).rstrip("/")
        self._session_token = session_token or cfg.session_token
        self._api_key = api_key or cfg.api_key
        self._on_auth_error = on_auth_error
        self._request_label = request_label
        self._request_show_qr = request_show_qr

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
                )
                self._session_token = await_session_approval(
                    result["id"],
                    base_url=self._base_url,
                    save_to_config=True,
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
    ) -> dict:
        """Thin wrapper around the module-level ``initiate_session_request``."""
        return initiate_session_request(label=label, base_url=self._base_url, show_qr=show_qr)

    def await_session_approval(
        self,
        request_id: str,
        poll_interval: float = 5.0,
        timeout: float = 900.0,
        save_to_config: bool = True,
    ) -> str:
        """Thin wrapper around the module-level ``await_session_approval``."""
        return await_session_approval(
            request_id,
            base_url=self._base_url,
            poll_interval=poll_interval,
            timeout=timeout,
            save_to_config=save_to_config,
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
        )


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------

def _save_session_token(token: str) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict = {}
    if path.exists():
        with open(path, "rb") as f:
            data = tomllib.load(f)
    data["session_token"] = token
    path.write_text(tomli_w.dumps(data))
