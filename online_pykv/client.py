import urllib.request
import urllib.error
from ._config import Config, load_config


class KVError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(f"HTTP {status}: {message}")


class NotFoundError(KVError):
    pass


class AuthError(KVError):
    pass


class KVClient:
    def __init__(self, session_token: str | None = None, base_url: str | None = None):
        cfg = load_config()
        self._base_url = (base_url or cfg.base_url).rstrip("/")
        self._session_token = session_token or cfg.session_token
        if not self._session_token:
            raise AuthError(0, "No session token found. Set KV_SESSION_TOKEN or add session_token to ~/.config/kv/config.toml")

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._session_token}"}

    def _request(self, method: str, path: str, body: bytes | None = None) -> str:
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

    def get(self, key: str) -> str:
        return self._request("GET", f"/kv/{key}")

    def get_or_default(self, key: str, default: str = "") -> str:
        try:
            return self.get(key)
        except NotFoundError:
            return default
