import os
import tomllib
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Config:
    base_url: str
    session_token: str | None
    api_key: str | None
    # Device identity for the session-request approval flow. The server now
    # delivers the approved session token ECDH-wrapped to a registered
    # device's public key, so the client needs a device id (assigned by the
    # server when a human enrols the *public* key via a WebAuthn-capable
    # surface) plus the matching *private* key, held only here on the client.
    device_id: str | None = None
    device_private_key: str | None = None  # base64(PKCS#8 DER)


def _config_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home()))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "kv" / "config.toml"


def load_config() -> Config:
    path = _config_path()
    data: dict = {}
    if path.exists():
        with open(path, "rb") as f:
            data = tomllib.load(f)

    return Config(
        base_url=os.environ.get("KV_BASE_URL", data.get("base_url", "https://kv.osmosis.page")).rstrip("/"),
        session_token=os.environ.get("KV_SESSION_TOKEN", data.get("session_token")),
        api_key=os.environ.get("KV_API_KEY", data.get("api_key")),
        device_id=os.environ.get("KV_DEVICE_ID", data.get("device_id")),
        device_private_key=os.environ.get(
            "KV_DEVICE_PRIVATE_KEY", data.get("device_private_key")
        ),
    )
