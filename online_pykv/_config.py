import os
import tomllib
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Config:
    base_url: str
    session_token: str | None
    api_key: str | None


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
    )
