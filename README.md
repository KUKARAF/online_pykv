# online_pykv

Python client for [kv.osmosis.page](https://kv.osmosis.page) — a lightweight key-value store for secrets and semi-public data.

## Installation

```bash
pip install git+https://github.com/KUKARAF/online_pykv.git
# or
uv add git+https://github.com/KUKARAF/online_pykv.git
```

## Authentication

The client looks for a session token in this order:

1. `KV_SESSION_TOKEN` environment variable
2. `~/.config/kv/config.toml` → `session_token` field (shared with `kv` CLI)

Get a token from the [kv.osmosis.page](https://kv.osmosis.page) admin UI via the **Copy Session Token** button.

## Usage

### Basic key lookup

```python
from online_pykv import KVClient

kv = KVClient()
value = kv.get("my-key")
```

### Loading an API key

A common pattern is to store API keys in kv.osmosis.page and load them at runtime:

```python
from online_pykv import KVClient

kv = KVClient()
openai_api_key = kv.get("openai-api-key")
```

### With a fallback

```python
version = kv.get_or_default("app-version", "0.0.0")
```

### Explicit token (e.g. in CI)

```python
import os
from online_pykv import KVClient

kv = KVClient(session_token=os.environ["KV_SESSION_TOKEN"])
db_password = kv.get("db-password-prod")
```

## Errors

| Exception | When |
|-----------|------|
| `AuthError` | No token found, or token rejected (401) |
| `NotFoundError` | Key does not exist (404) |
| `KVError` | Any other HTTP error |

## Requirements

Python 3.11+ — no external dependencies.
