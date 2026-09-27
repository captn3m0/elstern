"""The elstern secret lives in the environment, never in a file we manage.

A secret is one JSON blob with the three per-token values the app also keeps
(clientId is a UUID minted once per install; tokenId is 62 random bytes per
token):

    {"key": "<EC P-256 PEM>", "clientId": "<UUID>", "tokenId": "<62B base64url>"}

Generate one with `elstern keygen` and keep it in one place, e.g. a single
`pass` entry. It is read only from $ELSTERN_KEY. Copy the blob, copy the login."""
from __future__ import annotations

import base64
import json
import os
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ENV_KEY = "ELSTERN_KEY"


@dataclass
class Secret:
    key: ec.EllipticCurvePrivateKey
    client_id: str
    token_id: str


def key_to_pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def generate_secret() -> dict:
    """A fresh secret; clientId and tokenId are random, exactly as the app does."""
    key = ec.generate_private_key(ec.SECP256R1())
    return {"key": key_to_pem(key),
            "clientId": str(uuid.uuid4()).upper(),
            "tokenId": base64.urlsafe_b64encode(os.urandom(62)).rstrip(b"=").decode()}


def secret_json() -> str:
    return json.dumps(generate_secret(), separators=(",", ":"))


def load_secret_from_env(env: str = ENV_KEY) -> Secret:
    """Parse the JSON secret blob in $ELSTERN_KEY (from `elstern keygen`)."""
    raw = os.environ.get(env, "").strip()
    if not raw:
        raise SystemExit(f"{env} is not set. Run `elstern keygen` and store it in `pass`.")
    try:
        d = json.loads(raw)
        key = serialization.load_pem_private_key(d["key"].encode(), password=None)
        return Secret(key, d["clientId"], d["tokenId"])
    except SystemExit:
        raise
    except Exception as e:
        raise SystemExit(f"{env} is not a valid elstern secret (expected `elstern keygen` JSON): {e}")
