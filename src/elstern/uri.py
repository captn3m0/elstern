"""Parse an ElsterSecure login/enroll URI: elster-secure://sec?p=<base64url(JSON)>."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class Routes:
    base: str
    trans: str
    prov: str
    prov1: str
    token: str

    def url(self, which: str) -> str:
        m = {"trans": self.trans, "prov": self.prov, "prov1": self.prov1, "token": self.token}
        return self.base + m[which]


@dataclass
class UriPayload:
    service_id: str
    config_id: str
    version: str
    bti: str
    routes: Routes


def parse_client_uri(uri: str) -> UriPayload:
    """Parse an elster-secure:// or https://…/elstersecure client URI."""
    q = parse_qs(urlparse(uri).query)
    d = json.loads(_b64url_decode(q["p"][0]))
    r = d["r"]
    return UriPayload(d["s"], d["c"], d.get("v", ""), d["bti"],
                      Routes(r["b"], r["t"], r["p"], r["p0"], r["u"]))
