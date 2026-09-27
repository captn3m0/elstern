import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from elstern import keys, wire
from elstern.uri import parse_client_uri


def _uri() -> str:
    d = {"s": "s", "c": "c", "v": "2.1", "bti": "bti",
         "r": {"b": "https://example/spro4u", "t": "/t", "p": "/p", "p0": "/p0", "u": "/u"}}
    p = base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return "elster-secure://sec?p=" + p


def test_generated_secret_shape():
    s = keys.generate_secret()
    assert set(s) == {"key", "clientId", "tokenId"}
    assert s["clientId"] == s["clientId"].upper() and len(s["clientId"]) == 36
    assert len(s["tokenId"]) == 83


def test_secret_json_roundtrip(monkeypatch):
    blob = keys.secret_json()
    monkeypatch.setenv("ELSTERN_KEY", blob)
    sec = keys.load_secret_from_env()
    d = json.loads(blob)
    assert sec.client_id == d["clientId"] and sec.token_id == d["tokenId"]


def test_non_json_secret_is_rejected(monkeypatch):
    import pytest
    monkeypatch.setenv("ELSTERN_KEY", keys.key_to_pem(ec.generate_private_key(ec.SECP256R1())))
    with pytest.raises(SystemExit):
        keys.load_secret_from_env()


def test_encoded_token_framing():
    tid = "T" * 83
    enc = base64.b64decode(wire.build_encoded_token(80010003, tid, [b"\xaa\xbb"]))
    assert enc[:2] == b"\x00\x03" and enc[2:6] == (80010003).to_bytes(4, "big")
    assert enc[9:10] == b"S" and enc[10:10 + 83].decode() == tid


def test_auth_jwt_verifies_and_carries_token():
    key = ec.generate_private_key(ec.SECP256R1())
    jwt = wire.build_auth_jwt(lambda si: key.sign(si, ec.ECDSA(hashes.SHA256())),
                              challenge="c", session_ticket="s", token_id="TID")
    h, p, s = jwt.split(".")
    inner = json.loads(json.loads(base64.urlsafe_b64decode(p + "=="))["payload"])
    assert inner["signatureToken"]["tokenId"] == "TID"
    raw = base64.urlsafe_b64decode(s + "==")
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    key.public_key().verify(der, (h + "." + p).encode(), ec.ECDSA(hashes.SHA256()))


def test_uri_parse():
    p = parse_client_uri(_uri())
    assert p.bti == "bti" and p.routes.url("prov1") == "https://example/spro4u/p0"


def test_client_platform_name(monkeypatch):
    from elstern.client import _client_platform
    monkeypatch.delenv("ELSTERN_PLATFORM_NAME", raising=False)
    p = _client_platform()
    assert p["platformName"] == "Android"  # server 400s on anything else
    assert set(p) == {"deviceName", "osName", "osVersion", "platformName"}
    monkeypatch.setenv("ELSTERN_PLATFORM_NAME", "iOS")
    assert _client_platform()["platformName"] == "iOS"
