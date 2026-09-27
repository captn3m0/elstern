"""Byte-exact wire builders for AddToken (enroll) and Auth (login).

The framing and JSON key order here are validated against real captured
requests; do not reorder fields or change the separators -- they are on the
wire and the server's signature check depends on them."""
from __future__ import annotations

import base64
import json
import struct
import time

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = bytearray()
    while n:
        out.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(out)]) + bytes(out)


def _der(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(val)) + val


def build_encoded_token(token_type: int, token_id: str, chain: list[bytes]) -> str:
    """u16be(3) || u32be(tokenType) || 0x000000 || 'S' || tokenId ||
    u32be(len(container)) || DER SEQUENCE{ INTEGER 1, [n]{OCTET STRING(cert)} }."""
    header = struct.pack(">H", 3) + struct.pack(">I", token_type) + b"\x00\x00\x00"
    body = _der(0x02, b"\x01")
    for i, cert in enumerate(chain):
        body += _der(0xA0 + i, _der(0x04, cert))
    container = _der(0x30, body)
    raw = header + b"S" + token_id.encode("ascii") + struct.pack(">I", len(container)) + container
    return base64.b64encode(raw).decode()


def _inner_addtoken(data_fields, encoded_token, token_id, token_type) -> str:
    return json.dumps({"dataFields": data_fields,
                       "newToken": {"encodedToken": encoded_token, "tokenId": token_id,
                                    "tokenType": token_type},
                       "signatureToken": {"tokenId": token_id, "tokenType": str(token_type)}},
                      separators=(",", ":"))


def _jose(sign, header, payload) -> str:
    si = (_b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
          _b64url(json.dumps(payload, separators=(",", ":")).encode()))
    sig = sign(si.encode())
    if len(sig) != 64:
        r, s = decode_dss_signature(sig)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return si + "." + _b64url(sig)


def build_addtoken_jwt(sign, *, use_case, data_fields, encoded_token, token_id,
                       token_type, iat=None, ttl_s=120) -> str:
    iat = iat or int(time.time())
    return _jose(sign, {"alg": "ES256"},
                 {"exp": iat + ttl_s, "iat": iat,
                  "payload": _inner_addtoken(data_fields, encoded_token, token_id, token_type),
                  "useCase": use_case})


def build_addtoken_request(bti, signed_jwt, client_name="<NOT SET>") -> dict:
    return {"businessTransactionId": bti, "clientName": client_name, "signedJWT": signed_jwt}


def build_auth_jwt(sign, *, challenge, session_ticket, login_token_validity="86400",
                   init_app="", pkcs10_request="", iat=None, ttl_s=120,
                   query_time_ms=None, use_case="authenticate", token_id=None,
                   token_type=80010003) -> str:
    iat = iat or int(time.time())
    fields = []
    if pkcs10_request:
        fields.append({"name": "pkcs10Request", "type": "_hidden_", "value": pkcs10_request})
    fields += [
        {"name": "initApp", "type": "_hidden_", "value": init_app},
        {"name": "sessionTicket", "type": "_hidden_", "value": session_ticket},
        {"name": "loginTokenGueltigkeit", "type": "_hidden_", "value": login_token_validity},
        {"name": "_challenge_", "type": "_meta_", "value": challenge},
        {"name": "_transactionQueryTime_", "type": "_meta_",
         "value": str(query_time_ms or int(time.time() * 1000))},
    ]
    inner = {"dataFields": fields}
    if token_id:
        inner["signatureToken"] = {"tokenId": token_id, "tokenType": str(token_type)}
    return _jose(sign, {"alg": "ES256"},
                 {"exp": iat + ttl_s, "iat": iat,
                  "payload": json.dumps(inner, separators=(",", ":")), "useCase": use_case})
