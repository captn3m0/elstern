"""The ElsterSecure transaction client (software-only).

One entry point: ``Client(uri).run(secret)`` opens the encrypted session, reads
the transaction, and either enrolls the key as a new login token (useCase
addToken) or signs the login challenge (authenticate). No hardware and no
attestation is verified server-side, so the token is just a plain self-signed
EC certificate carrying the key's public part."""
from __future__ import annotations

import base64
import datetime
import json
import os
import platform
import struct
import urllib.error
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from . import wire
from .uri import parse_client_uri

CLIENT_VERSION = "1.11.1"
TOKEN_TYPE = 80010003
DEVICE_NAME = os.environ.get("ELSTERN_DEVICE_NAME") or platform.node() or "elstern"


def _client_platform() -> dict:
    """clientPlatform reported at bootstrap. osName/osVersion/deviceName are the
    real system values; platformName is a fixed server enum -- the backend 400s
    on anything but "Android"/"iOS", so it defaults to "Android" and is only
    changed via $ELSTERN_PLATFORM_NAME."""
    try:
        osr = platform.freedesktop_os_release()
    except OSError:
        osr = {}
    return {"deviceName": DEVICE_NAME,
            "osName": osr.get("NAME") or platform.system() or "Linux",
            "osVersion": osr.get("VERSION_ID") or platform.release() or "",
            "platformName": os.environ.get("ELSTERN_PLATFORM_NAME") or "Android"}


def _spki_b64(key) -> str:
    return base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


def _b64(s: str) -> bytes:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s) if ("-" in s or "_" in s) else base64.b64decode(s)


def _self_signed_cert(key) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Android Keystore Key")])
    ku = x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                       data_encipherment=False, key_agreement=False, key_cert_sign=False,
                       crl_sign=False, encipher_only=False, decipher_only=False)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2021, 1, 13, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2031, 1, 11, tzinfo=datetime.timezone.utc))
            .add_extension(ku, critical=True).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


class Client:
    def __init__(self, uri: str):
        self.p = parse_client_uri(uri)

    def run(self, cred) -> dict:
        """Do the whole dance and return {action, useCase, clientId, tokenId,
        response, message}. ``cred`` is a keys.Secret; ``action`` is 'enroll'
        or 'login'."""
        client_id, token_id, key = cred.client_id, cred.token_id, cred.key
        client_key = ec.generate_private_key(ec.SECP384R1())
        boot = self._bootstrap(client_id, client_key)
        secret = self._secret(client_key, boot)
        use_case, fields = self._fetch(secret, client_id)

        def sign(signing_input: bytes) -> bytes:
            return key.sign(signing_input, ec.ECDSA(hashes.SHA256()))

        if use_case == "addToken":
            resp, action = self._enroll(secret, client_id, token_id, key, sign, use_case, fields), "enroll"
        else:
            resp, action = self._login(secret, client_id, token_id, sign, use_case, fields), "login"
        return {"action": action, "useCase": use_case, "clientId": client_id,
                "tokenId": token_id, "response": resp, "message": _message(resp)}

    def _post(self, url, obj):
        body = json.dumps(obj, separators=(",", ":")).encode()
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Accept": "application/json"})
        try:
            return json.loads(urllib.request.urlopen(req, timeout=30).read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace").strip()[:300]
            raise SystemExit(f"{url} returned HTTP {e.code}: {detail}")
        except (urllib.error.URLError, TimeoutError) as e:
            reason = getattr(e, "reason", e)
            raise SystemExit(f"could not reach {url}: {reason}")

    def _bootstrap(self, client_id, client_key):
        return self._post(self.p.routes.url("prov1"), {
            "clientId": client_id,
            "clientPlatform": _client_platform(),
            "clientVersion": CLIENT_VERSION, "publicKey": _spki_b64(client_key)})

    @staticmethod
    def _secret(client_key, boot):
        pl = json.loads(_b64(boot["signedJwt"].split(".")[1]))
        server_b = serialization.load_der_public_key(_b64(pl["B"]))
        return client_key.exchange(ec.ECDH(), server_b)[:32]

    @staticmethod
    def _enc(secret, plaintext):
        iv = os.urandom(12)
        ct = AESGCM(secret).encrypt(iv, plaintext, None)
        return base64.b64encode(struct.pack(">H", len(iv)) + iv + ct).decode()

    @staticmethod
    def _dec(secret, payload_b64):
        raw = _b64(payload_b64)
        n = struct.unpack(">H", raw[:2])[0]
        return AESGCM(secret).decrypt(raw[2:2 + n], raw[2 + n:], None)

    def _trans(self, secret, client_id, request_type, plain):
        resp = self._post(self.p.routes.url("trans"), {
            "payload": self._enc(secret, json.dumps(plain, separators=(",", ":")).encode()),
            "requestType": request_type, "senderId": client_id})
        if not resp.get("success"):
            return resp
        return json.loads(self._dec(secret, resp["payload"]))

    def _fetch(self, secret, client_id):
        out = self._trans(secret, client_id, "GetTransactionDetails",
                          {"businessTransactionId": self.p.bti})
        data = out.get("data", out)
        return data.get("useCase", ""), data.get("dataFields", [])

    def _enroll(self, secret, client_id, token_id, key, sign, use_case, fields):
        data_fields = []
        for f in fields:
            g = dict(f)
            if g.get("name") == "nameMobilesGeraet":
                g["value"] = DEVICE_NAME
            data_fields.append(g)
        encoded = wire.build_encoded_token(TOKEN_TYPE, token_id, [_self_signed_cert(key)])
        jwt = wire.build_addtoken_jwt(sign, use_case=use_case, data_fields=data_fields,
                                      encoded_token=encoded, token_id=token_id, token_type=TOKEN_TYPE)
        return self._trans(secret, client_id, "AddToken",
                           wire.build_addtoken_request(self.p.bti, jwt))

    def _login(self, secret, client_id, token_id, sign, use_case, fields):
        def field(name, default=""):
            for f in fields:
                if f.get("name") == name:
                    return f.get("value", default)
            return default
        jwt = wire.build_auth_jwt(
            sign, challenge=field("_challenge_"), session_ticket=field("sessionTicket"),
            login_token_validity=field("loginTokenGueltigkeit", "86400"),
            init_app=field("initApp", ""), pkcs10_request=field("pkcs10Request"),
            use_case=use_case, token_id=token_id, token_type=TOKEN_TYPE)
        return self._trans(secret, client_id, "Auth",
                           {"businessTransactionId": self.p.bti, "signedJWT": jwt})


def _message(resp: dict) -> str:
    if isinstance(resp, dict):
        rn = resp.get("resultNotificationByClient")
        if isinstance(rn, dict):
            labels = [d.get("label", "") for d in rn.get("dataFields", [])]
            return " ".join(x for x in labels if x)
        if resp.get("error"):
            return resp["error"].get("errorMessage") or json.dumps(resp["error"])
    return json.dumps(resp)[:200]
