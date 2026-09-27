# The `/spro4u` transaction protocol

The authenticator talks to the backend named in the login link's routes —
`https://www.elster.de/spro4u`. Every call is `POST` with a JSON body and
`Content-Type: application/json`. There are three steps: **bootstrap** an
encrypted session, **fetch** the transaction, and **sign** it (authenticate a
login, or [enrol a token](registration.md)).

The transport is ordinary HTTPS. The application layer adds its own encryption:
after the bootstrap, the request and response bodies of `/v3_0/trans` are
AES-256-GCM sealed under a session key derived by ECDH.

## 1. Bootstrap — `POST /v3_1/prov`

The client generates an ephemeral EC **P-384** key pair and sends its public
key:

```json
{
  "clientId": "<UUID>",
  "clientPlatform": {"deviceName": "…", "osName": "…",
                     "osVersion": "…", "platformName": "Android"},
  "clientVersion": "1.11.1",
  "publicKey": "<EC P-384 SubjectPublicKeyInfo, base64 DER>"
}
```

`clientId` is a per-client UUID (see [registration](registration.md#identity));
it becomes the `senderId` on every later call. `platformName` is a fixed
platform identifier the server validates — `Android` or `iOS`; other values are
rejected with HTTP 400. `osName`, `osVersion` and `deviceName` are free-form and
merely describe the client.

The response is an ES384-signed JWT plus an error object:

```json
{ "signedJwt": "<ES384 JWT>", "error": {"errorCode": 0} }
```

The JWT payload carries service metadata and an ECIES block:

- `B` — the server's ephemeral EC P-384 public key (SPKI, base64 DER),
- `iv` — a 12-byte nonce,
- `cipherText` — an AES-256-GCM ciphertext holding the client configuration.

### Session key

Both the ECIES block and every subsequent `/trans` body use the same secret:

```
shared  = ECDH(client_private_P384, B)     # 48-byte P-384 shared secret
session = shared[:32]                        # AES-256 key
```

Decrypting the bootstrap config confirms the key:
`AES-256-GCM.decrypt(session, iv, cipherText)` yields an inner ES384 JWT whose
payload is the client config (server hostname, service public key, the token-type
catalogue, etc.).

## 2. The `/v3_0/trans` envelope

Every transaction call has the same outer shape:

```json
{ "payload": "<sealed>", "requestType": "<type>", "senderId": "<clientId>" }
```

`requestType` is `GetTransactionDetails`, `Auth`, or `AddToken`. `payload` is
base64 of:

```
u16be(len(iv)=12) ‖ iv(12) ‖ AES-256-GCM(session, iv, plaintext)
```

where `plaintext` is the request's inner JSON and the GCM output is
`ciphertext ‖ 16-byte tag`. A successful response is
`{"success": true, "payload": "<sealed>"}`, decoded the same way; a failure is
`{"success": false, "error": {"errorCode": N, "errorMessage": "…"}}`.

## 3. Fetch — `GetTransactionDetails`

Inner request:

```json
{ "businessTransactionId": "<bti from the login link>" }
```

The decrypted response describes the pending transaction:

```json
{ "useCase": "authenticate",
  "dataFields": [
    {"name": "initApp",               "type": "_hidden_", "value": "…"},
    {"name": "sessionTicket",          "type": "_hidden_", "value": "…"},
    {"name": "loginTokenGueltigkeit",  "type": "_hidden_", "value": "86400"},
    {"name": "_challenge_",            "type": "_meta_",   "value": "…"},
    {"name": "_transactionQueryTime_", "type": "_meta_",   "value": "…"}
  ] }
```

`useCase` is `authenticate` for a login and `addToken` for an enrolment (whose
fields are described in [registration](registration.md)). Field `type`s seen:
`_header_` (display), `_text_` (user-visible, sometimes read-only), `_hidden_`
(passed through untouched), `_meta_` (protocol values such as the challenge).

## 4. Authenticate (login)

To answer a login the client builds an **ES256** JWT (ECDSA P-256 / SHA-256),
signed by the enrolled token key, and submits it:

```json
{ "businessTransactionId": "<bti>", "signedJWT": "<ES256 JWT>" }
```

with `requestType: "Auth"`. The JWT is:

```
header  = {"alg": "ES256"}
payload = { "exp": <iat+120>, "iat": <now>,
            "payload": "<inner JSON, stringified>",
            "useCase": "authenticate" }
```

and the stringified inner payload echoes the transaction's data fields and names
the signing token:

```json
{ "dataFields": [ initApp, sessionTicket, loginTokenGueltigkeit,
                  _challenge_, _transactionQueryTime_ ],
  "signatureToken": { "tokenId": "<token id>", "tokenType": "80010003" } }
```

`_transactionQueryTime_` is set to the current time in milliseconds; the other
fields are copied from the fetch. The signature covers
`base64url(header) + "." + base64url(payload)` and is encoded as JOSE raw
`R‖S` (64 bytes).

The server looks up the token by `(senderId, signatureToken.tokenId)`, verifies
the signature against the public key recorded at enrolment, and — on success —
returns a notification:

```json
{ "resultNotificationByClient": { "dataFields": [
    {"type": "_fixedtext_", "label": "Login successful"} ] } }
```

The relying party's next poll then yields the `loginToken` that finalises the
browser session.

> A desktop/browser login also includes a `pkcs10Request` field (the browser's
> ephemeral CSR) in the data fields; the token signs it so the browser receives
> a short-lived client certificate. The authenticator-only flow above omits it.
