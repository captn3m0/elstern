# Enrolling a login token

Enrolment adds a new login token to an account. It runs over the same
[`/spro4u` protocol](protocol.md) as a login: bootstrap a session, fetch the
transaction, then submit — here with `requestType: "AddToken"`. The link comes
from a logged-in Mein-ELSTER session ("add login option") and its transaction
has `useCase: "addToken"`.

## The token key

A token is an **EC P-256** key pair held by the authenticator. Its public key is
what the server stores and later checks login signatures against. Enrolment is a
proof of possession: the whole `AddToken` JWT is self-signed by this key.

## Identity

Two identifiers, chosen by the client and fixed for the life of the token,
accompany the key:

- **`clientId`** — a UUID, the `senderId` on every `/spro4u` call. In the
  official app it is minted once per install and reused for every token.
- **`tokenId`** — 62 random bytes, base64url-encoded (83 characters), minted per
  token.

The server keys a token by the pair `(clientId, tokenId)`. Both must be
reproduced at login, so a client that wants to log in later must persist them
together with the key.

## The fetched transaction

`GetTransactionDetails` for an enrolment returns fields such as:

```
_header_                       display
benutzername   _text_ readOnly the account name
email          _text_          the account email
nameMobilesGeraet _text_       a device label the user can set
initApp        _hidden_
sessionTicket  _hidden_
accountId      _hidden_
_challenge_    _meta_
_transactionQueryTime_ _meta_
```

The client echoes these back as its user input, filling `nameMobilesGeraet` with
the token's display name.

## `encodedToken`

The public key is delivered inside `encodedToken` — a length-prefixed blob that
wraps an X.509 certificate carrying the token key. Its layout (then base64):

```
u16be(3)                       version
u32be(tokenType)               80010003  → bytes 04 C4 DB 13
0x00 0x00 0x00                 reserved
'S'                            0x53
tokenId                        ASCII, 83 bytes
u32be(len(container))
container                      DER, below
```

The container is a DER sequence holding a leaf-first certificate chain, each
certificate wrapped in an explicit context tag:

```
SEQUENCE {
  INTEGER 1
  [0] { OCTET STRING (leaf certificate, DER) }
  [1] { OCTET STRING (next certificate, DER) }   -- optional
  …
}
```

`tokenType` `80010003` is the "Auto-Token EC" type (an EC login token).

### The certificate

In the official app the leaf certificate is the head of an **Android key
attestation** chain. The server, however, binds the token to the **public key**
in the leaf and verifies login signatures against it; it does not require a
particular issuer or chain. A single **self-signed** certificate carrying the
token's public key is therefore sufficient for enrolment — which is what a
software client such as `elstern` submits.

## The `AddToken` request

The inner plaintext sealed into the `/v3_0/trans` envelope is:

```json
{ "businessTransactionId": "<bti>",
  "clientName": "<NOT SET>",
  "signedJWT": "<ES256 JWT>" }
```

The JWT (ES256, self-signed by the token key) has the usual
`{header, payload}` shape with `useCase: "addToken"`, and its stringified inner
payload ties the key, its identifiers and the user input together:

```json
{ "dataFields": [ … the echoed user input … ],
  "newToken":       { "encodedToken": "<base64>",
                      "tokenId": "<token id>", "tokenType": 80010003 },
  "signatureToken": { "tokenId": "<token id>", "tokenType": "80010003" } }
```

`newToken` describes the token being added; `signatureToken` names the key that
signed the request (the same one — enrolment is self-signed). The signature
covers `base64url(header) + "." + base64url(payload)` as JOSE raw `R‖S`.

## Response

On success the server returns a notification:

```json
{ "resultNotificationByClient": { "dataFields": [
    {"type": "_header_",    "label": "The setup of the ElsterSecure app was successful!"},
    {"type": "_fixedtext_", "label": "From now on, you can always log in securely …"} ] } }
```

The token now appears on the account and can be used to
[log in](protocol.md#4-authenticate-login): the client presents the same
`clientId` and `tokenId` and signs the login challenge with the token key.
