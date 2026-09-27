# How ElsterSecure login works

ElsterSecure is the passwordless login of Germany's *Mein ELSTER* tax portal.
A browser (or any relying party) shows a short-lived **login link**, encoded as
a QR code or `elster-secure://` URI.

The apps (iOS/Android only) can sign the pending transaction with an enrolled
key, and submits it.

Two things happen over their own channels:

- The **browser leg** (relying party ⇄ `elster.de/eportal`) mints the login
  link, polls for completion, and finalises the session.
- The **authenticator leg** (device ⇄ `elster.de/spro4u`) opens an encrypted
  session, reads the transaction, and signs it.

```
browser                    elster.de                    authenticator
   │  POST .../init            │                               │
   │─────────────────────────▶│  mint bti, return login link   │
   │  render QR (login link)   │                               │
   │                           │   ◀── read link, open session ─│
   │                           │   ◀── GetTransactionDetails ───│
   │                           │   ◀── signed Auth ─────────────│
   │  POST .../poll  ─────────▶│  loginToken                    │
   │  POST .../elstersecure ──▶│  session authenticated         │
```

The same login-link format and the same `/spro4u` protocol cover both
**logging in** and **enrolling a new token**; the transaction behind the link
decides which (its `useCase` is `authenticate` or `addToken`).

## Documents

- [The login link (QR payload)](login-link.md) — the `elster-secure://` URI.
- [The `/spro4u` transaction protocol](protocol.md) — session, encryption
  envelope, transaction fetch, and the login signature.
- [Enrolling a login token](registration.md) — the `addToken` flow.

These describe the wire protocol only. Endpoint paths, versions and field names
are taken from the login link itself and the backend responses.