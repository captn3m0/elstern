# The login link (QR payload)

## Envelope

The same payload appears under two schemes:

```
elster-secure://sec?p=<base64url(JSON)>            # native scheme (desktop QR)
https://www.elster.de/elstersecure?p=<base64url(JSON)>   # universal link (mobile)
```

`p` is a base64url-encoded JSON object with no padding. An optional
`initApp=Mein%20ELSTER` (or `initApp=''`) is a deep-link hint that foregrounds
the authenticator app; it is not part of the signed protocol.

## Payload

```json
{
  "s":   "171d2898-2e36-11eb-b8f3-8753828dcb43",
  "c":   "app-svc-2025-11-07_2026-04-05",
  "v":   "2.1",
  "bti": "bcGdaRUs4BflaDGRKBcj1BuGCXjbB57nwTup8TrmVm4",
  "r": {
    "b":  "https://www.elster.de/spro4u",
    "t":  "/v3_0/trans",
    "p":  "/v3_0/prov",
    "p0": "/v3_1/prov",
    "u":  "/v3_0/token"
  }
}
```

| Field | Meaning |
|-------|---------|
| `s`   | Service id — a static UUID identifying the ElsterSecure service. |
| `c`   | Service-config id, carrying a validity window. |
| `v`   | Payload version (`2.1`). |
| `bti` | **businessTransactionId** — a fresh 32-byte nonce (base64url), one per attempt. It ties the link to exactly one server-side transaction. |
| `r`   | Route table, relative to the base URL `b`. |

The routes in `r` name the backend endpoints (see
[the protocol](protocol.md)):

| Key  | Path          | Purpose |
|------|---------------|---------|
| `b`  | base URL      | `https://www.elster.de/spro4u` |
| `t`  | `/v3_0/trans` | transaction envelope (fetch, authenticate, addToken) |
| `p`  | `/v3_0/prov`  | provisioning (activation-code enrolment) |
| `p0` | `/v3_1/prov`  | client bootstrap |
| `u`  | `/v3_0/token` | token operations |

`s`, `c` and `r` are constant across attempts; only `bti` changes.

## How the link is minted

The link is generated **server-side**, per attempt, and refreshed on a timer —
the browser never builds it. On the relying-party side:

1. `POST /eportal/login/elstersecure/init` starts an attempt and returns
   `elsterSecureLoginClientUri` (the link, with a fresh `bti`),
   `elsterSecureRequestId` (a poll handle) and a validity window
   (`elsterSecureLoginClientUriDuration`, ~180 s).
2. The page renders the link as a QR code and polls
   `POST /eportal/login/elstersecure/poll` with the request id. While the
   authenticator has not answered, the poll returns an empty (pending) result.
3. When the window elapses the page re-inits and shows a new link with a new
   `bti` — each refresh is a fresh server-minted attempt.
4. Once the authenticator has signed and submitted (see
   [authenticate](protocol.md#4-authenticate-login)), the next poll returns a
   `loginToken`, and `POST /eportal/login/elstersecure` finalises the browser
   session.

## Login vs. enrolment

Logging in and adding a new login token use the **same link format**. What the
authenticator does with it is decided by the transaction behind `bti`, whose
`useCase` is `authenticate` (log in) or `addToken` (enrol). Enrolment links from
a logged-in session typically carry a longer validity window (~30 min).
