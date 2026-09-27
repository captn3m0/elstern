# elstern

[![PyPI](https://img.shields.io/pypi/v/elstern)](https://pypi.org/project/elstern/)
[![License](https://img.shields.io/pypi/l/elstern)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/captn3m0/elstern/test.yml?label=CI)](https://github.com/captn3m0/elstern/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/captn3m0/elstern)](https://github.com/captn3m0/elstern/releases/latest)

A free, software-only client for **ElsterSecure** — the passwordless login of
Germany's *Mein ELSTER* tax portal.

> Unofficial. Not affiliated with ELSTER, the *Bundeszentralamt für Steuern*, or
> secunet. *ElsterSecure* and *Mein ELSTER* are their trademarks. Use it with
> your own account, at your own risk.

## How it works

The token is an EC P-256 key. `elstern` manages the token signing for both registration
and subsequent logins and talks to the elster.de backend to confirm both.

See `docs/` for complete documentation of the internals.

## Install

```sh
pipx install elstern      # or: uv tool install elstern
```

## Use

Generate a secret and store it in [`pass`](https://www.passwordstore.org/), or password
manager of your choice.

```sh
elstern keygen | pass insert -m elstern/elster.de
```

`elstern keygen` returns a JSON encoded responses containing a `key`, `clientId`, and `tokenId`.

Then, on the Mein-ELSTER page, choose **add login option** (enroll) or **login**,
and hand `elstern` the `elster-secure://…` URI it shows:

```sh
ELSTERN_KEY="$(pass show elstern/elster.de)" elstern 'elster-secure://sec?p=…'
```

`elstern` does not allow reading secrets from a file to avoid insecure configurations.

## `pass` extension (optional)

Copy `contrib/elstern.bash` to `~/.password-store/.extensions/elstern.bash`,
and set `PASSWORD_STORE_ENABLE_EXTENSIONS=true`. It stores the secrets at
`elstern/elster.de` by default, but you can change the path to store multiple
identities if needed:

```sh
pass elstern 'elster-secure://sec?p=…'            # default key: elstern/elster.de
pass elstern work/elster 'elster-secure://sec?p=…'  # a second, separate token
```

## License

Licensed under the [EUPL‑1.2](LICENSE) license.
