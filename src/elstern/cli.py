"""elstern -- a free, software-only ElsterSecure (Mein ELSTER) client.

    elstern keygen                          # print a new EC key; store it in `pass`
    ELSTERN_KEY="$(pass show elstern/elster.de)" elstern '<elster-secure://...>'

The URI's transaction decides the action: an "add login option" URI enrolls this
key as a new login token; a login URI signs the login. The key is read only from
$ELSTERN_KEY -- elstern never touches the filesystem."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, keys
from .client import Client


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="elstern", description=__doc__.splitlines()[0])
    ap.add_argument("arg", metavar="keygen|URI", help="'keygen', or an elster-secure:// URI")
    ap.add_argument("--json", action="store_true", help="print the full server response")
    ap.add_argument("--version", action="version", version=f"elstern {__version__}")
    args = ap.parse_args(argv)

    if args.arg == "keygen":
        print(keys.secret_json())
        return 0
    if not (args.arg.startswith("elster-secure://") or "elstersecure" in args.arg):
        ap.error("expected 'keygen' or an elster-secure:// URI")

    out = Client(args.arg).run(keys.load_secret_from_env())
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"{out['action']}: {out['message']}")
    resp = out["response"]
    ok = "error" not in out and not (isinstance(resp, dict) and resp.get("success") is False)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
