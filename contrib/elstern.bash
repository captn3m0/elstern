# pass extension: `pass elstern [key/path] <elster-secure://...>`
#
# Stores one elstern secret (key + clientId + tokenId, as JSON) per path under
# elstern/ in your password store, then runs the whole ElsterSecure dance: an
# "add login option" URI enrolls this secret, a login URI logs in. The secret is
# created once on first use and is NEVER overwritten.
#
# Install: copy to ~/.password-store/.extensions/elstern.bash, chmod +x, and set
# PASSWORD_STORE_ENABLE_EXTENSIONS=true. Needs `elstern` on PATH.

cmd_elstern() {
	local path uri entry
	if [[ $# -ge 2 ]]; then
		path="$1"; uri="$2"
	else
		path="elster.de"; uri="${1:-}"
	fi
	if [[ -z "$uri" ]]; then
		echo "usage: pass elstern [key/path] <elster-secure://...>" >&2
		return 1
	fi
	entry="elstern/$path"
	if ! pass show "$entry" >/dev/null 2>&1; then
		elstern keygen | pass insert -m "$entry" >/dev/null
		echo "created new elstern secret: $entry" >&2
	fi
	ELSTERN_KEY="$(pass show "$entry")" elstern "$uri"
}
