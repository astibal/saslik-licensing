#!/usr/bin/env bash
set -euo pipefail

issuer=$1
licensectl=$2
daemon=$3
workdir=$(mktemp -d)
daemon_pid=''

cleanup() {
    if [[ -n $daemon_pid ]]; then
        kill "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
    fi
    rm -rf "$workdir"
}
trap cleanup EXIT

private_key="$workdir/issuer-private.pem"
public_key="$workdir/issuer-public.pem"
license="$workdir/supporter.license"
socket="$workdir/licensing.sock"

keygen_output=$("$issuer" keygen \
    --private "$private_key" \
    --public "$public_key")

grep -q 'name:  _saslik-license.saslik.io' <<<"$keygen_output"
grep -q 'value: v=saslik1;issuer=smithproxy;key=' <<<"$keygen_output"
grep -Eq 'sha256=[0-9a-f]{64}' <<<"$keygen_output"
grep -q 'dig +short TXT _saslik-license.saslik.io' <<<"$keygen_output"

"$issuer" issue \
    --key "$private_key" \
    --output "$license" \
    --id test-supporter \
    --subject "Test supporter" \
    --valid-days 1 \
    --feature component.lored \
    --argument lored:workers=4

[[ $(stat -c '%a' "$private_key") == 600 ]]

"$daemon" \
    --storage "$workdir/licenses" \
    --issuers "$workdir/issuers" \
    --socket "$socket" &
daemon_pid=$!

for _ in {1..50}; do
    [[ -S $socket ]] && break
    sleep 0.02
done
[[ -S $socket ]]

"$licensectl" --socket "$socket" \
    install-issuer smithproxy "$public_key"
"$licensectl" --socket "$socket" install "$license"
[[ $("$licensectl" --socket "$socket" has component.lored) == "OK 1" ]]
[[ $("$licensectl" --socket "$socket" args lored) == $'OK\tworkers=4' ]]
