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
root_private_key="$workdir/root-private.pem"
root_public_key="$workdir/root-public.pem"
dns_record="$workdir/dns-record.txt"
license="$workdir/supporter.license"
socket="$workdir/licensing.sock"

"$issuer" root-keygen \
    --private "$root_private_key" \
    --public "$root_public_key"

keygen_output=$("$issuer" keygen \
    --private "$private_key" \
    --public "$public_key" \
    --root-key "$root_private_key" \
    --txt-output "$dns_record")

grep -q 'Root-signed DNS TXT record' <<<"$keygen_output"
grep -q 'name:  _saslik-license.saslik.io' <<<"$keygen_output"
grep -q 'value: v=saslik1;issuer=saslik.io-authority;not_before=' <<<"$keygen_output"
grep -q ';signature=' "$dns_record"
grep -q 'dig +short TXT _saslik-license.saslik.io' <<<"$keygen_output"

"$issuer" dns-verify \
    --root-key "$root_public_key" \
    --input "$dns_record"

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
    --root-key "$root_public_key" \
    --socket "$socket" &
daemon_pid=$!

for _ in {1..50}; do
    [[ -S $socket ]] && break
    sleep 0.02
done
[[ -S $socket ]]

"$licensectl" --socket "$socket" install-signed-issuer "$dns_record"
"$licensectl" --socket "$socket" install "$license"
[[ $("$licensectl" --socket "$socket" has component.lored) == "OK 1" ]]
[[ $("$licensectl" --socket "$socket" args lored) == $'OK\tworkers=4' ]]

status=$("$licensectl" --socket "$socket" status)
grep -q '^Licensing trust$' <<<"$status"
grep -Eq '^  Root +v1 · [0-9A-F]{4}…[0-9A-F]{4}$' <<<"$status"
grep -Eq '^  Signing +saslik.io-authority/v1 · [0-9A-F]{4}…[0-9A-F]{4}$' <<<"$status"
grep -q '^Valid licenses$' <<<"$status"
grep -Eq '^  test-supporter +lored$' <<<"$status"

sed 's/issuer=saslik.io-authority/issuer=attacker/' "$dns_record" > "$workdir/tampered.txt"
if "$licensectl" --socket "$socket" install-signed-issuer "$workdir/tampered.txt"; then
    echo "tampered DNS record was accepted" >&2
    exit 1
fi
