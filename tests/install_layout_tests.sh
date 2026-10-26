#!/usr/bin/env bash
set -euo pipefail

cmake=$1
build=$2
source_key=$3
destination=$(mktemp -d)
trap 'rm -rf "$destination"' EXIT

DESTDIR=$destination "$cmake" --install "$build" >/dev/null
installed_key="$destination/etc/saslik/licensing/root.pem"

cmp "$source_key" "$installed_key"
if grep -q 'PRIVATE KEY' "$installed_key"; then
    echo "installed trust anchor contains a private key" >&2
    exit 1
fi
