#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: $0 SOURCE_CONF DEST_CONF EXPECTED_ADDRESS EXPECTED_ENDPOINT" >&2
    exit 2
fi

src=$1
dst=$2
expected_address=$3
expected_endpoint=$4
tmp="${dst}.tmp.$$"
trap 'rm -f "$tmp"' EXIT HUP INT TERM

test -f "$src"
actual_address=$(awk -F= 'tolower($1) ~ /^[[:space:]]*address[[:space:]]*$/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$src")
actual_endpoint=$(awk -F= 'tolower($1) ~ /^[[:space:]]*endpoint[[:space:]]*$/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$src")
[ "$actual_address" = "$expected_address" ]
[ "$actual_endpoint" = "$expected_endpoint" ]

umask 077
mkdir -p "$(dirname "$dst")"

awk '
function emit_quick_options() {
    if (!emitted) {
        print "MTU = 1280"
        print "Table = off"
        print "SaveConfig = false"
        emitted = 1
    }
}
function normalized(line, value) {
    value = line
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
    return tolower(value)
}
function option_key(line, value) {
    value = line
    sub(/^[[:space:]]*/, "", value)
    if (value !~ /=/) return ""
    sub(/[[:space:]]*=.*/, "", value)
    gsub(/[[:space:]]/, "", value)
    return tolower(value)
}
normalized($0) == "[interface]" {
    print
    in_interface = 1
    next
}
normalized($0) ~ /^\[/ {
    if (in_interface) emit_quick_options()
    in_interface = 0
    print
    next
}
in_interface && option_key($0) ~ /^(dns|mtu|table|preup|postup|predown|postdown|saveconfig)$/ { next }
{ print }
END { if (in_interface) emit_quick_options() }
' "$src" > "$tmp"

# Validate the temporary file completely before the destination is replaced.
[ "$(grep -Eic '^[[:space:]]*\[Interface\][[:space:]]*$' "$tmp")" -eq 1 ]
[ "$(grep -Eic '^[[:space:]]*PrivateKey[[:space:]]*=[[:space:]]*[^[:space:]]+' "$tmp")" -eq 1 ]
[ "$(grep -Eic '^[[:space:]]*PresharedKey[[:space:]]*=[[:space:]]*[^[:space:]]+' "$tmp")" -ge 1 ]
[ "$(grep -Eic '^[[:space:]]*Table[[:space:]]*=[[:space:]]*off[[:space:]]*$' "$tmp")" -eq 1 ]
[ "$(grep -Eic '^[[:space:]]*SaveConfig[[:space:]]*=[[:space:]]*false[[:space:]]*$' "$tmp")" -eq 1 ]
grep -Eiq '^[[:space:]]*AllowedIPs[[:space:]]*=.*0\.0\.0\.0/0' "$tmp"
! grep -Eiq '^[[:space:]]*(PreUp|PostUp|PreDown|PostDown)[[:space:]]*=' "$tmp"

chmod 0600 "$tmp"
mv -f "$tmp" "$dst"
trap - EXIT HUP INT TERM
