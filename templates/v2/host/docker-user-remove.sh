#!/bin/sh
set -eu

CHAIN=AMNEZIA_LB_V2
while :; do
    number=$(iptables -w 5 -S DOCKER-USER | awk -v wanted="$CHAIN" '
        $1 == "-A" { n++ }
        $1 == "-A" && $0 ~ ("-j " wanted "([[:space:]]|$)") {
            print n
            exit
        }
    ')
    [ -n "$number" ] || break
    iptables -w 5 -D DOCKER-USER "$number"
done
iptables -w 5 -F "$CHAIN" 2>/dev/null || true
iptables -w 5 -X "$CHAIN" 2>/dev/null || true
