#!/bin/sh
set -eu
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /bin/sh "$directory/universal/install.sh" "$@"
