#!/bin/sh
set -eu
directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
command -v python3 >/dev/null 2>&1 || {
    echo 'Python 3.10+ is required. Install: sudo apt-get install python3' >&2
    exit 2
}
exec python3 "$directory/routerctl.py" install "$@"
