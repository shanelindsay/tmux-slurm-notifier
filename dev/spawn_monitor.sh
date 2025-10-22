#!/usr/bin/env bash
# Deprecated shim: use notifier/spawn_monitor.sh
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &>/dev/null && pwd -P )"
echo "[DEPRECATED] dev/spawn_monitor.sh is replaced by notifier/spawn_monitor.sh" >&2
exec "${SCRIPT_DIR}/../notifier/spawn_monitor.sh" "$@"
