#!/usr/bin/env bash
# Deprecated shim: use notifier/monitor_job.sh
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &>/dev/null && pwd -P )"
echo "[DEPRECATED] dev/monitor_job.sh is replaced by notifier/monitor_job.sh" >&2
exec "${SCRIPT_DIR}/../notifier/monitor_job.sh" "$@"
