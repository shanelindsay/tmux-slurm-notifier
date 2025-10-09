#!/usr/bin/env bash
set -euo pipefail

# Example tmux launcher for MULTI-REPO POSIS watcher.
# Required:
#   export GITHUB_TOKEN=ghp_xxx
#   export POSIS_ROOT=/path/to/upper-level/folder
#
# Optional:
#   export POSIS_REGEX="##codecs"        # regex, case-insensitive
#   export POSIS_RECURSIVE=1             # scan recursively
#   export POSIS_REQUIRE_MARKER=1        # only repos with .posis-enabled file
#   export POSIS_EXCLUDE_DIRS="venv,node_modules"
#   export POSIS_POLL_SECONDS=20
#   export CODECS_CMD="codecs"
#   export CODECS_ARGS="exec --stdin"
#
# Usage:
#   chmod +x tmux-start-multi.sh posis_watch_multi.py
#   ./tmux-start-multi.sh

SESSION="posis"
SCRIPT="$(dirname "$0")/posis_watch_multi.py"
LOGFILE="${LOGFILE:-posis_multi.log}"

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "Session '$SESSION' already exists. Attach with: tmux attach -t $SESSION"
  exit 0
fi

cmd="python3 \"$SCRIPT\" 2>&1 | tee -a \"$LOGFILE\""
tmux new-session -d -s "$SESSION" "$cmd"
echo "Started tmux session '$SESSION'. Attach with: tmux attach -t $SESSION"
