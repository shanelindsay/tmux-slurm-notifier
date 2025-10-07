#!/usr/bin/env bash
# Non-blocking tmux spawner for SLURM job monitor
# Backward compatible:
#   ./dev/spawn_monitor.sh <jobid> [interval_seconds] [timeout_minutes] [--exit-on-timeout|--keep-after-timeout|--use-current-session]
#
# New QoL flags:
#   -i/--interval <sec>   -t/--timeout <min>
#   -C/--use-current-session
#   -S/--session <name>   -r/--reuse   -a/--attach   -d/--dry-run
#   -p/--pane <target-pane> (agent pane; defaults to $TMUX_CALLER_TARGET if in tmux)
#   -T/--topic <ntfy-topic> (optional passthrough)
set -Eeuo pipefail
IFS=$'\n\t'

die(){ echo "Error: $*" >&2; exit 2; }
log(){ echo "[spawn_monitor] $*" >&2; }

DEFAULT_MONITOR_SESSION=${MONITOR_SESSION_NAME:-monitor}
FORCE_MONITOR_SESSION=${MONITOR_FORCE_SESSION:-1}  # 1 = prefer separate session, 0 = prefer current
EXIT_ON_TIMEOUT=1
INTERVAL=60
TIMEOUT=720
KEEP_WINDOW=0
USE_CURRENT=0
EXPLICIT_SESSION=""
ATTACH=0
REUSE=0
DRYRUN=0
CALLER_PANE="${TMUX_CALLER_TARGET:-}"
NTFY_TOPIC_DEFAULT="${NTFY_TOPIC:-hpc-shane}"
NTFY_URL_DEFAULT="${NTFY_URL:-}"

usage(){
  cat <<'USAGE'
Usage:
  dev/spawn_monitor.sh [options] <jobid> [interval_seconds] [timeout_minutes] [--exit-on-timeout|--keep-after-timeout|--use-current-session]

Options:
  -i, --interval SEC          Poll interval (seconds). Default: 60
  -t, --timeout MIN           Monitor timeout (minutes). Default: 720
  -C, --use-current-session   Use current tmux session (vs dedicated session)
  -S, --session NAME          Explicit tmux session name
  -r, --reuse                 Replace existing monitor window for this job if it exists
  -a, --attach                Select the new window after spawning
  -p, --pane TARGET           tmux target pane for agent (e.g. 'agent:0.0'); defaults to $TMUX_CALLER_TARGET
  -T, --topic TOPIC           NTFY topic passthrough (ignored if NTFY_DISABLE=1)
  -k, --keep-window           Leave the monitor window open after completion
  -d, --dry-run               Print tmux command instead of executing
  -h, --help                  Show help

Compat flags (kept):
  --exit-on-timeout | --keep-after-timeout | --use-current-session
USAGE
}

# Parse flags
while (( $# )); do
  case "${1:-}" in
    -i|--interval) INTERVAL="${2:-}"; shift 2;;
    -t|--timeout)  TIMEOUT="${2:-}";  shift 2;;
    -C|--use-current-session) USE_CURRENT=1; FORCE_MONITOR_SESSION=0; shift;;
    -S|--session)  EXPLICIT_SESSION="${2:-}"; shift 2;;
    -r|--reuse)    REUSE=1; shift;;
    -a|--attach)   ATTACH=1; shift;;
    -p|--pane)     CALLER_PANE="${2:-}"; shift 2;;
    -T|--topic)    NTFY_TOPIC_DEFAULT="${2:-}"; shift 2;;
    -k|--keep-window) KEEP_WINDOW=1; shift;;
    -d|--dry-run)  DRYRUN=1; shift;;
    -h|--help)     usage; exit 0;;
    --exit-on-timeout) EXIT_ON_TIMEOUT=1; shift;;
    --keep-after-timeout) EXIT_ON_TIMEOUT=0; shift;;
    --use-current-session) USE_CURRENT=1; FORCE_MONITOR_SESSION=0; shift;;
    --) shift; break;;
    -*) die "Unknown option: $1";;
    *)  break;;
  esac
done

# Positional compatibility
JOBID="${1:-}"; [[ -n "$JOBID" ]] || die "missing jobid"
shift || true

if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
  INTERVAL="$1"
  shift
fi

if [[ "${1:-}" =~ ^[0-9]+$ ]]; then
  TIMEOUT="$1"
  shift
fi

# Trailing compatibility flags (legacy usage)
for extra in "$@"; do
  case "$extra" in
    --exit-on-timeout) EXIT_ON_TIMEOUT=1;;
    --keep-after-timeout) EXIT_ON_TIMEOUT=0;;
    --use-current-session) USE_CURRENT=1; FORCE_MONITOR_SESSION=0;;
    --keep-window) KEEP_WINDOW=1;;
    *)
      die "Unknown option: $extra"
      ;;
  esac
done

[[ "$INTERVAL" =~ ^[0-9]+$ ]] || die "interval must be integer seconds"
[[ "$TIMEOUT"  =~ ^[0-9]+$ ]] || die "timeout must be integer minutes"
if ! command -v tmux >/dev/null 2>&1; then die "tmux not found. Load/enable tmux first."; fi

# Resolve repo root without realpath
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &>/dev/null && pwd -P )"
REPO_ROOT="$( git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || (cd "$SCRIPT_DIR/.." && pwd -P) )"

# Caller tmux context
CURRENT_SESSION=""
if [[ -n "${TMUX:-}" ]]; then
  CURRENT_SESSION="$(tmux display -p '#S')"
  CALLER_PANE="${CALLER_PANE:-$(tmux display -p '#S:#I.#P')}"
elif [[ -n "$CALLER_PANE" ]]; then
  CURRENT_SESSION="${CALLER_PANE%%:*}"
fi

# Ensure/choose session
ensure_session(){
  local s="$1"
  tmux has-session -t "$s" 2>/dev/null || tmux new-session -d -s "$s" -n monitor-shell >/dev/null 2>&1
}
SESSION=""
if [[ -n "$EXPLICIT_SESSION" ]]; then
  ensure_session "$EXPLICIT_SESSION" || die "failed to init session '$EXPLICIT_SESSION'"
  SESSION="$EXPLICIT_SESSION"
elif [[ -n "${TMUX:-}" && $USE_CURRENT -eq 1 ]]; then
  SESSION="$CURRENT_SESSION"
else
  ensure_session "$DEFAULT_MONITOR_SESSION" || die "failed to init session '$DEFAULT_MONITOR_SESSION'"
  SESSION="$DEFAULT_MONITOR_SESSION"
fi

# Safe window name
sanitize(){ sed -E 's/[^A-Za-z0-9._-]+/_/g' <<<"$1"; }
WINDOW_NAME="mon-$(sanitize "$JOBID")"
MONITOR_TARGET="${SESSION}:${WINDOW_NAME}"

window_exists() { tmux list-windows -t "$SESSION" -F '#{window_name}' 2>/dev/null | grep -Fxq "$WINDOW_NAME"; }
(( REUSE )) && window_exists && tmux kill-window -t "$MONITOR_TARGET" || true

# Env exports to child pane
ENV_EXPORTS=()
if [[ "${NTFY_DISABLE:-0}" == "1" ]]; then
  ENV_EXPORTS+=( "NTFY_DISABLE=1" )
else
  ENV_EXPORTS+=( "NTFY_TOPIC=$(printf %q "$NTFY_TOPIC_DEFAULT")" )
  [[ -n "$NTFY_URL_DEFAULT" ]] && ENV_EXPORTS+=( "NTFY_URL=$(printf %q "$NTFY_URL_DEFAULT")" )
fi
[[ -n "$CALLER_PANE" ]] && ENV_EXPORTS+=( "TMUX_TARGET=$(printf %q "$CALLER_PANE")" )
ENV_EXPORTS+=( "TMUX_MONITOR_WINDOW=$(printf %q "$MONITOR_TARGET")" "TMUX_MONITOR_SESSION=$(printf %q "$SESSION")" )

build_env_prefix(){ local out=""; for kv in "${ENV_EXPORTS[@]}"; do out+="${kv} "; done; printf "%s" "$out"; }

CMD="cd $(printf %q "$REPO_ROOT") && $(build_env_prefix) ./dev/monitor_job.sh $(printf %q "$JOBID") $(printf %q "$INTERVAL") $(printf %q "$TIMEOUT")"
if [[ $EXIT_ON_TIMEOUT -eq 1 ]]; then CMD+=" --exit-on-timeout"; else CMD+=" --keep-after-timeout"; fi
if (( KEEP_WINDOW )); then CMD+=" --keep-window"; fi

TMUX_ARGS=( new-window -c "$REPO_ROOT" -t "$SESSION" -n "$WINDOW_NAME" bash -lc "$CMD" )

if (( DRYRUN )); then
  printf 'DRY-RUN -> tmux'
  for arg in "${TMUX_ARGS[@]}"; do printf ' %q' "$arg"; done
  printf '\n'
  exit 0
fi

tmux "${TMUX_ARGS[@]}"
# Keep scrollback unless explicitly killed later
if (( KEEP_WINDOW )); then
  tmux set-option -w -t "$MONITOR_TARGET" remain-on-exit on >/dev/null 2>&1 || true
else
  tmux set-option -w -t "$MONITOR_TARGET" remain-on-exit off >/dev/null 2>&1 || true
fi

log "Spawned ${MONITOR_TARGET} watching job ${JOBID}"
if [[ -n "$CALLER_PANE" ]]; then
  log "Notifications will return to $CALLER_PANE"
else
  log "No TMUX_TARGET provided; notifications will print in monitor window only"
fi

(( ATTACH )) && tmux select-window -t "$MONITOR_TARGET" || true
