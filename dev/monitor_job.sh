#!/usr/bin/env bash
# Monitor a SLURM job id (supports array tasks), notify agent via tmux pane.
# Contract: send a human line + a machine line:
#   [monitor] job <id> state=<STATE> exit=<EXIT> elapsed=<ELAPSED>
#   MONITOR_DONE {"jobid":"...","state":"...","exit":"...","elapsed":"...","crumb":"STATE1->STATE2->..."}
#
# IMPORTANT: We send text and press Enter using TWO SEPARATE tmux commands,
# per agent requirements.

set -Eeuo pipefail
IFS=$'\n\t'

# Default ntfy topic unless explicitly disabled.
if [[ -z "${NTFY_TOPIC:-}" && "${NTFY_DISABLE:-0}" != "1" ]]; then
  NTFY_TOPIC="hpc-shane"
fi

notify_ntfy(){
  if [[ "${NTFY_DISABLE:-0}" == "1" ]]; then
    return
  fi
  local topic="${NTFY_TOPIC:-}"
  if [[ -z "$topic" ]]; then
    return
  fi
  local base="${NTFY_URL:-https://ntfy.sh}"
  curl -fsS --max-time 5 \
    -H "Title: Slurm $JOBID" \
    -H "Tags: information_source" \
    -d "$1" "${base%/}/$topic" >/dev/null 2>&1 || true
}

trap 'log "ERR line $LINENO status $? (cmd: $BASH_COMMAND)"' ERR

die(){ echo "Error: $*" >&2; exit 2; }
log(){ echo "[monitor_job] $*" >&2; }

usage(){
  cat <<'USAGE'
Usage:
  dev/monitor_job.sh <jobid> [interval_seconds] [timeout_minutes] [--exit-on-timeout|--keep-after-timeout|--keep-window]
Options:
  --on-success <cmd>   Run after COMPLETED with exit code 0 (optional)
  --on-fail <cmd>      Run after any non-success terminal state (optional)
  --keep-window        Leave the monitor tmux window open after completion
Env:
  TMUX_TARGET=<session:win.pane>        # agent pane to notify (recommended)
  TMUX_MONITOR_WINDOW=<session:win>     # monitor window name (for verbose logs / cleanup)
  TMUX_NOTIFY_VERBOSE=1                 # show internal notify steps in monitor window
USAGE
}

JOBID="${1:-}"; [[ -n "$JOBID" ]] || { usage; die "missing jobid"; }
INTERVAL="${2:-60}"
TIMEOUT_MIN="${3:-720}"

EXIT_ON_TIMEOUT=1
KEEP_WINDOW=0
ON_SUCCESS=""
ON_FAIL=""
shift_count=0

# Pull compatibility flags and hooks
for arg in "${@:4}"; do
  case "$arg" in
    --exit-on-timeout) EXIT_ON_TIMEOUT=1;;
    --keep-after-timeout) EXIT_ON_TIMEOUT=0;;
    --keep-window) KEEP_WINDOW=1;;
    --on-success) shift_count=1;;
    --on-fail)    shift_count=2;;
    *)
      if (( shift_count == 1 )); then ON_SUCCESS="$arg"; shift_count=0; continue; fi
      if (( shift_count == 2 )); then ON_FAIL="$arg"; shift_count=0; continue; fi
      ;;
  esac
 done

[[ "$INTERVAL" =~ ^[0-9]+$ ]] || die "interval must be integer seconds"
[[ "$TIMEOUT_MIN" =~ ^[0-9]+$ ]] || die "timeout must be integer minutes"
TIMEOUT_SEC=$(( TIMEOUT_MIN * 60 ))

JOBROOT="${JOBID%%_*}"   # handles 12345_7 -> 12345 (for scontrol lookups)
HIST=()
QUEUE_REASON=""
SQUEUE_PARTITION=""
SQUEUE_TIMELIMIT=""
SQUEUE_NNODES=""
SQUEUE_NODELIST=""
SQUEUE_REASON=""
SUBMIT_HOST=""
ACCOUNT=""
USER_NAME=""
STDOUT_PATH=""
STDERR_PATH=""
WORK_DIR=""
REQ_MEM=""
MIN_MEM_CPU=""
NUM_CPUS=""
CPUS_TASK=""
GRES_REQ=""
REQ_TRES=""
SUBMIT_TIME=""
PRIORITY=""
NODELIST_ALLOC=""
NUM_NODES=""

# --- Helpers -----------------------------------------------------------------
FAST_PHASE_SEC=${MONITOR_FAST_PHASE_SEC:-180}
FAST_INTERVAL=${MONITOR_FAST_INTERVAL:-10}

rand_jitter(){ awk -v max=0.15 'BEGIN{srand(); print 1.0+((rand()*2-1)*max)}'; }
sleep_with_jitter(){
  local base="$1"
  # jitter ±15% to avoid thundering herd
  local j
  j="$(rand_jitter)"
  local dur
  dur="$(awk -v b="$base" -v j="$j" 'BEGIN{printf "%.3f\n", b*j}')"
  sleep "$dur"
}

secs_to_hms(){
  local total=$1
  if [[ -z "$total" || "$total" == "0" ]]; then
    echo ""
    return
  fi
  if (( total >= 86400 )); then
    local days=$(( total / 86400 ))
    local rem=$(( total % 86400 ))
    printf '%d-%02d:%02d:%02d' "$days" $(( rem / 3600 )) $(( (rem % 3600) / 60 )) $(( rem % 60 ))
  else
    printf '%02d:%02d:%02d' $(( total / 3600 )) $(( (total % 3600) / 60 )) $(( total % 60 ))
  fi
}

to_secs(){
  # Accept D-HH:MM:SS | HH:MM:SS | MM:SS | SS
  local t="$1"
  if [[ -z "$t" ]]; then
    echo 0
    return
  fi
  if [[ "$t" =~ ^([0-9]+)-([0-9]{2}):([0-9]{2}):([0-9]{2})$ ]]; then
    echo $(( ${BASH_REMATCH[1]}*86400 + ${BASH_REMATCH[2]}*3600 + ${BASH_REMATCH[3]}*60 + ${BASH_REMATCH[4]} ))
  elif [[ "$t" =~ ^([0-9]{2}):([0-9]{2}):([0-9]{2})$ ]]; then
    echo $(( ${BASH_REMATCH[1]}*3600 + ${BASH_REMATCH[2]}*60 + ${BASH_REMATCH[3]} ))
  elif [[ "$t" =~ ^([0-9]{1,2}):([0-9]{2})$ ]]; then
    echo $(( ${BASH_REMATCH[1]}*60 + ${BASH_REMATCH[2]} ))
  elif [[ "$t" =~ ^[0-9]+$ ]]; then
    echo "$t"
  else
    echo 0
  fi
}

squeue_line(){
  # Output: JOBIDRAW|STATE|ELAPSED
  # Use the full JOBID (works for arrays); -h removes header
  LC_ALL=C squeue -h -j "$JOBID" -o "%i|%T|%M" 2>/dev/null || true
}

sacct_rows(){
  # Machine-readable output for this JOBID; includes steps
  local rows
  rows="$(LC_ALL=C sacct -n -P -j "$JOBID" --format=JobID,JobIDRaw,State,ExitCode,Elapsed,Timelimit 2>/dev/null || true)"
  if [[ -z "$rows" && "$JOBID" == *_* ]]; then
    rows="$(LC_ALL=C sacct -n -P -j "$JOBROOT" --format=JobID,JobIDRaw,State,ExitCode,Elapsed,Timelimit 2>/dev/null || true)"
  fi
  printf '%s' "$rows"
}

parse_sacct_terminal(){
  # Prefer batch step; else job line
  local rows="$1"
  local line
  line="$(awk -F'|' -v jid="$JOBID" '
    $1==jid".batch" {print; found=1; exit}
    END { if(!found) print "" }
  ' <<<"$rows")"
  if [[ -z "$line" ]]; then
    line="$(awk -F'|' -v jid="$JOBID" '$1==jid {print; exit}' <<<"$rows")"
  fi
  # Fallback when sacct stores array task under different numeric JobID but retains task info in JobID field
  if [[ -z "$line" && "$JOBID" == *_* ]]; then
    line="$(awk -F'|' -v jid_root="$JOBROOT" -v jid="$JOBID" '
      $1==jid_root".batch" && !found {print; found=1}
      $1==jid_root && !found {print; found=1}
    ' <<<"$rows")"
  fi
  if [[ -z "$line" ]]; then
    return 1
  fi

  IFS='|' read -r jobid jobidraw state exit elapsed tlim <<<"$line"
  echo "state=$state exit=$exit elapsed=$elapsed tlim=$tlim"
}

read_timelimit(){
  # Use scontrol (single line with -o), handle absent gracefully
  local out
  out="$(scontrol show job -o "$JOBROOT" 2>/dev/null || true)"
  [[ -z "$out" ]] && { echo ""; return; }
  # Prefer TimeLimitRaw if present, else TimeLimit (D-HH:MM:SS)
  local raw tl
  raw="$(grep -Eo 'TimeLimitRaw=[0-9]+' <<<"$out" | cut -d= -f2 || true)"
  if [[ -n "$raw" ]]; then
    echo "$raw"
  else
    tl="$(grep -Eo 'TimeLimit=[0-9:-]+' <<<"$out" | cut -d= -f2 || true)"
    [[ -n "$tl" ]] && to_secs "$tl" || echo ""
  fi
}

notify_tmux(){
  # Sends $1 to agent pane as *two commands*: (text) then (Enter)
  local line="$1"
  if [[ -n "${TMUX_TARGET:-}" ]] && command -v tmux >/dev/null 2>&1; then
    # Optional visibility in monitor window
    if [[ -n "${TMUX_MONITOR_WINDOW:-}" && "${TMUX_NOTIFY_VERBOSE:-0}" == "1" ]]; then
      tmux display-message -t "$TMUX_MONITOR_WINDOW" -- "[notify] send text to $TMUX_TARGET"
    fi
    tmux send-keys -t "$TMUX_TARGET" -l -- "$line" || true

    if [[ -n "${TMUX_MONITOR_WINDOW:-}" && "${TMUX_NOTIFY_VERBOSE:-0}" == "1" ]]; then
      tmux display-message -t "$TMUX_MONITOR_WINDOW" -- "[notify] press Enter on $TMUX_TARGET"
    fi
    tmux send-keys -t "$TMUX_TARGET" Enter || true
  fi
  # Always echo to our own stdout as well
  echo "$line"
}

record_breadcrumb(){
  local s="$1"
  local last=""
  local count=${#HIST[@]}
  if (( count > 0 )); then
    last="${HIST[$((count-1))]}"
  fi
  if [[ "$s" != "$last" ]]; then HIST+=("$s"); fi
}

format_breadcrumb(){
  local sep=""
  local out=""
  local state
  for state in "${HIST[@]}"; do
    out+="${sep}${state}"
    sep="->"
  done
  printf '%s' "$out"
}

sanitize_value(){
  local val="$1"
  local quote='"'
  val=${val//$quote/}
  val=${val//[()]/}
  val=${val// /_}
  echo "$val"
}

append_kv(){
  local key="$1"
  local raw="$2"
  if [[ -z "$raw" ]]; then
    return
  fi
  case "$raw" in
    "(null)"|"None"|"UNKNOWN"|"Unknown") return ;;
  esac
  local value
  value=$(sanitize_value "$raw")
  if [[ -z "$value" ]]; then
    return
  fi
  EXTRA_FIELDS+=("$key=$value")
}

extract_field(){
  local info="$1" key="$2" match
  match=$(grep -o "${key}=[^ ]*" <<<"$info" | tail -n1 || true)
  if [[ -n "$match" ]]; then
    echo "${match#*=}"
  fi
  return 0
}

collect_metadata(){
  local info
  info=$(scontrol show job -o "$JOBID" 2>/dev/null || true)
  if [[ -z "$info" && "$JOBID" == *_* ]]; then
    info=$(scontrol show job -o "$JOBROOT" 2>/dev/null || true)
  fi
  [[ -z "$info" ]] && return

  local field

  field=$(extract_field "$info" "SubmitHost")
  if [[ -n "$field" ]]; then
    SUBMIT_HOST="$field"
  fi

  field=$(extract_field "$info" "AllocNode")
  if [[ -n "$field" && -z "$SUBMIT_HOST" ]]; then
    SUBMIT_HOST="${field%%:*}"
  fi

  field=$(extract_field "$info" "Account")
  if [[ -n "$field" ]]; then
    ACCOUNT="$field"
  fi

  field=$(extract_field "$info" "UserId")
  if [[ -n "$field" ]]; then
    USER_NAME="${field%%(*}"
  fi

  field=$(extract_field "$info" "StdOut")
  if [[ -n "$field" ]]; then
    STDOUT_PATH="$field"
  fi

  field=$(extract_field "$info" "StdErr")
  if [[ -n "$field" ]]; then
    STDERR_PATH="$field"
  fi

  field=$(extract_field "$info" "WorkDir")
  if [[ -n "$field" ]]; then
    WORK_DIR="$field"
  fi

  field=$(extract_field "$info" "ReqMem")
  if [[ -n "$field" ]]; then
    REQ_MEM="$field"
  fi

  field=$(extract_field "$info" "MinMemoryCPU")
  if [[ -n "$field" ]]; then
    MIN_MEM_CPU="$field"
  fi

  field=$(extract_field "$info" "NumCPUs")
  if [[ -n "$field" ]]; then
    NUM_CPUS="$field"
  fi

  field=$(extract_field "$info" "CPUs/Task")
  if [[ -n "$field" ]]; then
    CPUS_TASK="$field"
  fi

  field=$(extract_field "$info" "ReqGRES")
  if [[ -n "$field" ]]; then
    GRES_REQ="$field"
  fi

  field=$(extract_field "$info" "ReqTRES")
  if [[ -n "$field" ]]; then
    REQ_TRES="$field"
  fi

  field=$(extract_field "$info" "SubmitTime")
  if [[ -n "$field" ]]; then
    SUBMIT_TIME="$field"
  fi

  field=$(extract_field "$info" "Priority")
  if [[ -n "$field" ]]; then
    PRIORITY="$field"
  fi

  field=$(extract_field "$info" "NodeList")
  if [[ -n "$field" ]]; then
    NODELIST_ALLOC="$field"
  fi

  field=$(extract_field "$info" "NumNodes")
  if [[ -n "$field" ]]; then
    NUM_NODES="$field"
  fi

  field=$(extract_field "$info" "Partition")
  if [[ -n "$field" && -z "$SQUEUE_PARTITION" ]]; then
    SQUEUE_PARTITION="$field"
  fi

  field=$(extract_field "$info" "TimeLimit")
  if [[ -n "$field" && -z "$SQUEUE_TIMELIMIT" ]]; then
    SQUEUE_TIMELIMIT="$field"
  fi

  field=$(extract_field "$info" "Reason")
  if [[ -n "$field" && -z "$QUEUE_REASON" && "$field" != "None" ]]; then
    QUEUE_REASON="$field"
  fi
}

build_brief(){
  local partition_display="${SQUEUE_PARTITION:-unknown}"
  local node_display="${SQUEUE_NODELIST:-$NODELIST_ALLOC}"
  if [[ -z "$node_display" || "$node_display" == "(null)" ]]; then
    node_display="n/a"
  fi
  local reason_display="${QUEUE_REASON:-$SQUEUE_REASON}"
  reason_display=${reason_display//[()]/}
  if [[ -z "$reason_display" || "$reason_display" == "None" ]]; then
    reason_display="None"
  fi
  printf '[monitor] job %s state=%s exit=%s elapsed=%s partition=%s nodes=%s reason=%s' \
    "$JOBID" "$STATE" "$EXIT" "$ELAPSED" "$partition_display" "$node_display" "$reason_display"
}

build_done_line(){
  EXTRA_FIELDS=()

  local queue_reason="${QUEUE_REASON:-$SQUEUE_REASON}"
  append_kv "queue_reason" "$queue_reason"

  local partition_value="$SQUEUE_PARTITION"
  append_kv "partition" "$partition_value"

  local node_list_value="${SQUEUE_NODELIST:-$NODELIST_ALLOC}"
  append_kv "nodelist" "$node_list_value"

  local node_count_value="${SQUEUE_NNODES:-$NUM_NODES}"
  append_kv "nodes" "$node_count_value"

  local timelimit_display="$SQUEUE_TIMELIMIT"
  if [[ -z "$timelimit_display" || "$timelimit_display" == "None" || "$timelimit_display" == "Unknown" ]]; then
    if [[ "$TLIM_RUN_SECS" =~ ^[0-9]+$ ]] && (( TLIM_RUN_SECS > 0 )); then
      timelimit_display="$(secs_to_hms "$TLIM_RUN_SECS")"
    fi
  fi
  append_kv "timelimit" "$timelimit_display"

  append_kv "submit_host" "$SUBMIT_HOST"
  append_kv "account" "$ACCOUNT"
  append_kv "user" "$USER_NAME"
  append_kv "stdout" "$STDOUT_PATH"
  append_kv "stderr" "$STDERR_PATH"
  append_kv "workdir" "$WORK_DIR"
  append_kv "req_mem" "$REQ_MEM"
  append_kv "min_mem_cpu" "$MIN_MEM_CPU"
  append_kv "cpus" "$NUM_CPUS"
  append_kv "cpus_per_task" "$CPUS_TASK"
  append_kv "gres" "$GRES_REQ"
  append_kv "req_tres" "$REQ_TRES"
  append_kv "submit_time" "$SUBMIT_TIME"
  append_kv "priority" "$PRIORITY"

  local done="MONITOR_DONE job=${JOBID} state=${STATE} exit=${EXIT} elapsed=${ELAPSED} crumb=${BREADCRUMB}"
  if (( ${#EXTRA_FIELDS[@]} )); then
    local IFS=' '
    done+=" ${EXTRA_FIELDS[*]}"
  fi
  printf '%s' "$done"
}
cleanup_window(){
  if (( KEEP_WINDOW )); then return; fi
  if [[ -n "${TMUX_MONITOR_WINDOW:-}" ]] && command -v tmux >/dev/null 2>&1; then
    ( sleep 0.1; tmux kill-window -t "$TMUX_MONITOR_WINDOW" >/dev/null 2>&1 || true ) &
  fi
}

# --- Main loop ---------------------------------------------------------------
START_TS=$(date +%s)
TLIM_RUN_SECS="$(read_timelimit || true)"
if [[ -n "$TLIM_RUN_SECS" ]]; then
  log "SLURM TimeLimit (run): ${TLIM_RUN_SECS}s"
fi

STATE=""
ELAPSED="00:00:00"
EXIT="0:0"
BREADCRUMB=""
SETTLE_TRIES=0

while :; do
  NOW=$(date +%s)
  # Hard monitor timeout
  if (( NOW - START_TS > TIMEOUT_SEC )); then
    STATE="MONITOR_TIMEOUT"
    ELAPSED="$ELAPSED"
    EXIT="0:0"
    record_breadcrumb "$STATE"
    collect_metadata
    BREADCRUMB="$(format_breadcrumb)"
    brief="$(build_brief)"
    notify_tmux "$brief"
    notify_ntfy "$brief"
    done_line="$(build_done_line)"
    notify_tmux "$done_line"
    notify_ntfy "$done_line"
    # Exit behavior
    cleanup_window
    if (( EXIT_ON_TIMEOUT )); then exit 124; else exit 0; fi
  fi

  # 1) While in queue or running -> squeue
  line="$(squeue_line)"
  if [[ -n "$line" ]]; then
    IFS='|' read -r jobidraw state elapsed reason partition tlimit nnodes nodelist <<<"$line"
    STATE="$state"; ELAPSED="$elapsed"
    SQUEUE_REASON="$reason"
    SQUEUE_PARTITION="$partition"
    SQUEUE_TIMELIMIT="$tlimit"
    SQUEUE_NNODES="$nnodes"
    SQUEUE_NODELIST="$nodelist"
    if [[ "$STATE" == "PENDING" && -n "$reason" && "$reason" != "None" && -z "$QUEUE_REASON" ]]; then
      QUEUE_REASON="$reason"
    fi
    record_breadcrumb "$STATE"

    # Optional early warning if approaching walltime while RUNNING
    if [[ "$STATE" == "RUNNING" && -n "$TLIM_RUN_SECS" ]]; then
      el_secs="$(to_secs "$ELAPSED")"
      if (( el_secs >= TLIM_RUN_SECS - 60 )); then
        notify_tmux "[monitor] job ${JOBID} nearing walltime (elapsed=${ELAPSED}, limit=${TLIM_RUN_SECS}s)"
      fi
    fi

    poll_base="$INTERVAL"
    if (( NOW - START_TS < FAST_PHASE_SEC )); then
      poll_base="$FAST_INTERVAL"
    fi
    sleep_with_jitter "$poll_base"
    continue
  fi

  # 2) Not in squeue -> give accounting a brief chance to settle
  if (( SETTLE_TRIES < 3 )); then
    ((SETTLE_TRIES+=1))
    sleep 2
    continue
  fi

  # 3) Fall back to sacct for terminal info
  rows="$(sacct_rows)"
  term="$(parse_sacct_terminal "$rows" || true)"
  if [[ -n "$term" ]]; then
    # state=X exit=A:B elapsed=HH:MM:SS tlim=...
    eval "$term" 2>/dev/null || true
    STATE="${state:-UNKNOWN}"
    EXIT="${exit:-0:0}"
    ELAPSED="${elapsed:-00:00:00}"
    record_breadcrumb "$STATE"
    break
  else
    # Could be very quick job / accounting delay; retry soon
    sleep 2
  fi
done

collect_metadata
BREADCRUMB="$(format_breadcrumb)"
brief="$(build_brief)"
notify_tmux "$brief"
notify_ntfy "$brief"
done_line="$(build_done_line)"
notify_tmux "$done_line"
notify_ntfy "$done_line"

# Optional hooks
exit_code_main="${EXIT%%:*}"
if [[ "$STATE" == "COMPLETED" && "$exit_code_main" == "0" ]]; then
  if [[ -n "$ON_SUCCESS" ]]; then bash -lc "$ON_SUCCESS" || true; fi
  cleanup_window
  exit 0
else
  if [[ -n "$ON_FAIL" ]]; then bash -lc "$ON_FAIL" || true; fi
  # Non-zero exit to make it obvious if someone ever checks the pane's status
  # (the agent should rely on the MONITOR_DONE line, not this exit code).
  [[ "$exit_code_main" =~ ^[0-9]+$ ]] || exit_code_main=1
  cleanup_window
  exit "$exit_code_main"
fi
