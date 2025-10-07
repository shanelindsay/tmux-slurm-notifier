# tmux-slurm-notifier

Non-blocking SLURM job monitoring that plays nicely with tmux-driven workflows and LLM agents. Each job gets its own tmux window that polls `squeue` while running, falls back to `sacct` for terminal states, and then sends two keystrokes back to your agent pane:

1. a human-readable status line
2. a machine-readable `MONITOR_DONE {"jobid":...}` line (followed by Enter)

Your agent can simply wait for the JSON line on stdin, parse it, and proceed with the next task (collect results, trigger new work, update dashboards, etc.). Optional [ntfy](https://ntfy.sh) integration mirrors the same messages to push notifications.

> **Why tmux?**
> Agents (or humans) running inside tmux panes cannot block on long `squeue` loops without tying up the session. Instead, we spawn a detached watcher window that does the polling and notifies the originating pane as soon as the job finishes.

## Quick start

```bash
# 1. Submit a job and capture the jobid
jid=$(sbatch job.sbatch | awk '{print $4}')

# 2. Launch the monitor from inside tmux (non-blocking)
./dev/spawn_monitor.sh "$jid"

# 3. Consume the completion line from your agent
# MONITOR_DONE {"jobid":"<id>","state":"<STATE>","exit":"A:B","elapsed":"HH:MM:SS","crumb":"..."}
```

Defaults:

- Auto-closes the monitor window after `MONITOR_DONE`
- Polls every 10 s for the first 3 minutes, then every 60 s (override with `-i`)
- Aborts after 12 h (override with `-t`)
- Posts to ntfy topic `hpc-shane` unless `NTFY_DISABLE=1`; customize via `NTFY_TOPIC` / `NTFY_URL`

Full CLI options, array-job tips, and success criteria live in [`dev/tmux-slurm-monitor.md`](dev/tmux-slurm-monitor.md).

## Files

- `dev/spawn_monitor.sh` – tmux launcher; detects your pane and exports env vars for the watcher
- `dev/monitor_job.sh` – polling daemon (`squeue ➜ sacct`), emits status + `MONITOR_DONE`, handles ntfy
- `dev/tmux-slurm-monitor.md` – user guide you can drop into your own `AGENTS.md`

## Installation

```bash
git clone https://github.com/shanelindsay/tmux-slurm-notifier.git
cd tmux-slurm-notifier
chmod +x dev/*.sh
```

Add the repo (or just the `dev/` directory) to your `$PATH`, or copy the scripts into an existing project.

## Integration tips

- Call `spawn_monitor.sh` immediately after `sbatch` to capture the job ID while it’s hot.
- Parse the JSON payload and treat the job as successful **only** when `state == "COMPLETED"` *and* the major exit code (`A` in `A:B`) equals `0`.
- Use `--keep-window` if you want to inspect the watcher output later; otherwise it tears down automatically.
- For array jobs, monitor individual tasks by passing `123456_7` instead of the root job.

## License

Released under the MIT License – see [LICENSE](LICENSE).
