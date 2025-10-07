# Use the tmux notifier for SLURM jobs

**Rule:** Use the notifier for **all jobs** unless they are trivially short (seconds). Assume you are running inside **tmux**; the script determines the session/window automatically.

## Quick start

```bash
jid=$(sbatch path/to/job.sbatch | awk '{print $4}')
./dev/spawn_monitor.sh "$jid"
# Parse the single line:
# MONITOR_DONE {"jobid":"<id>","state":"<STATE>","exit":"A:B","elapsed":"HH:MM:SS","crumb":"..."}
```

## Defaults

- **Auto-cleanup:** monitor window closes after `MONITOR_DONE`.
- **Polling:** 10 s for first 3 min, then 60 s thereafter.
- **Upper bound:** 12 h (720 min).

## Options (CLI)

```
./dev/spawn_monitor.sh <jobid> [options]

-i, --interval <sec>     Steady-state poll interval after first 3 min (default: 60)
-t, --timeout  <min>     Upper bound monitor time in minutes (default: 720)
-r, --reuse              Replace an existing monitor window for this job
-a, --attach             Select the monitor window after spawning (human debugging)
--keep-window            Do not auto-close the monitor window on completion
-C, --use-current-session
                         Use current tmux session instead of dedicated one
-S, --session <name>     Use a specific tmux session
-d, --dry-run            Print the tmux command instead of executing it
-p, --pane <target>      (Advanced) Explicit tmux pane target (e.g., agent:0.0)
-T, --topic <topic>      (Advanced) Pass NTFY topic through to monitor
--exit-on-timeout        Nonzero exit when monitor hits its timeout (default)
--keep-after-timeout     Keep monitor running after timeout (not typical)
-h, --help               Show help
```

## Recommended practice

- Set `-t` close to expected runtime with small headroom.
- Adjust `-i` only if you need slower/faster steady polling.

## Array jobs

Monitor a specific task by suffixing `<taskid>`:

```bash
./dev/spawn_monitor.sh "123456_7"
```

## Success criteria

Consider the job **successful** only if:

- `state == "COMPLETED"` **and**
- major code in `exit` (`A` in `A:B`) is `0`.
