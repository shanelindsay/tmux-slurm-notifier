# Codex Watcher Toolkit

This directory groups the Codex-oriented automation that previously lived under
`dev/s/posis`. It mirrors the layout we expect to promote into its own
repository in the future.

Key contents:
- `src/codex_watcher/`: Python package with the multi-repository GitHub watcher.
- `bin/`: user-facing entrypoints that bootstrap the watcher package.
- `scripts/`: helper utilities (e.g. tmux launchers) that integrate with tmux / Slurm flows.
- `docs/`: focused documentation for Codex-specific automation.
- `pyproject.toml`: packaging metadata exposing console scripts when installed.

During the transition phase the legacy import path `dev.s.posis.posis_watch_multi`
remains available as a thin compatibility shim, so existing tmux workflows can
continue to function while new tooling adopts `codex_watcher` directly.
