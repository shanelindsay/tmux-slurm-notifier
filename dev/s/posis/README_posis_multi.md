# POSIS Multi-Repo Watcher

POSIS watches GitHub issues for a trigger phrase and hands the conversation to an external tool (for example `codex exec -`). This multi-repo variant scans a root directory for git repositories, maps each one to its GitHub `owner/repo`, and runs the external command from that repository's working tree. Results are posted straight back to the triggering issue as a formatted comment.

## Features
- Polls the GitHub Issues API; no inbound webhooks or background services required.
- Discovers repositories automatically (optionally recursive) with per-repo state tracking.
- Supports regex triggers in issue comments, and (when enabled) in issue titles/bodies.
- Streams context (issue body, optional parent, full comment history) to the external command via stdin.
- Posts the model's final stdout back to GitHub (trimmed to remove Codex CLI chatter) with truncation and timeout safeguards.
- Adds an 👀 reaction to the triggering comment whenever a run completes successfully.
- tmux launcher script (`tmux-start-multi.sh`) keeps the watcher alive in a named session.
- Remembers the last Codex run per issue so a plain `codexe` comment resumes by default; force a fresh run with `codexe new` or resume a specific id with `codexe resume <id>`.

## Prerequisites
- Python 3.9 or newer (CentOS 7 users: load a modern Python module or conda env).
- `requests` library (install with `pip install -r requirements.txt`).
- GitHub personal access token with Issues read/write permissions (`GITHUB_TOKEN`).

## Quick Start
1. Install dependencies: `pip install -r requirements.txt` (inside the environment that will launch the watcher).
2. Export required environment variables:
   ```bash
   export GITHUB_TOKEN=ghp_yourtoken
   export POSIS_ROOT=/path/to/root-with-many-repos
   ```
3. (Optional) Adjust toggles such as `POSIS_REGEX`, `POSIS_MATCH_TARGET`, or `POSIS_RECURSIVE`.
4. Launch the watcher directly:
   ```bash
   chmod +x dev/s/posis/run-multi.sh dev/s/posis/tmux-start-multi.sh
   dev/s/posis/run-multi.sh
   ```
   or start the bundled tmux session:
   ```bash
   dev/s/posis/tmux-start-multi.sh
   tmux attach -t posis
   ```

## Configuration
All behaviour is controlled through environment variables (defaults in parentheses):
- `GITHUB_TOKEN` (required): GitHub token with Issues scope.
- `POSIS_ROOT` (`$PWD`): Top-level directory that contains the repos to watch.
- `POSIS_RECURSIVE` (`0`): Set to `1` to walk subdirectories recursively.
- `POSIS_REQUIRE_MARKER` (`0`): Set to `1` to only include repos containing `.posis-enabled`.
- `POSIS_EXCLUDE_DIRS` (empty): Comma-separated directory names to skip during discovery.
- `POSIS_REGEX` (`codexe`): Case-insensitive regex used to detect triggers.
- `POSIS_MATCH_TARGET` (`comments`): Set to `issue_or_comments` to also match issue titles/bodies without a comment.
- `POSIS_IGNORE_SELF` (`1`): Leave at `1` to skip comments written by the authenticated GitHub account; set to `0` if you want to trigger on your own comments.
- `POSIS_POLL_SECONDS` (`20`): Poll interval for the GitHub API loop.
- `POSIS_PER_REPO_PAUSE` (`0.3`): Sleep inserted between repos each loop to spread API calls.
- `POSIS_STATE` (`$POSIS_ROOT/.posis_state_multi.json`): JSON file storing per-repo watermarks and history.
- `POSIS_LOCKFILE` (`$POSIS_ROOT/.posis_multi.lock`): Prevents multiple watcher instances in the same root.
- `CODEX_CMD` (`codex`): External command to execute.
- `CODEX_ARGS` (`exec -`): Arguments passed to `CODEX_CMD`.
- `CODEX_RESUME_ARGS` (`resume`): Arguments used when resuming a Codex run; combined with the run id.
- `CODEX_TIMEOUT` (`3600`): Seconds before the external command is terminated.
- `POSIS_DEFAULT_RESUME` (`1`): When `1`, a plain `codexe` resumes the last run if present; set to `0` to always start new unless `resume` appears.
- `POSIS_RESUME_SEND_CONTEXT` (`0`): When `1`, still sends the assembled issue context on resume (stdin); keep `0` if your Codex CLI expects no input when resuming.

## State, Logging, and Shutdown
- State is committed to `.posis_state_multi.json` so restarts resume without duplicate work.
- Logs stream to stdout/stderr (attach to the tmux session to observe them).
- Graceful exit: `Ctrl-C` inside the tmux pane or `tmux kill-session -t posis`.
- A `.posis_multi.lock` file guards against double-starts; remove it only if the process truly exited.

## Testing
- Lightweight smoke tests live under `tests/` and can be executed with `python -m unittest discover -s tests`.
- For an end-to-end validation workflow (including multi-repo discovery and GitHub behaviour), follow `dev/s/POSIS_TEST_PLAN.md`.

## Related Documents
- `dev/s/POSIS_TEST_PLAN.md` – detailed manual/agent test scenarios.
