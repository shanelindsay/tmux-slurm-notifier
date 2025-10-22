# Codex Multi-Repo Watcher

The Codex watcher scans a local workspace for Git repositories, listens for
trigger phrases on GitHub issues, and hands the full conversation to a Codex
command-line tool. Results are posted back to GitHub so collaborators can follow
progress from the issue thread.

## Highlights
- Polls the GitHub Issues API; no inbound webhooks or background services.
- Discovers repositories automatically (optionally recursively) with per-repo
  state tracking that survives restarts.
- Supports regex triggers in issue comments and optionally in issue bodies and
  titles.
- Streams issue context, parent issue bodies, comments, and metadata to Codex via
  stdin in the repository that triggered the run.
- Adds 👀 reactions to triggering comments when executions complete successfully.
- Remembers the last Codex run per issue so a plain `codexe` resumes by default.

## Quick Start
1. Create or activate a Python 3.9+ environment and install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   or install the package locally:
   ```bash
   pip install -e codex_tooling
   ```
2. Export required environment variables:
   ```bash
   export GITHUB_TOKEN=ghp_yourtoken
   export POSIS_ROOT=/path/to/repos
   ```
3. (Optional) Toggle behaviour with environment variables such as
   `POSIS_REGEX`, `POSIS_MATCH_TARGET`, `POSIS_RECURSIVE`, and
   `POSIS_REQUIRE_MARKER`.
4. Launch the watcher:
   ```bash
   codex_tooling/bin/codex-watch
   ```
   or start the tmux helper:
   ```bash
   codex_tooling/scripts/tmux-start-codex-watch.sh
   tmux attach -t codex-watch
   ```

## Configuration
All behaviour is controlled through environment variables (defaults in
parentheses):

- `GITHUB_TOKEN`: personal access token (required).
- `POSIS_ROOT`: root directory containing Git repos (default: current working
  directory when launching the watcher).
- `POSIS_RECURSIVE`: `1` to scan recursively (default: `0`).
- `POSIS_REGEX`: trigger regex (default: `codexe`).
- `POSIS_MATCH_TARGET`: `comments` or `issue_or_comments` (default: `comments`).
- `POSIS_POLL_SECONDS`: poll interval in seconds (default: 20).
- `POSIS_PER_REPO_PAUSE`: delay between repos per loop (default: 0.3).
- `POSIS_REQUIRE_MARKER`: requires `.posis-enabled` marker file inside repo
  (default: `0`).
- `POSIS_EXCLUDE_DIRS`: comma-separated directories to skip during discovery.
- `POSIS_DEFAULT_RESUME`: resume previous Codex run if no explicit intent.
- `POSIS_RESUME_SEND_CONTEXT`: send full context even for resume invocations.
- `CODEX_CMD`: codex binary (default: `codex`).
- `CODEX_ARGS`: arguments for new runs (default: `exec -`).
- `CODEX_RESUME_ARGS`: arguments for resuming runs (default: `resume`).
- `CODEX_TIMEOUT`: seconds before Codex invocation is terminated (default: 3600).
- `POSIS_STATE`: path to state file (default: `<POSIS_ROOT>/.posis_state_multi.json`).
- `POSIS_LOCKFILE`: path to single-instance lock (default: `<POSIS_ROOT>/.posis_multi.lock`).
- `POSIS_FORWARD_GITHUB_TOKEN`: forward the token into the Codex subprocess when
  set to `1`.

## Development
- Run unit tests: `python -m unittest discover tests`.
- Format code with `black` / `ruff` once we wire tooling into CI.
- Packaging metadata lives in `codex_tooling/pyproject.toml`.
