# POSIS Test Plan for Coding Agent

_Scope: single‑repo and multi‑repo watchers; GitHub issue comment triggers; external command execution; result posting._

## A. Pre‑flight


1. **Create/choose two test repos on GitHub** (e.g., `owner/repoA`, `owner/repoB`).
2. **Clone both under an upper‑level folder**, e.g. `~/work/posis-root/repoA` and `~/work/posis-root/repoB`.
3. **Personal access token**: create a token with issues read/write. Export `GITHUB_TOKEN` in the shell that will launch tmux.
4. **Install** Python 3.9+ and run `pip install -r requirements.txt` in the upper‑level folder (or each repo for single‑repo tests).
5. Optional: prepare a minimal external command to prove `cwd`. For example, a shell script `codex` that writes a file to `$(pwd)/POSIS_PROOF.txt` and echoes a markdown `## Result` line.
6. If triggers will be authored by the same account running the watcher, export `POSIS_IGNORE_SELF=0` before launching so self-comments are processed.

## B. Single‑repo watcher tests


1. **Happy path**  
   - In `repoA` working directory, start single‑repo watcher with `POSIS_TRIGGER=codexe`.  
   - Create GitHub issue `#1` with a task description.  
   - Comment `codexe start`.  
   - Expect: watcher posts a result comment; verify `cwd` by checking the artefact file appears in `repoA` only.

2. **Resume mode**  
   - On the same issue, comment `codexe resume`.  
   - External tool should see `MODE: RESUME` in the payload; watcher posts another result comment.

3. **Parent issue inclusion**  
   - Create issue `#2` as parent with context.  
   - Edit issue `#1` body to include `Parent: #2`.  
   - Trigger on `#1`.  
   - Expect: payload includes a `PARENT ISSUE BODY` section.

4. **PRs ignored**  
   - Open a pull request and comment `codexe` on it.  
   - Expect: no action (PRs are skipped).

5. **Long output truncation**  
   - External tool prints >70k characters.  
   - Expect: posted comment includes `[output truncated]` near the end.

6. **Timeout**  
   - Set `CODEX_TIMEOUT=2` and run an external command that sleeps 5 s.  
   - Expect: run ends with a timeout and posts a failure comment with a clear error message.

## C. Multi‑repo watcher tests


1. **Discovery**  
   - Place `repoA` and `repoB` under `POSIS_ROOT`.  
   - Start the multi‑repo watcher.  
   - Expect: startup log lists both repos and their `owner/repo` mapping.

2. **Per-repo `cwd`**  
   - Trigger `codexe` on an issue in `repoA`; verify artefact file appears only in `repoA`.  
   - Trigger `codexe` in `repoB`; verify artefact appears only in `repoB`.
   - Confirm the triggering comment gains an 👀 reaction after a successful run.
   - The posted result comment should contain only the Codex output (no POSIS status header).

3. **Regex matching**  
   - Set `POSIS_TRIGGER_REGEX='codexe\b'`. Comment variants:  
     - `codexe` → should match.  
     - `CODEXE resume` → should match (case‑insensitive).  
     - `codex` → should not match.

4. **Match titles/bodies**  
   - Set `POSIS_MATCH_TARGET=issue_or_comments`.  
   - Create a new issue whose body contains `codexe`.  
   - Expect: watcher triggers even without a comment.

5. **Rate‑limit behaviour**  
   - With many rapid triggers, observe logs for `Retry‑After` handling and that the loop spreads requests with `POSIS_PER_REPO_PAUSE`.

6. **Idempotency**  
   - Add the same trigger comment twice quickly.  
   - Expect: only one processing per unique comment ID.

## D. Negative and edge cases


1. **Missing token**: unset `GITHUB_TOKEN`; watcher should exit with a clear message.
2. **Invalid repo mapping**: break `remote.origin.url` in one local repo; expect that repo is skipped (or not discovered) without crashing the whole loop.
3. **Network errors**: simulate by blocking network temporarily; watcher should log and retry later.
4. **Huge issue history**: issues with many comments should still build payloads and post results; verify chronological ordering.
5. **Lockfile**: attempt to start two watcher instances in the same directory; the second should exit stating the lock is held.

## E. Operational checklist


- Logs are written via stdout/stderr (attach to the tmux session to watch live output).  
- State files: `.posis_state.json` and `.posis_multi_state.json`. Validate they contain processed IDs and timestamps.  
- Environment captured: ensure `which codex` resolves inside tmux before starting the watcher.  
- Clean shutdown: `Ctrl‑C` inside tmux pane or `tmux kill-session -t posis(-multi)`.

## F. Acceptance criteria


- Triggering comments cause exactly one run per comment across restarts.  
- Result comments mirror the Codex stdout (failure details fall back to stderr in a code block).  
- External command runs in the correct repo directory and can create files there.  
- Parent issue text is included when marked.  
- Timeouts and truncation are handled gracefully.  
- PR comments are ignored.  
- Multi‑repo operation spreads requests and does not starve any repo.
