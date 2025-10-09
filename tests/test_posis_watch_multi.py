import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


if "requests" not in sys.modules:
    class _StubSession:
        def __init__(self):
            self.headers = {}

        def get(self, *args, **kwargs):  # pragma: no cover - tests never rely on real HTTP
            raise NotImplementedError("HTTP interactions are stubbed in unit tests")

        def post(self, *args, **kwargs):  # pragma: no cover
            raise NotImplementedError("HTTP interactions are stubbed in unit tests")

        def delete(self, *args, **kwargs):  # pragma: no cover
            raise NotImplementedError("HTTP interactions are stubbed in unit tests")

    sys.modules["requests"] = types.SimpleNamespace(Session=_StubSession, HTTPError=Exception)


from dev.s.posis import posis_watch_multi as pwm


class ParseRemoteTests(unittest.TestCase):
    def test_parse_github_owner_repo_handles_https_and_ssh(self):
        self.assertEqual(
            pwm.parse_github_owner_repo("https://github.com/foo/bar.git"),
            "foo/bar",
        )
        self.assertEqual(
            pwm.parse_github_owner_repo("git@github.com:Foo/Baz.git"),
            "Foo/Baz",
        )
        self.assertIsNone(pwm.parse_github_owner_repo("https://example.com/org/repo"))


class DiscoverReposTests(unittest.TestCase):
    @mock.patch("dev.s.posis.posis_watch_multi.subprocess.check_output")
    def test_discover_local_repos_respects_marker(self, mock_check_output):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo_a = root / "repoA"
            repo_b = root / "repoB"
            (repo_a / ".git").mkdir(parents=True)
            (repo_b / ".git").mkdir(parents=True)
            (repo_b / ".posis-enabled").touch()

            def fake_check_output(cmd, text=True):
                repo_path = Path(cmd[2])
                if repo_path == repo_a:
                    return "git@github.com:owner/repo-a.git"
                if repo_path == repo_b:
                    return "git@github.com:owner/repo-b.git"
                raise FileNotFoundError

            mock_check_output.side_effect = fake_check_output

            repos = pwm.discover_local_repos(root, recursive=False, require_marker=True, exclude_dirs=[])
            self.assertEqual(repos, {"owner/repo-b": repo_b})

    @mock.patch("dev.s.posis.posis_watch_multi.subprocess.check_output")
    def test_discover_local_repos_recursive_respects_exclude(self, mock_check_output):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "nest" / "repoC"
            ignored = root / "venv"
            (nested / ".git").mkdir(parents=True)
            (ignored / ".git").mkdir(parents=True)

            def fake_check_output(cmd, text=True):
                repo_path = Path(cmd[2])
                if repo_path == nested:
                    return "https://github.com/owner/repo-c.git"
                if repo_path == ignored:
                    return "https://github.com/owner/ignored.git"
                raise FileNotFoundError

            mock_check_output.side_effect = fake_check_output

            repos = pwm.discover_local_repos(root, recursive=True, require_marker=False, exclude_dirs=["venv"])
            self.assertEqual(repos, {"owner/repo-c": nested})


class BuildJobInputTests(unittest.TestCase):
    def test_build_job_input_includes_parent_and_comments(self):
        repo = "owner/repo"
        issue = {"number": 7, "title": "Do work", "body": "Parent: #6"}
        parent = {"number": 6, "title": "Parent", "body": "Parent body"}
        comments = [
            {"created_at": "2025-10-09T00:00:00Z", "user": {"login": "alice"}, "body": "first"},
            {"created_at": "2025-10-09T01:00:00Z", "user": {"login": "bob"}, "body": "second"},
        ]
        trigger_comment = {"id": 123, "user": {"login": "alice"}, "created_at": "2025-10-09T01:00:00Z", "body": "codexe"}
        payload = pwm.build_job_input(repo, issue, comments, parent, trigger_comment, resume=False)

        self.assertIn("=== PARENT ISSUE BODY ===", payload)
        self.assertIn("Parent body", payload)
        self.assertIn("[2025-10-09T01:00:00Z] @bob:", payload)
        self.assertIn("MODE: NEW", payload)


class ResumeDetectionTests(unittest.TestCase):
    def test_extract_resume_flag(self):
        self.assertTrue(pwm.extract_resume_flag("Please resume"))
        self.assertFalse(pwm.extract_resume_flag("start fresh"))


class IntentParsingTests(unittest.TestCase):
    def test_default_intent(self):
        self.assertEqual(pwm.extract_intent("codexe"), ("default", None))

    def test_new_intent(self):
        self.assertEqual(pwm.extract_intent("codexe new run"), ("new", None))

    def test_resume_with_id(self):
        self.assertEqual(pwm.extract_intent("codexe resume abc123"), ("resume", "abc123"))

    def test_resume_without_id_case_insensitive(self):
        self.assertEqual(pwm.extract_intent("CoDeXe RESUME"), ("resume", None))


class RunIdExtractionTests(unittest.TestCase):
    def test_extracts_from_run_id_line(self):
        self.assertEqual(pwm.extract_codex_run_id("Run ID: abcd-1234"), "abcd-1234")

    def test_extracts_from_resume_hint(self):
        text = "Resume with: codex resume 9f8e7d"
        self.assertEqual(pwm.extract_codex_run_id(text), "9f8e7d")

    def test_extracts_from_json_blob(self):
        self.assertEqual(pwm.extract_codex_run_id('{"id": "xyz_42"}'), "xyz_42")


class CommandSelectionTests(unittest.TestCase):
    def setUp(self):
        self.cfg = pwm.Config(token="token", root=Path("."))
        self.cfg.codex_args = ["exec", "-"]
        self.cfg.codex_resume_args = ["resume"]
        self.cfg.default_resume = True
        self.cfg.resume_send_context = False

    def test_stored_id_default_intent_uses_resume(self):
        args, send_payload, resume_flag, resume_id = pwm.decide_codex_invocation(
            self.cfg, "default", None, "stored123"
        )
        self.assertEqual(args, ["resume", "stored123"])
        self.assertFalse(send_payload)
        self.assertTrue(resume_flag)
        self.assertEqual(resume_id, "stored123")

    def test_new_intent_forces_exec(self):
        args, send_payload, resume_flag, resume_id = pwm.decide_codex_invocation(
            self.cfg, "new", None, "stored123"
        )
        self.assertEqual(args, ["exec", "-"])
        self.assertTrue(send_payload)
        self.assertFalse(resume_flag)
        self.assertIsNone(resume_id)

    def test_resume_with_explicit_id(self):
        args, send_payload, resume_flag, resume_id = pwm.decide_codex_invocation(
            self.cfg, "resume", "explicit456", None
        )
        self.assertEqual(args, ["resume", "explicit456"])
        self.assertFalse(send_payload)
        self.assertTrue(resume_flag)
        self.assertEqual(resume_id, "explicit456")

    def test_resume_without_id_and_no_stored_falls_back(self):
        args, send_payload, resume_flag, resume_id = pwm.decide_codex_invocation(
            self.cfg, "resume", None, None
        )
        self.assertEqual(args, ["exec", "-"])
        self.assertTrue(send_payload)
        self.assertFalse(resume_flag)
        self.assertIsNone(resume_id)

    def test_resume_send_context_toggle(self):
        self.cfg.resume_send_context = True
        args, send_payload, resume_flag, resume_id = pwm.decide_codex_invocation(
            self.cfg, "resume", "explicit789", None
        )
        self.assertTrue(send_payload)
        self.assertTrue(resume_flag)
        self.assertEqual(args, ["resume", "explicit789"])


class ConfigTests(unittest.TestCase):
    def test_invalid_match_target_exits(self):
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "token", "POSIS_MATCH_TARGET": "nope"}, clear=True):
            with self.assertRaises(SystemExit):
                pwm.Config.from_env()

    def test_negative_per_repo_pause_clamped(self):
        with mock.patch.dict(
            os.environ,
            {"GITHUB_TOKEN": "token", "POSIS_PER_REPO_PAUSE": "-5"},
            clear=True,
        ):
            cfg = pwm.Config.from_env()
            self.assertEqual(cfg.per_repo_pause, 0.0)

    def test_ignore_self_flag(self):
        with mock.patch.dict(
            os.environ,
            {"GITHUB_TOKEN": "token", "POSIS_IGNORE_SELF": "0"},
            clear=True,
        ):
            cfg = pwm.Config.from_env()
            self.assertFalse(cfg.ignore_self)


class PostprocessStdoutTests(unittest.TestCase):
    def test_codex_output_trimmed_to_final_message(self):
        raw = (
            "thinking\nRun something\n"
            "codex\n## Result\nFirst result\n\n## Decisions\nfoo\n"
            "tokens used\n123\n"
        )
        trimmed = pwm.postprocess_stdout(raw, "codex")
        self.assertIn("## Result", trimmed)
        self.assertNotIn("tokens used", trimmed)
        self.assertNotIn("codex\n", trimmed)

    def test_non_codex_output_returns_original(self):
        raw = "Hello world"
        trimmed = pwm.postprocess_stdout(raw, "other")
        self.assertEqual(trimmed, raw)


class WatermarkComputationTests(unittest.TestCase):
    def test_compute_new_since_uses_latest_timestamp(self):
        previous = "2025-10-01T00:00:00Z"
        comments = [{"created_at": "2025-10-08T12:00:00Z"}]
        issues = [{"updated_at": "2025-10-09T05:00:00Z"}]
        result = pwm._compute_new_since(previous, (comments, issues))
        self.assertEqual(result, "2025-10-09T05:00:00Z")

    def test_compute_new_since_falls_back_when_empty(self):
        previous = "2025-10-01T00:00:00Z"
        result = pwm._compute_new_since(previous, ())
        self.assertEqual(result, previous)

    def test_compute_new_since_uses_comment_when_issues_missing(self):
        previous = "2025-10-01T00:00:00Z"
        comments = [{"created_at": "2025-10-02T00:00:00Z"}]
        result = pwm._compute_new_since(previous, (comments,))
        self.assertEqual(result, "2025-10-02T00:00:00Z")


class SubprocessEnvTests(unittest.TestCase):
    def test_build_subprocess_env_scrubs_github_token(self):
        with mock.patch.dict(
            os.environ,
            {"PATH": "/bin", "GITHUB_TOKEN": "secret", "POSIS_FORWARD_GITHUB_TOKEN": "0"},
            clear=True,
        ):
            env = pwm._build_subprocess_env(Path("/tmp/work"))
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertEqual(env["PATH"], "/bin")
            self.assertEqual(env["PWD"], "/tmp/work")

    def test_build_subprocess_env_can_forward_token(self):
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/bin",
                "GITHUB_TOKEN": "secret",
                "POSIS_FORWARD_GITHUB_TOKEN": "1",
            },
            clear=True,
        ):
            env = pwm._build_subprocess_env(Path("/tmp/work"))
            self.assertEqual(env.get("GITHUB_TOKEN"), "secret")


if __name__ == "__main__":
    unittest.main()
