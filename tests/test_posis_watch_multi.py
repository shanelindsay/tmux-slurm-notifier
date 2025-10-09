import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


if __name__ == "__main__":
    unittest.main()
