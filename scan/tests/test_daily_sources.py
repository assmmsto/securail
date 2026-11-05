"""The daily source check: the decision that decides whether a red build is
raised. Exercised on the three files it reads, with an injected date."""

import datetime
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scan"))

CHECK = None


def setUpModule():
    global CHECK
    path = ROOT / "build" / "check_sources.py"
    spec = importlib.util.spec_from_file_location("_check_sources", str(path))
    CHECK = importlib.util.module_from_spec(spec)
    sys.modules["_check_sources"] = CHECK
    spec.loader.exec_module(CHECK)


TODAY = datetime.date(2026, 11, 6)


def update_doc(**sources):
    """A `--update --json` summary: id -> (status, indicators)."""
    out = []
    for sid, value in sources.items():
        status, count = value
        entry = {"id": sid, "name": sid.upper(), "status": status}
        if count is not None:
            entry["indicators"] = count
        if status == "failed":
            entry["error"] = "connection reset"
        out.append(entry)
    return {"sources": out, "ok": 0, "failed": 0}


def manifest_doc(**sources):
    """A cache manifest: id -> (indicators, sha256)."""
    return {"sources": {sid: {"name": sid.upper(), "indicators": count, "sha256": digest}
                        for sid, (count, digest) in sources.items()}}


def state_doc(since, **sources):
    """The previous run's state: id -> (count, sha256)."""
    return {"checked": since, "sources": {
        sid: {"count": count, "sha256": digest, "unchanged_since": since}
        for sid, (count, digest) in sources.items()}}


class TestHealthy(unittest.TestCase):
    def test_a_normal_day_raises_nothing(self):
        problems, rows, _ = CHECK.check(
            update_doc(alpha=("updated", 100)),
            manifest_doc(alpha=(100, "aaa")),
            state_doc("2026-11-05", alpha=(90, "old")), TODAY)
        self.assertEqual(problems, [])
        self.assertEqual([r["id"] for r in rows], ["alpha"])
        self.assertEqual(rows[0]["count"], 100)
        self.assertEqual(rows[0]["was"], 90)

    def test_a_first_run_has_nothing_to_compare_against(self):
        problems, rows, state = CHECK.check(
            update_doc(alpha=("updated", 50)),
            manifest_doc(alpha=(50, "aaa")), {}, TODAY)
        self.assertEqual(problems, [])
        self.assertEqual(rows[0]["was"], None)
        self.assertEqual(state["sources"]["alpha"]["count"], 50)
        self.assertEqual(state["sources"]["alpha"]["unchanged_since"], "2026-11-06")

    def test_an_unchanged_file_refreshes_nothing_but_the_clock(self):
        problems, rows, state = CHECK.check(
            update_doc(alpha=("unchanged", 50)),
            manifest_doc(alpha=(50, "aaa")),
            state_doc("2026-11-01", alpha=(50, "aaa")), TODAY)
        self.assertEqual(problems, [])
        self.assertEqual(rows[0]["stale_days"], 5)
        # The date the file last changed is carried forward, not reset to today.
        self.assertEqual(state["sources"]["alpha"]["unchanged_since"], "2026-11-01")


class TestFailures(unittest.TestCase):
    def test_a_failed_download_is_a_problem(self):
        problems, _, _ = CHECK.check(
            update_doc(alpha=("failed", None)),
            manifest_doc(alpha=(100, "aaa")),
            state_doc("2026-11-05", alpha=(100, "aaa")), TODAY)
        self.assertEqual(len(problems), 1)
        self.assertIn("failed to download", problems[0]["why"])
        self.assertIn("connection reset", problems[0]["why"])

    def test_a_sharp_shrink_is_a_problem(self):
        problems, _, _ = CHECK.check(
            update_doc(alpha=("updated", 10)),
            manifest_doc(alpha=(10, "new")),
            state_doc("2026-11-05", alpha=(100, "aaa")), TODAY)
        self.assertEqual(len(problems), 1)
        self.assertIn("count fell from 100 to 10", problems[0]["why"])

    def test_a_small_shrink_is_left_alone(self):
        problems, _, _ = CHECK.check(
            update_doc(alpha=("updated", 80)),
            manifest_doc(alpha=(80, "new")),
            state_doc("2026-11-05", alpha=(100, "aaa")), TODAY)
        self.assertEqual(problems, [])

    def test_a_source_that_disappeared_is_a_problem(self):
        problems, _, _ = CHECK.check(
            update_doc(beta=("updated", 10)),
            manifest_doc(beta=(10, "bbb")),
            state_doc("2026-11-05", alpha=(100, "aaa"), beta=(10, "bbb")), TODAY)
        self.assertEqual(len(problems), 1)
        self.assertEqual(problems[0]["id"], "alpha")
        self.assertIn("disappeared", problems[0]["why"])

    def test_a_failed_source_keeps_what_we_knew(self):
        _, _, state = CHECK.check(
            update_doc(alpha=("failed", None)),
            manifest_doc(alpha=(100, "aaa")),
            state_doc("2026-10-01", alpha=(100, "aaa")), TODAY)
        # A download failure must not reset the "unchanged since" clock, or the
        # next good run would look like a change that never happened.
        self.assertEqual(state["sources"]["alpha"]["unchanged_since"], "2026-10-01")
        self.assertEqual(state["sources"]["alpha"]["count"], 100)

    def test_a_stale_file_is_a_problem(self):
        problems, rows, _ = CHECK.check(
            update_doc(alpha=("unchanged", 100)),
            manifest_doc(alpha=(100, "aaa")),
            state_doc("2026-09-01", alpha=(100, "aaa")), TODAY)
        self.assertEqual(len(problems), 1)
        self.assertIn("unchanged for 66 days", problems[0]["why"])
        self.assertEqual(rows[0]["stale_days"], 66)

    def test_stale_is_measured_on_the_published_file_not_the_check(self):
        # The file changed today, even though yesterday's state is months old:
        # the publisher is active, so nothing is stale.
        problems, _, _ = CHECK.check(
            update_doc(alpha=("updated", 100)),
            manifest_doc(alpha=(100, "brand-new")),
            state_doc("2026-06-01", alpha=(100, "aaa")), TODAY)
        self.assertEqual(problems, [])

    def test_every_problem_is_reported_not_just_the_first(self):
        problems, _, _ = CHECK.check(
            update_doc(alpha=("failed", None), beta=("updated", 1)),
            manifest_doc(alpha=(100, "aaa"), beta=(1, "b")),
            state_doc("2026-11-05", alpha=(100, "aaa"), beta=(100, "bb")), TODAY)
        self.assertEqual(sorted(p["id"] for p in problems), ["alpha", "beta"])


class TestCommand(unittest.TestCase):
    def run_cli(self, directory, *extra, update=None, manifest=None, state=None):
        paths = {}
        for name, doc in (("update.json", update), ("manifest.json", manifest),
                          ("state.json", state)):
            path = os.path.join(directory, name)
            paths[name] = path
            if doc is not None:
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(doc, fh)
        argv = ["--update-json", paths["update.json"], "--manifest", paths["manifest.json"],
                "--output", os.path.join(directory, "new-state.json"),
                "--summary", os.path.join(directory, "summary.md"),
                "--today", "2026-11-06"] + list(extra)
        if state is not None:
            argv += ["--state", paths["state.json"]]
        return CHECK.main(argv), os.path.join(directory, "new-state.json"), \
            os.path.join(directory, "summary.md")

    def test_the_command_writes_state_and_summary_and_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, state_path, summary = self.run_cli(
                tmp, update=update_doc(alpha=("updated", 100)),
                manifest=manifest_doc(alpha=(100, "aaa")))
            self.assertEqual(code, 0)
            with open(state_path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["sources"]["alpha"]["count"], 100)
            with open(summary, encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("Every source downloaded", text)
            self.assertIn("| ALPHA | updated | 100 | - | 0d |", text)

    def test_the_command_exits_one_when_a_source_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, summary = self.run_cli(
                tmp, update=update_doc(alpha=("failed", None)),
                manifest=manifest_doc())
            self.assertEqual(code, 1)
            with open(summary, encoding="utf-8") as fh:
                self.assertIn("failed to download", fh.read())

    def test_an_unreadable_update_summary_is_an_error_not_a_green_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = self.run_cli(tmp, update=None, manifest=manifest_doc())
            self.assertEqual(code, 2)


class TestWorkflow(unittest.TestCase):
    """The workflow is the only place this check runs, so a silent edit that
    drops the daily trigger or the comparison would leave the promise in
    docs/VERIFYING.md unkept."""

    def workflow(self):
        return (ROOT / ".github" / "workflows" / "daily-sources.yml").read_text(encoding="utf-8")

    def test_it_runs_every_day(self):
        text = self.workflow()
        self.assertIn('cron: "23 4 * * *"', text)
        self.assertIn("workflow_dispatch:", text)

    def test_it_downloads_every_source_and_compares(self):
        text = self.workflow()
        self.assertIn("--update --latest", text)
        self.assertIn("build/check_sources.py", text)
        self.assertIn('--summary "$REPORT"', text)

    def test_it_can_report_and_reads_nothing_else(self):
        text = self.workflow()
        self.assertIn("issues: write", text)
        self.assertIn("contents: read", text)
        # It must not be able to push: this job only reads public lists.
        self.assertNotIn("contents: write", text)

    def test_a_failed_run_opens_or_updates_one_issue(self):
        text = self.workflow()
        self.assertIn("gh issue comment", text)
        self.assertIn("gh issue create", text)
        self.assertIn("gh issue close", text)

    def test_only_a_healthy_day_becomes_the_baseline(self):
        text = self.workflow()
        # Saving a degraded run would hide the drop that caused it, so the save
        # step carries the success condition itself.
        self.assertRegex(text, r"if: success\(\)\s*\n\s*uses: actions/cache/save")


if __name__ == "__main__":
    unittest.main()