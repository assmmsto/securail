"""A small crafted Favicons database with repeated ids must not multiply into
millions of rows held in memory; icons are streamed and capped. And the
release-verify workflow checks the downloadable file against the manifest AND a
rebuild from the tag, and claims no signature it does not have."""
import contextlib
import os
import sqlite3
import time
from pathlib import Path

from securail.modules import browser
from test_expanded_capabilities import context, BAD
from test_followup_fixes import bundle  # noqa: F401  (fixture)
from test_desktop_toolkit import _dt_iocs


def _favicons(folder, repeats):
    with contextlib.closing(sqlite3.connect(folder / "History")) as db:
        db.execute("CREATE TABLE urls(url TEXT,title TEXT,last_visit_time INTEGER)")
        db.commit()
    with contextlib.closing(sqlite3.connect(folder / "Favicons")) as db:
        db.executescript("CREATE TABLE favicons(id INTEGER,url TEXT);"
                         "CREATE TABLE favicon_bitmaps(icon_id INTEGER,image_data BLOB)")
        db.executemany("INSERT INTO favicons VALUES(1,?)", [("https://" + BAD + "/",)] * repeats)
        db.executemany("INSERT INTO favicon_bitmaps VALUES(1,?)", [(b"x",)] * repeats)
        db.commit()


def test_repeated_icon_ids_do_not_multiply(tmp_path, bundle):
    _favicons(tmp_path, 3000)  # a join would make 9,000,000 rows
    for reader in (browser.run, bundle.run_browser):
        ctx = context(targets=(str(tmp_path),))
        ctx.iocs = _dt_iocs()
        start = time.monotonic()
        r = reader(ctx)
        assert time.monotonic() - start < 60
        assert {(h.indicator, h.evidence) for h in r.hits} == {(BAD, "contacted")}
        assert not [c for c in r.checks if not c.ran and "favicons" in c.name]


def test_icon_row_cap_is_a_gap(tmp_path, monkeypatch):
    _favicons(tmp_path, 5)
    monkeypatch.setattr(browser, "_FAVICON_ROW_LIMIT", 3)
    ctx = context(targets=(str(tmp_path),))
    ctx.iocs = _dt_iocs()
    r = browser.run(ctx)
    gaps = [c.reason for c in r.checks if not c.ran and "favicons" in c.name]
    assert gaps and "more than 3 icons" in gaps[0]


def test_verify_workflow_checks_the_download_and_the_rebuild():
    root = Path(__file__).resolve().parents[2]
    run = (root / ".github" / "workflows" / "verify-release.yml").read_text(encoding="utf-8")
    # Both published files are fetched, and the scanner is the one hashed.
    assert "--pattern SHA256SUMS --pattern securail.py" in run
    assert "sha256sum published/securail.py" in run
    # The manifest must describe the file beside it, and the rebuild must equal
    # both, or the job fails: a release is never trusted because it downloaded.
    assert "( cd published && sha256sum -c SHA256SUMS )" in run
    assert "test -n \"$expected\"" in run
    assert 'test "$expected" = "$rebuilt"' in run
    assert 'test "$download" = "$rebuilt"' in run
    # This fork publishes no signature and must not pretend it checks one.
    # Rebuilding from the tag is the whole verification story; see
    # docs/VERIFYING.md for why there is no key here.
    assert "VALIDSIG" not in run
    assert "gpg" not in run.lower()
