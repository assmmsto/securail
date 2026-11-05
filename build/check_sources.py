"""Decide whether today's indicator download is healthy, for the daily job.

`--update` already refuses a source whose count falls by more than a third and
keeps the previous copy of anything that fails. That protects a scan running on
this machine. It does not tell anyone that a publisher stopped publishing, and
it says nothing across days: a list that halves by 20% twice looks fine, and no
single run can see that a file has not changed in six weeks.

This reads the summary `--update --json` wrote, the manifest beside the cache,
and the state file the previous run left behind. It prints a table, records the
new state, and exits non-zero when any source failed, disappeared, shrank by
more than a third against yesterday, or has not changed in --max-stale-days.

No network, no clock of its own that cannot be injected: the whole decision is
a function of the three files and --today, so it can be tested.
"""
import argparse
import datetime
import io
import json
import os
import sys

# A source that shrank past this fraction of its previous count has lost enough
# that a scan may miss what it used to catch. Matches the guard in feeds.update.
SHRINK_FRACTION = 3.0
MAX_STALE_DAYS = 45


def _load(path):
    with io.open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _sources_from_update(update_doc):
    """{id: {...}} from the `--update --json` summary."""
    out = {}
    for entry in (update_doc or {}).get("sources") or []:
        if not isinstance(entry, dict):
            continue
        sid = entry.get("id")
        if not isinstance(sid, str) or not sid:
            continue
        out[sid] = entry
    return out


def _sources_from_manifest(manifest_doc):
    """{id: {...}} from the cache manifest, which holds the last good copy."""
    out = {}
    for sid, entry in (manifest_doc or {}).get("sources", {}).items():
        if isinstance(entry, dict):
            out[sid] = entry
    return out


def _date(value):
    """The date part of an ISO timestamp, or None."""
    if not isinstance(value, str) or len(value) < 10:
        return None
    try:
        return datetime.date(int(value[0:4]), int(value[5:7]), int(value[8:10]))
    except ValueError:
        return None


def check(update_doc, manifest_doc, state_doc, today,
          shrink_fraction=SHRINK_FRACTION, max_stale_days=MAX_STALE_DAYS):
    """Return (problems, rows, new_state).

    A problem is a dict with `id`, `name` and `why`. A row is what the table
    prints for every source that was seen at all, healthy or not.
    """
    reported = _sources_from_update(update_doc)
    manifest = _sources_from_manifest(manifest_doc)
    previous = ((state_doc or {}).get("sources") or {})
    problems = []
    rows = []
    new_state = {"checked": today.isoformat(), "sources": {}}

    for sid in sorted(set(reported) | set(manifest)):
        now = manifest.get(sid) or {}
        ran = reported.get(sid) or {}
        name = now.get("name") or ran.get("name") or sid
        status = ran.get("status") or ("present" if now else "missing")
        count = now.get("indicators")
        if not isinstance(count, int):
            count = ran.get("indicators") if isinstance(ran.get("indicators"), int) else None
        digest = now.get("sha256") if isinstance(now.get("sha256"), str) else None
        before = previous.get(sid) if isinstance(previous.get(sid), dict) else {}
        was = before.get("count")
        seen_digest = before.get("sha256")
        since = _date(before.get("unchanged_since"))

        row = {"id": sid, "name": name, "status": status, "count": count,
               "was": was if isinstance(was, int) else None, "stale_days": None}

        if status == "failed":
            problems.append({"id": sid, "name": name,
                             "why": "failed to download: " + str(ran.get("error") or "no reason given")[:200]})
        elif count is None:
            problems.append({"id": sid, "name": name, "why": "downloaded but reported no indicator count"})
        elif isinstance(was, int) and was > 0 and count < was / shrink_fraction:
            problems.append({"id": sid, "name": name,
                             "why": "count fell from {:,} to {:,} ({:.0f}% of yesterday)".format(
                                 was, count, 100.0 * count / was)})

        # Staleness is measured on the publisher's file, not on our check time:
        # an unchanged sha256 means the publisher has not republished anything.
        if digest and digest == seen_digest and since is not None:
            unchanged_since = since
        elif digest:
            unchanged_since = today
        else:
            unchanged_since = since
        if unchanged_since is not None:
            age = (today - unchanged_since).days
            row["stale_days"] = age
            if digest and age > max_stale_days:
                problems.append({"id": sid, "name": name,
                                 "why": "file unchanged for {} days (limit {})".format(age, max_stale_days)})

        if count is not None:
            new_state["sources"][sid] = {
                "count": count, "sha256": digest,
                "unchanged_since": unchanged_since.isoformat() if unchanged_since else None}
        elif sid in previous:
            # Keep what we knew: a failed download must not look like a reset.
            new_state["sources"][sid] = previous[sid]
        rows.append(row)

    # A source the previous run recorded and today never mentions at all: it was
    # removed from the catalogue or the summary lost it. Either way it is gone.
    for sid in sorted(set(previous) - set(new_state["sources"])):
        if sid in reported or sid in manifest:
            continue
        name = (previous.get(sid) or {}).get("name") or sid
        problems.append({"id": sid, "name": name, "why": "disappeared from the source list"})

    return problems, rows, new_state


def report_markdown(problems, rows, today):
    total = sum(r["count"] for r in rows if isinstance(r.get("count"), int))
    lines = ["# Indicator sources, {}".format(today.isoformat()), ""]
    if problems:
        lines.append("**{} problem(s) found.**".format(len(problems)))
        lines.append("")
        for problem in problems:
            lines.append("- **{}**: {}".format(problem["name"], problem["why"]))
        lines.append("")
    else:
        lines.append("Every source downloaded and none regressed.")
        lines.append("")
    lines.append("{} sources, {:,} indicators.".format(len(rows), total))
    lines.append("")
    lines.append("| source | status | indicators | yesterday | unchanged |")
    lines.append("| --- | --- | ---: | ---: | ---: |")
    for row in rows:
        was = "-" if row["was"] is None else "{:,}".format(row["was"])
        count = "-" if row["count"] is None else "{:,}".format(row["count"])
        stale = "-" if row["stale_days"] is None else "{}d".format(row["stale_days"])
        lines.append("| {} | {} | {} | {} | {} |".format(
            row["name"], row["status"], count, was, stale))
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--update-json", required=True,
                        help="summary written by --update --json")
    parser.add_argument("--manifest", required=True,
                        help="manifest.json beside the indicator cache")
    parser.add_argument("--state", default="",
                        help="state file the previous run wrote; absent on the first run")
    parser.add_argument("--output", default="",
                        help="where to write the new state file")
    parser.add_argument("--summary", default="",
                        help="where to write the markdown report (for $GITHUB_STEP_SUMMARY)")
    parser.add_argument("--today", default="",
                        help="YYYY-MM-DD; defaults to the UTC date")
    parser.add_argument("--max-stale-days", type=int, default=MAX_STALE_DAYS)
    parser.add_argument("--shrink-fraction", type=float, default=SHRINK_FRACTION)
    args = parser.parse_args(argv)

    today = datetime.date.today()
    if args.today:
        today = datetime.date(*[int(part) for part in args.today.split("-")])

    try:
        update_doc = _load(args.update_json)
    except (OSError, ValueError) as exc:
        print("error: could not read {}: {}".format(args.update_json, exc), file=sys.stderr)
        return 2
    try:
        manifest_doc = _load(args.manifest)
    except (OSError, ValueError):
        # No cache at all: the update summary is then the only evidence, and a
        # missing manifest is not itself a regression.
        manifest_doc = {}
    state_doc = {}
    if args.state and os.path.exists(args.state):
        try:
            state_doc = _load(args.state)
        except (OSError, ValueError) as exc:
            print("note: previous state unreadable ({}); treating this as a first run".format(exc),
                  file=sys.stderr)

    problems, rows, new_state = check(
        update_doc, manifest_doc, state_doc, today,
        shrink_fraction=args.shrink_fraction, max_stale_days=args.max_stale_days)

    markdown = report_markdown(problems, rows, today)
    print(markdown)
    if args.output:
        with io.open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(new_state, indent=2, sort_keys=True) + "\n")
    if args.summary:
        with io.open(args.summary, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(markdown + "\n")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())