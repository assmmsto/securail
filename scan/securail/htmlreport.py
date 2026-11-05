"""One self-contained HTML file that opens offline, in any browser, on any
computer - no server, no script, no network request of any kind.

The readable text report stays the record: it is what the tool prints, what
--report saves and what a responder can be sent. This module renders the same
evidence as a page for someone who would rather read it in a browser or attach
it to a message. Two rules shape everything here:

  1. Nothing leaves the file. There is no <script>, no <link>, no @import, no
     remote font, image or stylesheet. The page must render identically on a
     computer with the network switched off, because that is often exactly how
     it will be opened.
  2. It must be safe to open. Indicator values and artifact paths come from
     scanned files and third-party feeds, so every value is HTML-escaped and
     the page carries a Content-Security-Policy that forbids scripts outright -
     a name inside a bookmark, a message or a filename can never run.

The page is a summary with its evidence, not the whole report: it mirrors the
sections a person reads first and then the findings, gaps and privacy warning.
"""
from __future__ import annotations

import copy
import html
from typing import Any, Dict, List

from . import __version__
from .contract import contract_must_relay
from .i18n import T, i18n_lang
from .report import (_advice_paragraph, _dedup_serious, _defang, _defang_report,
                     _defang_text,
                     _evidence_gloss, _gap_lines, _headline_for, _human_document,
                     _net_value, _recommended_action, is_serious,
                     render_summary)

# A restrictive policy for a local file: no scripts at all, nothing loaded from
# anywhere, and no way to reach out through a form. It is a second lock beside
# the escaping, for anyone who opens the file with a hostile value in it.
_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

_CSS = """
:root{--ink:#16181d;--muted:#5b6472;--line:#d5dae2;--bg:#ffffff;--panel:#f6f7f9;
--serious:#8c1d1d;--serious-bg:#fdf1f1;--warn:#6b4b00;--warn-bg:#fdf8e7;
--ok:#1d5c33;--ok-bg:#f0f8f2;--info:#1f3a68;--info-bg:#eff4fb;
--mono:ui-monospace,SFMono-Regular,"Cascadia Mono",Consolas,monospace}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);line-height:1.55;
font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
font-size:16px}
.wrap{max-width:60rem;margin:0 auto;padding:1.5rem 1.25rem 4rem}
header.top{border-bottom:2px solid var(--ink);padding-bottom:.9rem;margin-bottom:1.5rem}
h1{font-size:1.45rem;margin:0 0 .2rem;letter-spacing:.01em}
.sub{color:var(--muted);font-size:.9rem;margin:0}
h2{font-size:1.05rem;margin:2rem 0 .6rem;padding-bottom:.3rem;
border-bottom:1px solid var(--line);letter-spacing:.02em}
h3{font-size:1rem;margin:1.4rem 0 .5rem}
p{margin:.6rem 0}
.muted{color:var(--muted)}
.mono{font-family:var(--mono);font-size:.86rem;word-break:break-word}
.banner{border:1px solid var(--line);border-left:5px solid var(--ink);
background:var(--panel);padding:.9rem 1rem;margin:1.2rem 0;border-radius:4px}
.banner.serious{border-left-color:var(--serious);background:var(--serious-bg)}
.banner.warn{border-left-color:var(--warn);background:var(--warn-bg)}
.banner.ok{border-left-color:var(--ok);background:var(--ok-bg)}
.banner.info{border-left-color:var(--info);background:var(--info-bg)}
.banner .label{font-size:.72rem;letter-spacing:.12em;text-transform:uppercase;
color:var(--muted);margin-bottom:.3rem}
.banner .result{font-size:1.15rem;font-weight:600}
.banner p{font-size:.92rem;margin:.5rem 0 0}
.chips{display:flex;flex-wrap:wrap;gap:.5rem;margin:.8rem 0 0}
.chip{font-size:.78rem;border:1px solid var(--line);background:var(--bg);
border-radius:999px;padding:.15rem .6rem;color:var(--muted)}
.chip.strong{border-color:var(--ink);color:var(--ink)}
table{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:.9rem}
th,td{text-align:left;vertical-align:top;padding:.45rem .55rem;
border-bottom:1px solid var(--line)}
th{font-size:.74rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);
font-weight:600}
td.num{text-align:right;font-variant-numeric:tabular-nums}
dl.facts{margin:.4rem 0}
dl.facts div{display:flex;gap:.8rem;padding:.25rem 0;border-bottom:1px dotted var(--line)}
dl.facts dt{flex:0 0 11rem;color:var(--muted);font-size:.88rem;margin:0}
dl.facts dd{margin:0;font-size:.9rem;word-break:break-word}
ul{padding-left:1.2rem;margin:.5rem 0}
li{margin:.3rem 0}
/* An attacker-supplied element inside a report value must not change how the
document beyond it renders: white-list plain text, show nothing else. */
li :not(b):not(i):not(em):not(strong):not(code):not(u):not(small),
.finding :not(b):not(i):not(em):not(strong):not(code):not(u):not(small),
td :not(b):not(i):not(em):not(strong):not(code):not(u):not(small),
dl.facts :not(b):not(i):not(em):not(strong):not(code):not(u):not(small),
.callout :not(b):not(i):not(em):not(strong):not(code):not(u):not(small),
.banner :not(b):not(i):not(em):not(strong):not(code):not(u):not(small),
footer :not(b):not(i):not(em):not(strong):not(code):not(u):not(small){display:none}
.finding{border:1px solid var(--line);border-left:4px solid var(--serious);
border-radius:4px;padding:.7rem .85rem;margin:.7rem 0;background:var(--serious-bg)}
.finding.note{border-left-color:var(--info);background:var(--info-bg)}
.finding h4{margin:0 0 .35rem;font-size:.95rem}
.finding .value{font-family:var(--mono);font-size:.86rem;word-break:break-all;
margin:.15rem 0 .4rem}
.finding dl.facts dt{flex:0 0 6.5rem}
.callout{border:1px solid var(--line);background:var(--panel);border-radius:4px;
padding:.8rem .95rem;margin:.9rem 0}
.callout.warn{border-color:#e6d5a8;background:var(--warn-bg)}
.callout.danger{border-color:#e3bcbc;background:var(--serious-bg)}
.callout p:first-child{margin-top:0}
.callout p:last-child{margin-bottom:0}
footer{margin-top:2.5rem;padding-top:.8rem;border-top:1px solid var(--line);
color:var(--muted);font-size:.82rem}
@media print{body{font-size:11pt}.wrap{max-width:none;padding:0}
h2{page-break-after:avoid}.finding,.callout,.banner{page-break-inside:avoid}
header.top{position:static}a{color:inherit;text-decoration:none}}
@media (prefers-color-scheme:dark){
:root{--ink:#e9ecf1;--muted:#a3adbb;--line:#333a45;--bg:#14171c;--panel:#1d2229;
--serious:#ff9d9d;--serious-bg:#2b1a1c;--warn:#e8c778;--warn-bg:#2a2415;
--ok:#8fd8a8;--ok-bg:#16251b;--info:#9dbcf0;--info-bg:#17202e}
.finding{border-left-color:var(--serious)}
.callout.warn{border-color:#4a4026}.callout.danger{border-color:#4a2a2c}}
"""

# Result kinds, mapped to the tone of the banner. Green is only ever "none":
# nothing found AND every check ran. Anything unknown stays neutral or amber.
_TONE = {"found": "serious", "withdrawn": "warn", "references": "info",
         "unread": "warn", "none_with_gaps": "warn", "none": "ok"}

_CLOSING = ("No result from this check proves a phone or computer is safe. Only "
            "publicly documented indicators of known spyware are looked for, "
            "and the traces spyware leaves usually expire within weeks.")


def _e(value) -> str:
    """Every value goes through here. Indicator names, file names and feed text
    are all third-party input."""
    return html.escape("" if value is None else str(value), quote=True)


def _result_kind(document: Dict[str, Any]) -> str:
    from .report import result_kind
    return result_kind(document)


def _summary_lines(document: Dict[str, Any]) -> List[str]:
    """The RESULT paragraph of the text report, as one plain sentence.

    Read from the one place it is written, so the page and the terminal can
    never drift into saying different things about the same scan. The text
    report hard-wraps at a fixed column; the page must not inherit that wrap."""
    lines = render_summary(document).split("\n")
    keep: List[str] = []
    started = False
    for line in lines:
        stripped = line.strip()
        if not started:
            if stripped.startswith("RESULT:"):
                started = True
                keep.append(stripped)
            continue
        if not stripped or (set(stripped) <= set("=-") and len(stripped) > 3):
            break
        if stripped.isupper() and len(stripped) > 3:
            break
        keep.append(stripped)
    return [" ".join(keep)] if keep else []


def _first_advice(document: Dict[str, Any]) -> str:
    """The opening advice of WHAT TO DO, as one sentence.

    Taken from the renderer rather than retyped, so a change to the advice
    reaches the page too. The advice is wrapped at a fixed column for the
    terminal; the page joins that first paragraph back into one sentence."""
    from .report import _next_steps
    hits = [h for _m, m in document["modules"].items() for h in m["hits"]
            if is_serious(h.get("evidence", ""))]
    if not hits:
        return ""
    out: List[str] = []
    _next_steps(out.append, hits)
    paragraph: List[str] = []
    for line in out:
        text = line.strip()
        if not text or text.isupper():
            if paragraph:
                break
            continue
        if text.startswith("- "):
            break
        paragraph.append(text)
        if text.endswith((".", "?", "!")):
            break
    return " ".join(paragraph)


def _relay(document: Dict[str, Any]) -> List[str]:
    return [item["text"] for item in contract_must_relay(document)]


def _seen(text, indicator: str = "") -> str:
    """A value as the page prints it.

    Exactly what the text report does - schemes neutered, the indicator's own
    name swapped for its defanged form - and nothing else, so a line on the page
    can be matched to a line in the terminal and the Windows paths in it still
    read as paths.

    This is the one and only defanging pass for a field: callers hand it the
    value as stored in the document, before `_human_document` touches it, and
    the summary block gets it through `_visible_document`. Running it twice
    would turn hxxps:// into hxxps:// a second time and lose the indicator."""
    return _defang_text(text, indicator)


def _visible_document(document):
    """The document as published: every artifact-derived value cleaned once.

    Handled exactly as the text report handles it. Nothing is re-cleaned here:
    the summary block is already rendered into the plain lines the terminal
    prints, and every other value reaches the page through `_seen`, which is the
    one defanging pass. The only change is restoring the source citations, which
    `_human_document` defangs with everything else - a citation is the published
    address of a research note and is meant to stay checkable, and the page
    prints it as text, never as a link."""
    doc = _human_document(document)
    for module, raw in zip(doc["modules"].values(), document["modules"].values()):
        for hit, source_hit in zip(module["hits"], raw["hits"]):
            hit["source"] = source_hit.get("source", "")
    return doc


def _indicator_rows(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    ioc = document.get("ioc_set") or {}
    rows = []
    for entry in ioc.get("sets") or []:
        from .report import _basename
        device = sum((entry.get("device_indicators") or {}).values())
        skipped = sum((entry.get("not_applicable_to_this_scan") or {}).values())
        refused = sum((entry.get("refused_invalid") or {}).values())
        rows.append({"file": _basename(entry.get("path", "")),
                     "usable": entry.get("usable", 0), "device": device,
                     "skipped": skipped, "refused": refused})
    return rows


def _gap_sentences(document: Dict[str, Any]) -> List[str]:
    """The gap list, grouped and defanged exactly as the text report prints it.

    Grouping is the text report's own, and the terminal defangs these lines in
    its one whole-text pass over the finished report - scheme left intact, host
    defanged at the dot. Stored gap reasons are raw, so the page runs the same
    pass here; otherwise the page would print an address the terminal refuses
    to print. Nothing else touches these lines: _defang_text is not idempotent,
    and a second pass would double the scheme."""
    gaps = document.get("verdict", {}).get("gaps") or []
    return [_defang_report(line, document) for line in _gap_lines(gaps)]


def _serious_findings(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits = [h for _m, m in document["modules"].items() for h in m["hits"]]
    serious = [h for h in hits if is_serious(h.get("evidence", ""))]
    out = []
    for h in sorted(_dedup_serious(serious), key=_recommended_action, reverse=True):
        net = _net_value(h)
        out.append({
            "headline": T(_headline_for(h)),
            "indicator": _defang(net) if net else h.get("indicator", ""),
            "tier": h.get("tier", ""),
            "evidence": h.get("evidence", ""),
            "gloss": ("" if h.get("withdrawn_only") else T(_evidence_gloss(h) or "")),
            "account": _seen(h.get("profile", ""), net),
            "when": _seen((h.get("observed") or "")[:19].replace("T", " "), net),
            "where": _seen(h.get("location", ""), net),
            "detail": _seen(h.get("detail", ""), net),
            "source": h.get("source", ""),
            "family": h.get("family", ""),
            "action": _recommended_action(h),
        })
    return out


def _worth_a_look(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{"what": item.get("what", ""), "location": item.get("location", ""),
             "usual": item.get("usual_reason", ""), "observed": item.get("observed", "")}
            for item in (document.get("worth_a_look") or [])]


def _banner(kind, summary):
    tone = _TONE.get(kind, "warn")
    label = {"found": "Finding", "withdrawn": "Withdrawn indicator",
             "references": "Saved references only", "unread": "Could not be checked",
             "none_with_gaps": "Nothing found, gaps", "none": "Nothing found"}.get(kind, "Result")
    head = summary[0] if summary else "Result"
    for prefix in ("RESULT: ", "RESULT:"):
        if head.startswith(prefix):
            head = head[len(prefix):]
            break
    parts = ['<div class="banner {}">'.format(tone),
             '<div class="label">{}</div>'.format(_e(T(label))),
             '<div class="result">{}</div>'.format(_e(T(head)))]
    parts.append("</div>")
    return "".join(parts)


def render_html(document: Dict[str, Any]) -> str:
    """The whole page, as one string. No external reference of any kind."""
    document = _visible_document(document)
    kind = _result_kind(document)
    summary = _summary_lines(document)
    scope = document.get("scope") or {}
    platform = document.get("platform") or {}
    verdict = document.get("verdict") or {}
    ioc = document.get("ioc_set") or {}
    findings = _serious_findings(document)
    looks = _worth_a_look(document)
    gaps = verdict.get("gaps") or []
    relay = _relay(document)

    out: List[str] = []
    w = out.append
    w("<!DOCTYPE html>")
    w('<html lang="{}">'.format(_e(i18n_lang() if i18n_lang() in ("ar", "fa", "he", "ur") else
                                  ("en" if i18n_lang() == "en" else i18n_lang()))))
    w("<head>")
    w('<meta charset="utf-8">')
    w('<meta name="viewport" content="width=device-width, initial-scale=1">')
    w('<meta http-equiv="Content-Security-Policy" content="{}">'.format(_CSP))
    w('<meta name="referrer" content="no-referrer">')
    w('<meta name="robots" content="noindex, nofollow">')
    w("<title>{} - {}</title>".format(
        _e(T("Securail {version} report", version=document["tool"]["version"])),
        _e(document.get("timestamp", ""))))
    w("<style>{}</style>".format(_CSS))
    w("</head>")
    w("<body>")
    w('<div class="wrap">')

    # --- head -----------------------------------------------------------------
    w('<header class="top">')
    w("<h1>{}</h1>".format(_e(T("Securail {version} - spyware indicator check",
                                version=document["tool"]["version"]))))
    w('<p class="sub mono">{}</p>'.format(_e(
        "{}  |  {} {}  |  {}".format(document.get("timestamp", ""), platform.get("system", ""),
                                     platform.get("release", ""),
                                     T("Scope: {kind}", kind=scope.get("scan_type", "default"))))))
    w("</header>")

    w(_banner(kind, summary))
    chips = []
    age = ioc.get("age_days")
    chips.append(_e(T("Indicator set: {count}, {age}",
                      count="{:,}".format(ioc.get("count", 0)),
                      age=(T("unknown age") if age is None else T("{days} day(s) old", days=age)))))
    if ioc.get("stale"):
        chips.append(_e(T("indicator set older than 30 days")))
    if ioc.get("freshness_unknown"):
        chips.append(_e(T("source dates unknown")))
    if gaps:
        chips.append(_e(T("{n} check(s) could not run", n=len(gaps))))
    if document.get("training"):
        chips.append(_e(T("training example - not a real device")))
    w('<div class="chips">')
    for i, chip in enumerate(chips):
        strong = " strong" if (i == 0 or (i == 1 and ioc.get("stale"))) else ""
        w('<span class="chip{}">{}</span>'.format(strong, chip))
    w("</div>")

    if scope.get("targets"):
        w('<p class="muted">' + _e(T("Only selected targets were checked; system and other-user "
                                     "records are outside scope.")) + "</p>")
    if scope.get("cancelled"):
        w('<p class="muted">' + _e(T("Cancelled: this page contains partial evidence only.")) + "</p>")

    # --- caveats that must reach the reader -----------------------------------
    if relay:
        w("<h2>{}</h2>".format(_e(T("Read this before the details"))))
        w('<div class="callout warn">')
        for text in relay:
            w("<p>{}</p>".format(_e(T(text))))
        w("</div>")

    # --- findings -------------------------------------------------------------
    w("<h2>{}</h2>".format(_e(T("What was found"))))
    if findings:
        for f in findings:
            w('<div class="finding{}">'.format(" note" if f["action"] <= 1 else ""))
            w("<h4>{}</h4>".format(_e(f["headline"])))
            w('<div class="value">{}</div>'.format(_e(f["indicator"])))
            w('<dl class="facts">')
            for label, value in ((T("Tier"), f["tier"]),
                                 (T("Evidence"), f["evidence"]),
                                 (T("Family"), f["family"]),
                                 (T("Source"), f["source"]),
                                 (T("Account"), f["account"]),
                                 (T("When"), f["when"]),
                                 (T("Where"), f["where"]),
                                 (T("Detail"), f["detail"])):
                if value:
                    w("<div><dt>{}</dt><dd>{}</dd></div>".format(_e(label), _e(value)))
            w("</dl>")
            if f["gloss"]:
                w("<p>{}</p>".format(_e(f["gloss"])))
            w("</div>")
        w('<div class="callout danger">')
        advice = _first_advice(document)
        w("<p><strong>{}</strong> {}</p>".format(
            _e(T("What to do now:")),
            _e(T(advice) if advice else T("Do not delete, move, run or 'clean' the matched "
                                          "files or records. Keep the device and this report "
                                          "as evidence."))))
        w("</div>")
    else:
        w("<p>{}</p>".format(_e(T("No serious indicator match was recorded in anything this "
                                  "scan could read."))))

    # --- worth a look ---------------------------------------------------------
    if looks:
        w("<h2>{}</h2>".format(_e(T("Worth a look - not findings"))))
        w("<p>{}</p>".format(_e(T("These are things the scan cannot judge. Each one "
                                  "comes with the ordinary explanation that usually "
                                  "accounts for it. None of them is a sign of spyware "
                                  "on its own."))))
        w("<table><thead><tr><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>".format(
            _e(T("Item")), _e(T("Where")), _e(T("Usual explanation"))))
        for item in looks:
            w("<tr><td>{}</td><td class=\"mono\">{}</td><td>{}</td></tr>".format(
                _e(_seen(item["what"])), _e(_seen(item["location"])),
                _e(_seen(item["usual"]))))
        w("</tbody></table>")

    # --- what could not be checked -------------------------------------------
    w("<h2>{}</h2>".format(_e(T("What could not be checked"))))
    if gaps:
        w("<ul>")
        for line in _gap_sentences(document):
            w("<li>{}</li>".format(_e(line)))
        w("</ul>")
        w('<p class="muted">{}</p>'.format(
            _e(T("Nothing was cleared in those places. The JSON report lists every gap "
                 "in full."))))
    else:
        w("<p>{}</p>".format(_e(T("Every check the tool offers for this scope ran to "
                                  "completion."))))

    # --- the indicator set ----------------------------------------------------
    w("<h2>{}</h2>".format(_e(T("The indicator set"))))
    w('<dl class="facts">')
    w("<div><dt>{}</dt><dd>{}</dd></div>".format(
        _e(T("Indicators used")), _e("{:,}".format(ioc.get("count", 0)))))
    w("<div><dt>{}</dt><dd>{}</dd></div>".format(
        _e(T("Age")), _e(T("unknown") if age is None else T("{days} day(s)", days=age))))
    if ioc.get("asof"):
        w("<div><dt>{}</dt><dd>{}</dd></div>".format(_e(T("As of")), _e(ioc["asof"])))
    rows = _indicator_rows(document)
    if rows:
        w("</dl>")
        w("<table><thead><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr></thead><tbody>".format(
            _e(T("Source file")), _e(T("Used here")), _e(T("For phone/mail checks")),
            _e(T("Not usable"))))
        for row in rows:
            w("<tr><td class=\"mono\">{}</td><td class=\"num\">{}</td>"
              "<td class=\"num\">{}</td><td class=\"num\">{}</td></tr>".format(
                  _e(row["file"]), _e(row["usable"]), _e(row["device"]),
                  _e(row["skipped"] + row["refused"])))
        w("</tbody></table>")
    else:
        w("</dl>")

    # --- privacy, always ------------------------------------------------------
    w("<h2>{}</h2>".format(_e(T("Before you share this page"))))
    w('<div class="callout danger">')
    w("<p>{}</p>".format(_e(T(
        "This page can contain your username, computer name, browser profile names, "
        "file paths, and details of what was found and where. Do not post it publicly. "
        "Ask whoever is helping you how to share it securely, and send it as a file "
        "rather than pasting it into a public channel."))))
    w("</div>")

    w("<footer>")
    w("<p>{}</p>".format(_e(T(_CLOSING))))
    w("<p>{}</p>".format(_e(T("Generated offline by Securail {version}. This file loads "
                              "nothing from the network and runs no script.",
                              version=document["tool"]["version"]))))
    w("</footer>")
    w("</div>")
    w("</body>")
    w("</html>")
    return "\n".join(out) + "\n"
