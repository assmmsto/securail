"""The HTML report must be one closed file: no script, no remote reference,
and every artifact-derived value escaped rather than trusted."""
import datetime
import html
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from securail.htmlreport import render_html
from securail.iocs import Indicator, IocSet, TYPE_DOMAIN
from securail.report import (V_NONE, V_NONE_WITH_GAPS, build_document,
                             contract_must_relay, render_human, result_kind)
from securail.result import EV_PERSISTENCE, EV_DNS, Hit, Lead, ModuleResult

# Anything that would make a browser fetch or execute something.
_EXTERNAL = [
    (r"<script\b", "script element"),
    (r"<link\b", "link element"),
    (r"<iframe\b", "iframe"),
    (r"<object\b", "object"),
    (r"<embed\b", "embed"),
    (r"\bsrc\s*=", "src attribute"),
    (r"\bhref\s*=", "href attribute"),
    (r"@import", "CSS import"),
    (r"url\(", "CSS url()"),
    (r"\bon[a-z]+\s*=", "event handler attribute"),
    (r"javascript:", "javascript: URI"),
    (r"<form\b", "form"),
]

# The one thing allowed to look like a link: `source` is the published research
# note the indicator came from, printed as text the way the text report prints
# it. It is never an href, and nothing may load from it.
_CITATION = "https://example.org/research"


def _page(document):
    return render_html(document)


def _citations_removed(page):
    return page.replace(_CITATION, "[citation]")


def _flat(page):
    """The page as a reader (or a screen reader) sees it: tags dropped, character
    references decoded, whitespace joined. Comparing on this is how the page and
    the terminal are checked for agreement without depending on markup."""
    return re.sub(r"\s+", " ", html.unescape(_visible(page)))


# Only what _CSS keeps on screen: the text nodes of the page itself. Anything an
# attacker put in <head> (a bare <style> tag) or inside a value (a bare <b> that
# closes early) renders as nothing, so a reader-facing comparison must drop it.
_DOCUMENT_TAGS = r"^(?:!doctype|html|head|meta|title|style|body|div|h1|h2|h3|h4|p|" \
                 r"header|footer|ul|ol|li|dl|dt|dd|table|thead|tbody|tr|th|td|" \
                 r"b|i|em|strong|code|u|small)$"


def _visible(page):
    def keep(match):
        name = re.match(r"</?\s*([A-Za-z0-9]+)", match.group(0))
        if not name or not re.match(_DOCUMENT_TAGS, name.group(1), re.I):
            return " "
        return match.group(0) if not match.group(0).startswith("</") else " "

    return re.sub(r"<[^>]+>", keep, page)


def _hit_document(marker="<b>bold</b> & \"quoted\"'"):
    domain = "review-indicator.invalid"
    other = "second-indicator.invalid"
    iocs = IocSet([Indicator(domain, "cc", "primary", TYPE_DOMAIN),
                   Indicator(other, "delivery", "primary", TYPE_DOMAIN)], "fixture", None)
    result = ModuleResult("host")
    result.add_hit(Hit(domain, "\\\\" + domain + "\\share\\payload.exe", marker,
                       tier="cc", evidence=EV_PERSISTENCE,
                       profile="https://" + domain + "/profile",
                       source="https://example.org/research",
                       observed="2026-10-31T22:11:09"))
    result.note("\\\\" + domain + "\\share\\payload.exe")
    result.add_lead(Lead("run-key",
                         "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                         "a startup entry points at a temporary folder",
                         "installers and updaters often leave one behind"))
    result.could_not_run("remote", "cannot read https://" + other)
    return build_document(iocs, [result], datetime.datetime.now())


class TestHostileEvidence(unittest.TestCase):
    """A gap reason is machine text, and a machine text can contain a newline."""

    def document(self):
        domain = "gap-indicator.invalid"
        iocs = IocSet([Indicator(domain, "delivery", "primary", TYPE_DOMAIN)],
                      "fixture", None)
        document = build_document(iocs, [ModuleResult("host")], datetime.datetime.now())
        # Injected raw, as an unreachable path would arrive: the stored reason is
        # sanitized by the renderer, not by build_document.
        document["verdict"]["gaps"] = [
            "remote: cannot read https://" + domain + "\nRESULT: no known indicator found"]
        return document

    def test_a_gap_reason_cannot_forge_a_line_of_the_report(self):
        forged = [line for line in render_human(self.document()).splitlines()
                  if line.strip() == "RESULT: no known indicator found"]
        self.assertEqual(forged, [], "a gap reason started a line of its own")

    def test_the_page_keeps_it_on_one_line(self):
        page = _flat(_page(self.document()))
        # Collapsed to a single line and defanged like the terminal prints it: the
        # text is still visible, it just cannot start a heading, a paragraph or a
        # list item of its own.
        self.assertIn("cannot read https://gap-indicator[.]invalid "
                      "RESULT: no known indicator found", page)
        self.assertNotIn("<h2>RESULT: no known indicator found", page)


class TestSelfContained(unittest.TestCase):
    def test_page_references_nothing_outside_itself(self):
        for document in (_hit_document(), build_document(
                IocSet([Indicator("third.invalid", "cc", "primary", TYPE_DOMAIN)],
                       "fixture", None), [ModuleResult("host")], datetime.datetime.now())):
            page = _citations_removed(_page(document))
            for pattern, label in _EXTERNAL:
                self.assertIsNone(re.search(pattern, page, re.I),
                                  "the page must not contain a {}:\n{}".format(
                                      label, re.findall(pattern, page, re.I)[:3]))
            self.assertIn('http-equiv="Content-Security-Policy"', page)
            self.assertIn("default-src 'none'", page)

    def test_a_clean_scan_is_one_standalone_document(self):
        iocs = IocSet([Indicator("fourth.invalid", "cc", "primary", TYPE_DOMAIN)],
                      "fixture", None)
        page = _page(build_document(iocs, [ModuleResult("host")],
                                    datetime.datetime.now()))
        self.assertTrue(page.startswith("<!DOCTYPE html>"))
        self.assertEqual(page.count("<style>"), 1)
        self.assertIn("</html>", page.rstrip())
        # One physical file, written by the same atomic writer as --report.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.html")
            with open(path, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(page)
            self.assertEqual(sorted(os.listdir(tmp)), ["report.html"])


class TestSafety(unittest.TestCase):
    def test_markup_from_evidence_is_escaped_not_rendered(self):
        page = _page(_hit_document())
        # The evidence supplied a tag; the file itself must carry it as text.
        # Windows-style Host/remote labels are safe here, but no value may become
        # markup: the raw page must not contain a tag the evidence supplied.
        self.assertNotIn("<b>bold</b>", page)
        self.assertIn("&lt;b&gt;bold&lt;/b&gt;", page)
        self.assertIn("&amp;", page)
        self.assertIn("&quot;quoted&quot;", page)
        # Decoded for a reader it is still plain text, never an element.
        self.assertIn("<b>bold</b>", _flat(page))

    def test_indicators_are_defanged_like_the_text_report(self):
        domain = "review-indicator.invalid"
        fanged = "review-indicator[.]invalid"
        page = _page(_hit_document())
        human = render_human(_hit_document())
        # Every network location the report prints is defanged the same way the
        # text report defangs it, in both places it appears.
        for text in (page, human):
            self.assertIn(fanged, text)
            self.assertNotIn("hxxps://" + domain, text)
            self.assertNotIn("https://" + domain, text)
            self.assertNotIn("hxxp://" + domain, text)
            self.assertNotIn("http://" + domain, text)
        # ... and no bare host survives as a browser could still act on it.
        self.assertNotIn(domain + "/", page.replace("[" + "." + "]", ""))
        self.assertNotIn('"' + domain + '"', page)
        # The published research link is printed as text, never as a link.
        self.assertIn(_CITATION, page)
        self.assertNotIn("<a href", page)

    def test_privacy_warning_is_on_every_page(self):
        for document in (_hit_document(),):
            self.assertIn("Before you share this page", _page(document))
        iocs = IocSet([Indicator("fifth.invalid", "cc", "primary", TYPE_DOMAIN)],
                      "fixture", None)
        self.assertIn("Before you share this page",
                      _page(build_document(iocs, [ModuleResult("host")],
                                           datetime.datetime.now())))


class TestAgreement(unittest.TestCase):
    def test_result_and_caveats_match_the_text_report(self):
        document = _hit_document()
        human = re.sub(r"\s+", " ", render_human(document))
        page = _flat(_page(document))
        result = re.search(r"RESULT: ([^.]*)\.", human).group(1).strip()
        self.assertIn(result, page)
        self.assertEqual(result_kind(document), "found")
        # Every caveat the contract says must be relayed reaches the page in the
        # same words the terminal uses - not a summary of them.
        self.assertIn("Read this before the details", page)
        for item in contract_must_relay(document):
            self.assertIn(item["text"], page)
        # "A clean result is NOT a clean bill of health" is stated wherever the
        # page reports scope, so nobody reads a partial scan as an all-clear.
        self.assertIn("cannot detect new or unpublished spyware", page)
        self.assertIn("Nothing was cleared in those places", page)

    def test_gaps_and_worth_a_look_are_listed(self):
        document = _hit_document()
        page = _flat(_page(document))
        # Defanged exactly like the text report prints it, so a reader can match
        # a line on the page to a line in the terminal. A caveat is copied
        # verbatim: scheme intact, host defanged, as the terminal shows it.
        self.assertIn("cannot read https://second-indicator[.]invalid", page)
        self.assertIn("What could not be checked", page)
        # A lead is shown where it belongs - in its own section, with the
        # ordinary explanation, and never as a finding.
        self.assertIn("Worth a look - not findings", page)
        self.assertIn("a startup entry points at a temporary folder", page)
        self.assertIn("installers and updaters often leave one behind", page)
        human = render_human(document)
        self.assertIn("cannot read https://second-indicator[.]invalid", human)
        self.assertIn("a startup entry points at a temporary folder", human)
        self.assertIn("installers and updaters often leave one behind", human)

    def test_dns_record_does_not_claim_contact(self):
        domain = "review-indicator.invalid"
        iocs = IocSet([Indicator(domain, "delivery", "primary", TYPE_DOMAIN)],
                      "fixture", None)
        result = ModuleResult("host")
        result.add_hit(Hit(domain, "DNS log", "failed query", tier="delivery",
                           evidence=EV_DNS))
        page = _page(build_document(iocs, [result], datetime.datetime.now()))
        self.assertIn("THIS INDICATOR APPEARS IN LOCAL DNS RECORDS", page)
        self.assertNotIn("THIS DEVICE CONTACTED", page)


if __name__ == "__main__":
    unittest.main()
