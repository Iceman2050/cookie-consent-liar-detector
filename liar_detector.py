#!/usr/bin/env python3
"""
cookie-consent-liar-detector
============================
Post-hoc analyzer: did "Reject all" actually stop the trackers?

You capture the network requests your browser made AFTER clicking "reject all"
on a site's cookie banner (see HAR-CAPTURE-HOWTO.md), then this tool matches
every request against a bundled list of ~250 known tracker domains and
produces an evidence-grade report:

  LIAR         -- known trackers fired after rejection (with per-tracker counts)
  CLEAN        -- no known tracker fired
  INCONCLUSIVE -- the capture is too small / malformed to judge

This is a post-hoc analyzer, NOT an automated browser test: it cannot click
the banner for you, it cannot prove what the site did server-side, and a CLEAN
verdict means "no *known* tracker fired", not "no tracking happened".

Stdlib only. No network access.
"""

import argparse
import json
import os
import sys
from urllib.parse import urlparse

from trackers import TRACKERS, tracker_map, tracker_count

TOOL_VERSION = "1.0.0"

LIAR = "LIAR"
CLEAN = "CLEAN"
INCONCLUSIVE = "INCONCLUSIVE"

MIN_REQUESTS_FOR_VERDICT = 5


# --------------------------------------------------------------------------
# Tracker matching
# --------------------------------------------------------------------------

def normalize_host(url):
    """Extract a lowercase, port-stripped hostname from a URL."""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return ""
    return host.lower().rstrip(".")


def match_tracker(host, tmap=None):
    """Match a hostname against the tracker list.

    Matches on label boundaries only: `sub.tracker.com` matches
    `tracker.com`, but `nottracker.com` does NOT. Returns
    (tracker_domain, owner, sources) or None.
    """
    if tmap is None:
        tmap = tracker_map()
    host = (host or "").lower().rstrip(".")
    if not host:
        return None
    for domain, (owner, sources) in tmap.items():
        if host == domain or host.endswith("." + domain):
            return domain, owner, sources
    return None


# --------------------------------------------------------------------------
# Input parsing: HAR or recorded request list
# --------------------------------------------------------------------------

def _entry_to_request(entry):
    req = entry.get("request", {}) if isinstance(entry, dict) else {}
    url = req.get("url") if isinstance(req, dict) else None
    method = req.get("method", "GET") if isinstance(req, dict) else "GET"
    started = entry.get("startedDateTime", "") if isinstance(entry, dict) else ""
    if not url or not isinstance(url, str):
        return None
    return {"url": url, "method": str(method), "started": str(started)}


def _list_item_to_request(item):
    if not isinstance(item, dict):
        return None
    url = item.get("url")
    if not url or not isinstance(url, str):
        return None
    return {
        "url": url,
        "method": str(item.get("method", "GET")),
        "started": str(item.get("startedDateTime", item.get("started", ""))),
    }


def extract_requests(data):
    """Return (requests, error). requests is a list of {url, method, started}."""
    requests = []
    if isinstance(data, dict) and isinstance(data.get("log"), dict):
        entries = data["log"].get("entries", [])
        if not isinstance(entries, list):
            return [], "HAR log.entries is not a list"
        for entry in entries:
            req = _entry_to_request(entry)
            if req:
                requests.append(req)
        return requests, None
    if isinstance(data, list):
        for item in data:
            req = _list_item_to_request(item)
            if req:
                requests.append(req)
        return requests, None
    return [], "unrecognized format: expected a HAR object or a JSON request list"


def load_input(path):
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as exc:
            return [], "not valid JSON: %s" % exc
    return extract_requests(data)


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def analyze(requests, page_domain=None, tmap=None):
    """Analyze requests captured after 'reject all'. Returns a report dict."""
    if tmap is None:
        tmap = tracker_map()
    report = {
        "tool": "cookie-consent-liar-detector",
        "version": TOOL_VERSION,
        "tracker_list_size": tracker_count(),
        "total_requests": len(requests),
        "verdict": INCONCLUSIVE,
        "reason": "",
        "tracker_hits": [],
        "per_tracker": {},
        "first_party_hits": [],
    }
    if len(requests) == 0:
        report["reason"] = "no requests found in the capture"
        return report
    if len(requests) < MIN_REQUESTS_FOR_VERDICT:
        report["reason"] = (
            "only %d request(s) captured -- fewer than %d; the capture looks "
            "incomplete (did you preserve the network log?)" % (len(requests), MIN_REQUESTS_FOR_VERDICT)
        )
        return report

    page_domain = (page_domain or "").lower().rstrip(".")
    for req in requests:
        host = normalize_host(req["url"])
        if not host:
            continue
        matched = match_tracker(host, tmap)
        if matched is None:
            continue
        domain, owner, sources = matched
        hit = {
            "url": req["url"],
            "host": host,
            "method": req["method"],
            "started": req["started"],
            "tracker_domain": domain,
            "owner": owner,
            "sources": sources,
        }
        is_first_party = bool(page_domain) and (
            host == page_domain or host.endswith("." + page_domain)
        )
        if is_first_party:
            report["first_party_hits"].append(hit)
        else:
            report["tracker_hits"].append(hit)

    per = {}
    for hit in report["tracker_hits"]:
        d = hit["tracker_domain"]
        slot = per.setdefault(d, {"owner": hit["owner"], "requests": 0, "sample_urls": []})
        slot["requests"] += 1
        if len(slot["sample_urls"]) < 3:
            slot["sample_urls"].append(hit["url"])
    report["per_tracker"] = per

    if report["tracker_hits"]:
        report["verdict"] = LIAR
        report["reason"] = (
            "%d request(s) to %d known tracker domain(s) fired after consent "
            "was rejected" % (len(report["tracker_hits"]), len(per))
        )
    else:
        report["verdict"] = CLEAN
        report["reason"] = (
            "no known tracker domains fired in %d captured request(s)" % len(requests)
        )
    return report


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def format_report(report):
    lines = []
    lines.append("== cookie-consent-liar-detector ==")
    lines.append("requests analyzed : %d" % report["total_requests"])
    lines.append("tracker list size : %d known domains" % report["tracker_list_size"])
    lines.append("verdict           : %s" % report["verdict"])
    lines.append("reason            : %s" % report["reason"])
    if report["tracker_hits"]:
        lines.append("")
        lines.append("trackers that fired after 'reject all':")
        for domain in sorted(report["per_tracker"]):
            slot = report["per_tracker"][domain]
            lines.append("  - %s (%s): %d request(s)" % (domain, slot["owner"], slot["requests"]))
            for url in slot["sample_urls"]:
                lines.append("      e.g. %s" % url)
    if report["first_party_hits"]:
        lines.append("")
        lines.append("note: %d hit(s) matched tracker domains served from the "
                     "first-party domain (excluded from verdict)" % len(report["first_party_hits"]))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------

def cmd_demo(_args):
    """Run the analyzer on the bundled sample HAR (planted tracker hits)."""
    here = os.path.dirname(os.path.abspath(__file__))
    sample = os.path.join(here, "sample-har.json")
    requests, error = load_input(sample)
    if error:
        print("demo failed to load sample HAR: %s" % error, file=sys.stderr)
        return 1
    print("analyzing sample capture: page=example-shop.com, consent=rejected")
    report = analyze(requests, page_domain="example-shop.com")
    print(format_report(report))
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_analyze(args):
    try:
        requests, error = load_input(args.input)
    except OSError as exc:
        requests, error = [], "cannot read input file: %s" % exc
    if error:
        report = {
            "tool": "cookie-consent-liar-detector",
            "version": TOOL_VERSION,
            "tracker_list_size": tracker_count(),
            "total_requests": 0,
            "verdict": INCONCLUSIVE,
            "reason": error,
            "tracker_hits": [],
            "per_tracker": {},
            "first_party_hits": [],
        }
    else:
        report = analyze(requests, page_domain=args.page_domain)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_report(report))
    return {"LIAR": 1, "CLEAN": 0, "INCONCLUSIVE": 2}[report["verdict"]]


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="liar_detector",
        description="Check whether 'reject all' really stopped the trackers.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_an = sub.add_parser("analyze", help="analyze a HAR file or request list")
    p_an.add_argument("input", help="path to .har (JSON) or JSON request list")
    p_an.add_argument("--page-domain", default=None,
                      help="the site's own domain (first-party tracker hits excluded)")
    p_an.add_argument("--json", action="store_true", help="emit JSON report")
    p_an.set_defaults(func=cmd_analyze)

    p_demo = sub.add_parser("demo", help="30-second demo on the bundled sample HAR")
    p_demo.set_defaults(func=cmd_demo)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
