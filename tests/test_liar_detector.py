#!/usr/bin/env python3
"""Tests for cookie-consent-liar-detector. No mocks of the core logic --
matching, HAR parsing, and verdicts are all exercised for real."""

import io
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import liar_detector as ld
from trackers import TRACKERS, tracker_map


def har_doc(urls):
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1"},
            "entries": [
                {"startedDateTime": "2026-10-17T14:00:%02d.000Z" % i,
                 "request": {"method": "GET", "url": url}}
                for i, url in enumerate(urls)
            ],
        }
    }


CLEAN_URLS = [
    "https://example-shop.com/",
    "https://example-shop.com/static/app.css",
    "https://cdn.example-shop.com/static/app.js",
    "https://example-shop.com/api/products",
    "https://example-shop.com/images/hero.jpg",
    "https://fonts.example.net/css?family=Inter",
]


class TestTrackerList(unittest.TestCase):
    def test_minimum_size(self):
        self.assertGreaterEqual(len(TRACKERS), 200,
                               "bundled list must carry ~200 tracker domains, got %d"
                               % len(TRACKERS))

    def test_entries_have_owner_and_sources(self):
        for domain, owner, sources in TRACKERS:
            self.assertTrue(domain and "." in domain and " " not in domain, domain)
            self.assertTrue(owner, domain)
            self.assertTrue(sources, domain)

    def test_no_duplicate_domains(self):
        domains = [d for d, _, _ in TRACKERS]
        self.assertEqual(len(domains), len(set(domains)))

    def test_known_trackers_present(self):
        tmap = tracker_map()
        for d in ["google-analytics.com", "doubleclick.net", "facebook.net",
                  "connect.facebook.net", "criteo.com", "hotjar.com"]:
            self.assertIn(d, tmap)


class TestMatching(unittest.TestCase):
    def test_exact_match(self):
        m = ld.match_tracker("google-analytics.com")
        self.assertIsNotNone(m)
        self.assertEqual(m[0], "google-analytics.com")
        self.assertEqual(m[1], "Google")

    def test_subdomain_match(self):
        m = ld.match_tracker("www.google-analytics.com")
        self.assertIsNotNone(m)
        self.assertEqual(m[0], "google-analytics.com")
        m2 = ld.match_tracker("x.bidswitch.net")
        self.assertIsNotNone(m2)
        self.assertEqual(m2[0], "bidswitch.net")

    def test_no_match_on_label_boundary(self):
        # notgoogle-analytics.com must NOT match google-analytics.com
        self.assertIsNone(ld.match_tracker("notgoogle-analytics.com"))
        self.assertIsNone(ld.match_tracker("google-analytics.com.evil.com"))

    def test_case_insensitive_and_port(self):
        self.assertIsNotNone(ld.match_tracker("WWW.GOOGLE-ANALYTICS.COM"))
        self.assertEqual(ld.normalize_host("https://sub.example.com:8443/x"), "sub.example.com")

    def test_normalize_host(self):
        self.assertEqual(ld.normalize_host("https://Example.COM:443/a?b=c"), "example.com")
        self.assertEqual(ld.normalize_host("not a url"), "")


class TestParsing(unittest.TestCase):
    def test_har_parsing(self):
        reqs, err = ld.extract_requests(har_doc(CLEAN_URLS))
        self.assertIsNone(err)
        self.assertEqual(len(reqs), len(CLEAN_URLS))
        self.assertEqual(reqs[0]["url"], CLEAN_URLS[0])

    def test_request_list_parsing(self):
        data = [{"url": u, "method": "POST"} for u in CLEAN_URLS[:3]]
        reqs, err = ld.extract_requests(data)
        self.assertIsNone(err)
        self.assertEqual(len(reqs), 3)
        self.assertEqual(reqs[0]["method"], "POST")

    def test_unrecognized_format(self):
        reqs, err = ld.extract_requests({"nope": True})
        self.assertEqual(reqs, [])
        self.assertTrue(err)

    def test_invalid_json_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as fh:
            fh.write("{not json")
            path = fh.name
        try:
            reqs, err = ld.load_input(path)
        finally:
            os.remove(path)
        self.assertEqual(reqs, [])
        self.assertIn("not valid JSON", err)


class TestVerdicts(unittest.TestCase):
    def test_liar_verdict(self):
        urls = CLEAN_URLS + [
            "https://www.google-analytics.com/g/collect?v=2",
            "https://connect.facebook.net/en_US/fbevents.js",
        ]
        reqs, _ = ld.extract_requests(har_doc(urls))
        report = ld.analyze(reqs, page_domain="example-shop.com")
        self.assertEqual(report["verdict"], "LIAR")
        self.assertEqual(len(report["per_tracker"]), 2)
        self.assertIn("google-analytics.com", report["per_tracker"])
        self.assertIn("facebook.net", report["per_tracker"])

    def test_clean_verdict(self):
        reqs, _ = ld.extract_requests(har_doc(CLEAN_URLS))
        report = ld.analyze(reqs, page_domain="example-shop.com")
        self.assertEqual(report["verdict"], "CLEAN")
        self.assertEqual(report["tracker_hits"], [])

    def test_inconclusive_empty(self):
        report = ld.analyze([])
        self.assertEqual(report["verdict"], "INCONCLUSIVE")

    def test_inconclusive_tiny_capture(self):
        reqs, _ = ld.extract_requests(har_doc(CLEAN_URLS[:3]))
        report = ld.analyze(reqs)
        self.assertEqual(report["verdict"], "INCONCLUSIVE")
        self.assertIn("incomplete", report["reason"])

    def test_first_party_hits_excluded(self):
        urls = CLEAN_URLS + ["https://stats.example-shop.com/matomo.js"]
        tmap = dict(tracker_map())
        tmap["stats.example-shop.com"] = ("Example Shop", ["Test"])
        reqs, _ = ld.extract_requests(har_doc(urls))
        report = ld.analyze(reqs, page_domain="example-shop.com", tmap=tmap)
        self.assertEqual(report["verdict"], "CLEAN")
        self.assertEqual(len(report["first_party_hits"]), 1)

    def test_report_json_serializable(self):
        urls = CLEAN_URLS + ["https://www.google-analytics.com/g/collect?v=2"]
        reqs, _ = ld.extract_requests(har_doc(urls))
        report = ld.analyze(reqs)
        json.dumps(report, sort_keys=True)  # must not raise

    def test_cli_exit_codes(self):
        with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as fh:
            json.dump(har_doc(CLEAN_URLS), fh)
            clean_path = fh.name
        with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as fh:
            json.dump(har_doc(CLEAN_URLS + ["https://bat.bing.com/bat.js"]), fh)
            liar_path = fh.name
        try:
            self.assertEqual(ld.main(["analyze", clean_path]), 0)
            self.assertEqual(ld.main(["analyze", liar_path]), 1)
            self.assertEqual(ld.main(["analyze", "/nonexistent.json"]), 2)
        finally:
            os.remove(clean_path)
            os.remove(liar_path)


class TestDemo(unittest.TestCase):
    def test_demo_runs_end_to_end(self):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = ld.main(["demo"])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("verdict           : LIAR", out)
        self.assertIn("google-analytics.com (Google)", out)

    def test_readme_example_output_matches_fresh_demo_run(self):
        """The README's Example output block is byte-for-byte the demo output."""
        readme = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "README.md")
        with open(readme) as fh:
            content = fh.read()
        m = re.search(r"<!-- DEMO-OUTPUT-START -->\n(.*?)<!-- DEMO-OUTPUT-END -->",
                      content, re.DOTALL)
        self.assertIsNotNone(m, "README missing DEMO-OUTPUT markers")
        block = m.group(1)
        self.assertTrue(block.startswith("```\n") and block.rstrip().endswith("```"))
        readme_output = block[len("```\n"):].rstrip()
        if readme_output.endswith("```"):
            readme_output = readme_output[:-3].rstrip()

        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = ld.main(["demo"])
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)
        fresh = buf.getvalue().rstrip()
        self.assertEqual(readme_output, fresh,
                         "README example output is stale -- re-run build_readme.py")


if __name__ == "__main__":
    unittest.main()
