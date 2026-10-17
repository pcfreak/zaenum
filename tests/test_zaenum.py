#!/usr/bin/env python3
"""Offline tests for zaenum's parsing and resume behaviour.

Run: python3 -m unittest discover -s tests -v
The transport is faked, so these pass with no network and no rate limits.
"""

import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import zaenum  # noqa: E402


def args(**over):
    base = dict(delay=0.0, timeout=5, retries=1, max_hosts=0, resolve=False,
                ct_url="http://ct.test/?q={query}")
    base.update(over)
    return types.SimpleNamespace(**base)


class FakeTransport:
    """Replaces zaenum.http_get with a scripted map of url-substring -> reply."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, url, timeout=60, delay=1.0, tries=4):
        self.calls.append(url)
        for needle, reply in self.routes.items():
            if needle in url:
                return reply
        return 200, b'{"pages": 0}'


class HostParsingTests(unittest.TestCase):
    def test_normalises_messy_names(self):
        self.assertEqual(zaenum.norm_host("*.WWW.Example.CO.ZA."), "www.example.co.za")
        self.assertEqual(zaenum.norm_host("host.co.za:443"), "host.co.za")
        self.assertEqual(zaenum.norm_host("admin@mail.co.za"), "mail.co.za")
        self.assertIsNone(zaenum.norm_host(""))
        self.assertIsNone(zaenum.norm_host("not a hostname"))
        self.assertIsNone(zaenum.norm_host("192.168.0.1"))

    def test_belongs_is_suffix_aware(self):
        self.assertTrue(zaenum.belongs("news24.com", "news24.com"))
        self.assertTrue(zaenum.belongs("www.news24.com", "news24.com"))
        self.assertFalse(zaenum.belongs("evilnews24.com", "news24.com"))
        self.assertFalse(zaenum.belongs("news24.com.attacker.net", "news24.com"))

    def test_san_lists_split_on_newlines_and_commas(self):
        names = list(zaenum.parse_names("a.co.za\nb.co.za,c.co.za\n*.d.co.za"))
        self.assertEqual(sorted(names), ["a.co.za", "b.co.za", "c.co.za", "d.co.za"])


class CTTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def run_ct(self, reply):
        transport = FakeTransport({"ct.test": reply})
        zaenum.http_get = transport
        state = {}
        hosts = zaenum.ct_hosts("co.za", state, args())
        return hosts, state, transport

    def test_parses_certificates_and_marks_complete(self):
        payload = [{"name_value": "www.a.co.za\n*.b.co.za", "common_name": "a.co.za"},
                   {"name_value": "outside.example.com", "common_name": ""}]
        hosts, state, _ = self.run_ct((200, json.dumps(payload).encode()))
        self.assertEqual(hosts, ["a.co.za", "b.co.za", "www.a.co.za"])
        self.assertTrue(state["ct"]["co.za"]["complete"])

    def test_502_is_not_completion(self):
        hosts, state, _ = self.run_ct((502, b"<html>bad gateway</html>"))
        self.assertEqual(hosts, [])
        self.assertFalse(state.get("ct", {}).get("co.za", {}).get("complete", False))

    def test_genuinely_empty_result_marks_complete(self):
        hosts, state, _ = self.run_ct((200, b"[]"))
        self.assertEqual(hosts, [])
        self.assertTrue(state["ct"]["co.za"]["complete"])

    def test_html_error_body_is_not_completion(self):
        hosts, state, _ = self.run_ct((200, b"<html>maintenance</html>"))
        self.assertEqual(hosts, [])
        self.assertFalse(state.get("ct", {}).get("co.za", {}).get("complete", False))


class CCTests(unittest.TestCase):
    def test_pagination_stop_and_resume(self):
        page0 = (200, b'{"url": "https://a.law.za/x"}\n{"url": "https://b.law.za/y"}\n')
        page1_fail = (504, b"gateway timeout")
        page2 = (200, b'{"url": "https://c.law.za/z"}\n{"url": "https://evil.example.com/q"}\n')

        routes = {
            "showNumPages=true": (200, b'{"pages": 3}'),
            "&page=0": page0,
            "&page=1": page1_fail,
            "&page=2": page2,
        }
        transport = FakeTransport(routes)
        zaenum.http_get = transport
        state = {}

        # First run: page 0 succeeds, page 1 fails, cursor must stop at 1.
        hosts = zaenum.cc_hosts("law.za", state, args(), "CC-TEST")
        self.assertEqual(hosts, ["a.law.za", "b.law.za"])
        self.assertEqual(state["cc"]["law.za"]["next_page"], 1)
        self.assertFalse(state["cc"]["law.za"].get("complete"))

        # Second run: page 1 now answers, walk finishes, no duplicate work.
        routes["&page=1"] = (200, b'{"url": "https://b2.law.za/w"}\n')
        hosts = zaenum.cc_hosts("law.za", state, args(), "CC-TEST")
        self.assertEqual(hosts, ["b2.law.za", "c.law.za"])
        self.assertTrue(state["cc"]["law.za"]["complete"])
        self.assertEqual(state["cc"]["law.za"]["next_page"], 3)
        page_zero_calls = [u for u in transport.calls if "&page=0" in u]
        self.assertEqual(len(page_zero_calls), 1, "page 0 must not be re-fetched")

    def test_new_crawl_restarts_the_zone(self):
        transport = FakeTransport({"showNumPages=true": (200, b'{"pages": 1}'),
                                   "&page=0": (200, b'{"url": "https://a.law.za"}\n')})
        zaenum.http_get = transport
        state = {"cc": {"law.za": {"collection": "CC-OLD", "next_page": 9, "complete": True}}}
        hosts = zaenum.cc_hosts("law.za", state, args(), "CC-NEW")
        self.assertEqual(hosts, ["a.law.za"])
        self.assertEqual(state["cc"]["law.za"]["collection"], "CC-NEW")

    def test_no_captures_marks_complete(self):
        transport = FakeTransport({"showNumPages=true": (200, b"No Captures found for: *.law.za")})
        zaenum.http_get = transport
        state = {}
        self.assertEqual(zaenum.cc_hosts("law.za", state, args(), "CC-TEST"), [])
        self.assertTrue(state["cc"]["law.za"]["complete"])

    def test_unreachable_index_stays_resumable(self):
        transport = FakeTransport({"showNumPages=true": (504, b"timeout")})
        zaenum.http_get = transport
        state = {}
        self.assertEqual(zaenum.cc_hosts("law.za", state, args(), "CC-TEST"), [])
        self.assertFalse(state["cc"]["law.za"].get("complete"))


class CdnTests(unittest.TestCase):
    def test_header_fingerprints(self):
        self.assertEqual(zaenum.provider_from_headers({"CF-RAY": "8a1b-LHR"})[0], "Cloudflare")
        self.assertEqual(zaenum.provider_from_headers({"x-amz-cf-id": "x"})[0], "Amazon CloudFront")
        self.assertEqual(zaenum.provider_from_headers({"X-Fastly-Request-ID": "t"})[0], "Fastly")
        self.assertEqual(zaenum.provider_from_headers({"server": "cloudflare"})[0], "Cloudflare")
        self.assertEqual(
            zaenum.provider_from_headers({"via": "1.1 abc.cloudfront.net (CloudFront)"})[0],
            "Amazon CloudFront")
        self.assertIsNone(zaenum.provider_from_headers({"server": "nginx"})[0])

    def test_cname_fingerprints(self):
        self.assertEqual(zaenum.provider_from_cname("d123.cloudfront.net")[0], "Amazon CloudFront")
        self.assertEqual(zaenum.provider_from_cname("e1.akamaiedge.net")[0], "Akamai")
        self.assertEqual(zaenum.provider_from_cname("x.cloudflare.net")[0], "Cloudflare")
        self.assertIsNone(zaenum.provider_from_cname("example.com")[0])

    def test_range_lookup(self):
        import ipaddress
        ranges = zaenum.CdnRanges([
            zaenum._cidr_entry("104.16.0.0/13", "Cloudflare"),
            zaenum._cidr_entry("13.32.0.0/15", "Amazon CloudFront"),
        ])
        self.assertEqual(ranges.lookup(int(ipaddress.ip_address("104.16.5.5"))), "Cloudflare")
        self.assertEqual(ranges.lookup(int(ipaddress.ip_address("13.32.1.1"))), "Amazon CloudFront")
        self.assertIsNone(ranges.lookup(int(ipaddress.ip_address("8.8.8.8"))))

    def test_parse_ranges_handles_each_feed_format(self):
        text = zaenum.parse_ranges("Cloudflare", b"104.16.0.0/13\n172.64.0.0/13\n", "text")
        self.assertEqual(len(text), 2)

        fastly = zaenum.parse_ranges("Fastly",
                                     json.dumps({"addresses": ["151.101.0.0/16"]}).encode(),
                                     "json-fastly")
        self.assertEqual(len(fastly), 1)

        aws = zaenum.parse_ranges("Amazon CloudFront", json.dumps({"prefixes": [
            {"service": "CLOUDFRONT", "ip_prefix": "13.32.0.0/15"},
            {"service": "EC2", "ip_prefix": "3.0.0.0/8"},
        ]}).encode(), "json-aws")
        self.assertEqual(len(aws), 1, "non-CloudFront AWS prefixes must be ignored")

        google = zaenum.parse_ranges("Google", json.dumps({"prefixes": [
            {"ipv4Prefix": "142.250.0.0/15"},
            {"ipv6Prefix": "2001:4860::/32"},
        ]}).encode(), "json-google")
        self.assertEqual(len(google), 1)


class StoreTests(unittest.TestCase):
    def test_dedupes_across_runs_and_sorts(self):
        tmp = tempfile.mkdtemp()
        store = zaenum.Store(tmp)
        self.assertEqual(store.add("law.za", ["b.law.za", "a.law.za", "a.law.za"]), 2)
        store.finalize("law.za")

        again = zaenum.Store(tmp)
        self.assertEqual(again.load("law.za"), 2)
        self.assertEqual(again.add("law.za", ["a.law.za", "c.law.za"]), 1)
        again.finalize("law.za")
        with open(os.path.join(tmp, "law.za.hosts.txt")) as handle:
            self.assertEqual(handle.read().split(), ["a.law.za", "b.law.za", "c.law.za"])


class DiscoverTests(unittest.TestCase):
    """The Exa-backed discovery step, with the client faked out."""

    def test_reduces_pages_to_their_zone(self):
        self.assertEqual(zaenum.zone_from_host("www.news24.com"), "news24.com")
        self.assertEqual(zaenum.zone_from_host("unisa.ac.za"), "unisa.ac.za")
        self.assertEqual(zaenum.zone_from_host("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(zaenum.zone_from_host("a.b.zaenum.example.com"), "example.com")
        self.assertIsNone(zaenum.zone_from_host("localhost"))

    def test_zones_from_results_dedupe_in_order(self):
        results = [
            {"url": "https://www.unisa.ac.za/news"},
            {"url": "https://unisa.ac.za/about"},
            {"url": "https://www.uct.ac.za/"},
            {"url": ""},
        ]
        self.assertEqual(zaenum.zones_from_results(results),
                         ["unisa.ac.za", "uct.ac.za"])

    def test_discover_saves_results_and_reports_zones(self):
        tmp = tempfile.mkdtemp()
        fake = types.ModuleType("exa_search")
        fake.search = lambda query, num_results=5: [
            {"title": "Unisa", "url": "https://www.unisa.ac.za/",
             "published_date": "2024-01-02", "author": None,
             "highlights": ["University of South Africa"]},
        ]
        saved = sys.modules.get("exa_search")
        sys.modules["exa_search"] = fake
        try:
            zones = zaenum.discover("south african universities", 3, tmp)
        finally:
            if saved is None:
                del sys.modules["exa_search"]
            else:
                sys.modules["exa_search"] = saved

        self.assertEqual(zones, ["unisa.ac.za"])
        with open(os.path.join(tmp, "exa-south-african-universities.json")) as handle:
            payload = json.load(handle)
        self.assertEqual(payload["query"], "south african universities")
        self.assertEqual(payload["results"][0]["url"], "https://www.unisa.ac.za/")
        self.assertEqual(payload["results"][0]["highlights"],
                         ["University of South Africa"])

    def test_discover_without_exa_py_explains_the_install(self):
        tmp = tempfile.mkdtemp()
        saved = sys.modules.get("exa_search")
        sys.modules["exa_search"] = None  # import raises ImportError
        try:
            with self.assertRaises(RuntimeError) as caught:
                zaenum.discover("anything", 1, tmp)
        finally:
            if saved is None:
                del sys.modules["exa_search"]
            else:
                sys.modules["exa_search"] = saved
        self.assertIn("requirements.txt", str(caught.exception))


class MenuTests(unittest.TestCase):
    """The console must build exactly the argv the flag interface documents."""

    def test_plain_selection_maps_to_enumerate_flags(self):
        argv = zaenum.menu_command("1", "co.za")
        self.assertEqual(argv[:2], ["--sld", "co.za"])
        self.assertIn("--out", argv)
        self.assertNotIn("--cdn", argv)

    def test_zone_is_normalised(self):
        self.assertEqual(zaenum.menu_command("2", "  .Example.COM. ")[:2],
                         ["--sld", "example.com"])

    def test_all_slds_needs_no_zone(self):
        self.assertEqual(zaenum.menu_command("3")[:2], ["--sld", "all"])

    def test_cdn_only_and_full_sweep_differ_by_one_flag(self):
        only = zaenum.menu_command("4", "example.com")
        sweep = zaenum.menu_command("5", "example.com")
        self.assertIn("--cdn-only", only)
        self.assertNotIn("--cdn", only)
        self.assertIn("--cdn", sweep)
        self.assertNotIn("--cdn-only", sweep)
        self.assertEqual([a for a in sweep if a.startswith("--cdn")],
                         ["--cdn", "--cdn-workers"])

    def test_discover_passes_the_query_through(self):
        argv = zaenum.menu_command("6", "  south african banks ")
        self.assertEqual(argv[:2], ["--discover", "south african banks"])
        self.assertIn("--discover-results", argv)

    def test_resolve_selection(self):
        self.assertIn("--resolve", zaenum.menu_command("7", "law.za"))

    def test_settings_reach_the_command_line(self):
        argv = zaenum.menu_command("1", "co.za", {"out": "runs/za", "delay": 2.5,
                                                   "max_hosts": 250})
        self.assertEqual(argv[argv.index("--out") + 1], "runs/za")
        self.assertEqual(argv[argv.index("--delay") + 1], "2.5")
        self.assertEqual(argv[argv.index("--max-hosts") + 1], "250")

    def test_in_process_choices_return_none(self):
        for choice in ("0", "8", "9", "10"):
            self.assertIsNone(zaenum.menu_command(choice))

    def test_bad_input_is_rejected_not_guessed(self):
        with self.assertRaises(ValueError):
            zaenum.menu_command("1", "")
        with self.assertRaises(ValueError):
            zaenum.menu_command("1", "not a host")
        with self.assertRaises(ValueError):
            zaenum.menu_command("6", "   ")
        with self.assertRaises(ValueError):
            zaenum.menu_command("99")

    def test_setting_coercion(self):
        self.assertEqual(zaenum.coerce_setting("delay", "0.5"), 0.5)
        self.assertEqual(zaenum.coerce_setting("retries", "3"), 3)
        self.assertEqual(zaenum.coerce_setting("out", "runs/za"), "runs/za")
        for key, raw in (("retries", "0"), ("delay", "-1"), ("cdn_workers", "many"),
                         ("out", ""), ("max_hosts", "1e9"), ("nope", "1")):
            with self.assertRaises(ValueError, msg=f"{key}={raw!r}"):
                zaenum.coerce_setting(key, raw)

    def test_colour_can_be_disabled(self):
        class FakeTty:
            def isatty(self):
                return True

        self.assertEqual(zaenum.palette(FakeTty())["green"], "\033[38;5;46m")
        saved = os.environ.get("NO_COLOR")
        os.environ["NO_COLOR"] = "1"
        try:
            self.assertEqual(zaenum.palette(FakeTty())["green"], "")
        finally:
            if saved is None:
                os.environ.pop("NO_COLOR", None)
            else:
                os.environ["NO_COLOR"] = saved

    def test_plain_stream_gets_no_escape_codes(self):
        class NotATty:
            def isatty(self):
                return False

        self.assertEqual(set(zaenum.palette(NotATty()).values()), {""})

    def test_banner_lines_are_the_same_width(self):
        self.assertEqual(len({len(line) for line in zaenum.WORDMARK}), 1)
        for letter, rows in zaenum.GLYPHS.items():
            self.assertEqual(len({len(row) for row in rows}), 1, f"glyph {letter} is ragged")
            self.assertEqual(len(rows), 3, f"glyph {letter} is not three rows")

    def test_menu_labels_stay_aligned(self):
        self.assertLessEqual(max(len(label) for _, label, _ in zaenum.MENU_ITEMS), 26)


if __name__ == "__main__":
    unittest.main(verbosity=2)
