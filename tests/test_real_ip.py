"""
Tests for modules/real_ip.py — comprehensive coverage of all seven techniques.
"""

import asyncio
import datetime
import sys
from pathlib import Path
from unittest.mock import patch, AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.real_ip import (
    is_cdn_ip,
    _valid_public_ip,
    _extract_ips,
    _filter_ips,
    _strip_tags,
    _date_confidence,
    _extract_title,
    _body_hash,
    _blank_entry,
    _method_viewdns_history,
    _method_crimeflare,
    _method_crtsh,
    _method_subdomain_dns,
    _shodan_verify,
    _http_matches_site,
    _get_site_fingerprint,
    run_real_ip_discovery,
)


# ══════════════════════════════════════════════════════════════════════════════
# Pure-function unit tests (no I/O)
# ══════════════════════════════════════════════════════════════════════════════

class TestIsCdnIp:
    def test_cloudflare_104(self):
        assert is_cdn_ip("104.16.1.2")
        assert is_cdn_ip("104.31.255.1")

    def test_cloudflare_172(self):
        assert is_cdn_ip("172.64.0.1")
        assert is_cdn_ip("172.71.99.9")

    def test_cloudflare_misc(self):
        assert is_cdn_ip("188.114.96.1")
        assert is_cdn_ip("162.158.0.1")
        assert is_cdn_ip("141.101.64.1")

    def test_akamai(self):
        assert is_cdn_ip("23.32.100.1")
        assert is_cdn_ip("23.192.5.10")
        assert is_cdn_ip("23.223.1.1")

    def test_fastly(self):
        assert is_cdn_ip("151.101.0.1")
        assert is_cdn_ip("199.232.0.1")

    def test_aws_cloudfront(self):
        assert is_cdn_ip("52.84.1.1")
        assert is_cdn_ip("54.182.0.1")

    def test_imperva(self):
        assert is_cdn_ip("45.60.1.1")

    def test_non_cdn(self):
        assert not is_cdn_ip("1.2.3.4")
        assert not is_cdn_ip("85.132.10.5")
        assert not is_cdn_ip("203.0.113.1")
        assert not is_cdn_ip("8.8.8.8")

    def test_empty_and_none(self):
        assert not is_cdn_ip("")
        assert not is_cdn_ip(None)


class TestValidPublicIp:
    def test_valid_public(self):
        assert _valid_public_ip("1.2.3.4")
        assert _valid_public_ip("85.132.10.5")
        assert _valid_public_ip("203.0.113.50")
        assert _valid_public_ip("8.8.8.8")

    def test_private_rfc1918(self):
        assert not _valid_public_ip("10.0.0.1")
        assert not _valid_public_ip("192.168.1.1")
        assert not _valid_public_ip("172.16.0.1")
        assert not _valid_public_ip("172.31.255.255")

    def test_loopback_and_special(self):
        assert not _valid_public_ip("127.0.0.1")
        assert not _valid_public_ip("0.0.0.0")
        assert not _valid_public_ip("169.254.1.1")  # link-local
        assert not _valid_public_ip("255.255.255.255")

    def test_multicast(self):
        assert not _valid_public_ip("224.0.0.1")
        assert not _valid_public_ip("239.255.255.255")

    def test_garbage(self):
        assert not _valid_public_ip("not-an-ip")
        assert not _valid_public_ip("")
        assert not _valid_public_ip("999.1.2.3")
        assert not _valid_public_ip("1.2.3")
        assert not _valid_public_ip(None)


class TestExtractIps:
    def test_basic(self):
        ips = _extract_ips("Text with 1.2.3.4 and 10.20.30.40")
        assert "1.2.3.4" in ips
        assert "10.20.30.40" in ips

    def test_in_html_table(self):
        html = "<td>85.132.10.5</td><td>104.16.1.1</td>"
        ips = _extract_ips(html)
        assert "85.132.10.5" in ips
        assert "104.16.1.1" in ips

    def test_empty_and_none(self):
        assert _extract_ips("") == []
        assert _extract_ips(None) == []

    def test_no_ips(self):
        assert _extract_ips("no addresses here") == []


class TestFilterIps:
    def test_removes_cdn(self):
        assert "104.16.1.1" not in _filter_ips(["104.16.1.1"])

    def test_removes_private(self):
        assert "10.0.0.1" not in _filter_ips(["10.0.0.1"])

    def test_keeps_public_non_cdn(self):
        result = _filter_ips(["1.2.3.4", "104.16.1.1", "10.0.0.1", "85.132.10.5"])
        assert "1.2.3.4" in result
        assert "85.132.10.5" in result
        assert len(result) == 2


class TestStripTags:
    def test_removes_tags(self):
        assert _strip_tags("<b>hello</b>") == "hello"

    def test_flag_image_and_text(self):
        result = _strip_tags('<img src="flags/az.png"> Azerbaijan')
        assert result == "Azerbaijan"

    def test_entities(self):
        assert "&amp;" not in _strip_tags("A &amp; B")
        assert "&nbsp;" not in _strip_tags("A&nbsp;B")

    def test_empty(self):
        assert _strip_tags("") == ""
        assert _strip_tags(None) == ""


class TestDateConfidence:
    def _ago(self, days: int) -> str:
        return (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")

    def test_recent_is_high(self):
        assert _date_confidence(self._ago(30)) == "high"

    def test_moderate_is_medium(self):
        assert _date_confidence(self._ago(200)) == "medium"

    def test_old_is_low(self):
        assert _date_confidence(self._ago(500)) == "low"

    def test_empty_is_low(self):
        assert _date_confidence("") == "low"
        assert _date_confidence(None) == "low"

    def test_invalid_is_low(self):
        assert _date_confidence("not-a-date") == "low"

    def test_alternate_formats(self):
        # "15 Jan 2020" — definitely old
        assert _date_confidence("15 Jan 2020") == "low"


class TestExtractTitle:
    def test_basic(self):
        assert _extract_title("<html><title>Hello World</title></html>") == "Hello World"

    def test_with_tags_inside(self):
        assert _extract_title("<title><b>Bold Title</b></title>") == "Bold Title"

    def test_no_title(self):
        assert _extract_title("<html><body>no title</body></html>") == ""

    def test_empty(self):
        assert _extract_title("") == ""


class TestBodyHash:
    def test_consistent(self):
        html = "<html><body><p>Hello World</p></body></html>"
        assert _body_hash(html) == _body_hash(html)

    def test_different_content(self):
        assert _body_hash("<p>Page A</p>") != _body_hash("<p>Page B</p>")

    def test_empty(self):
        result = _body_hash("")
        assert isinstance(result, str) and len(result) == 32  # MD5 hex

    def test_strips_tags_before_hashing(self):
        # Same text content but different markup → same hash
        a = "<b><i>same text</i></b>"
        b = "<span>same text</span>"
        assert _body_hash(a) == _body_hash(b)


# ══════════════════════════════════════════════════════════════════════════════
# Discovery method tests (mocked I/O)
# ══════════════════════════════════════════════════════════════════════════════

# ── ViewDNS history ───────────────────────────────────────────────────────────

_VIEWDNS_HTML = """
<html><body>
<table border="1">
<tr><td>IP Address</td><td>Location</td><td>Owner</td><td>Last seen</td></tr>
<tr>
  <td>85.132.10.5</td>
  <td><img src="flags/az.png"> Azerbaijan</td>
  <td>Delta Telecom</td>
  <td>2026-01-01</td>
</tr>
<tr>
  <td>104.16.1.1</td>
  <td>United States</td>
  <td>Cloudflare</td>
  <td>2025-12-01</td>
</tr>
<tr>
  <td>203.0.113.99</td>
  <td>Germany</td>
  <td>Some ISP</td>
  <td>2024-01-15</td>
</tr>
</table>
</body></html>
"""


@pytest.mark.asyncio
async def test_viewdns_history_parses_table():
    with patch("modules.real_ip._fetch_get", return_value=_VIEWDNS_HTML):
        results = await _method_viewdns_history("example.com")
    ips = [r["ip"] for r in results]
    assert "85.132.10.5" in ips
    assert "203.0.113.99" in ips


@pytest.mark.asyncio
async def test_viewdns_history_excludes_cdn():
    with patch("modules.real_ip._fetch_get", return_value=_VIEWDNS_HTML):
        results = await _method_viewdns_history("example.com")
    assert "104.16.1.1" not in [r["ip"] for r in results]


@pytest.mark.asyncio
async def test_viewdns_history_populates_country_and_last_seen():
    with patch("modules.real_ip._fetch_get", return_value=_VIEWDNS_HTML):
        results = await _method_viewdns_history("example.com")
    az = next(r for r in results if r["ip"] == "85.132.10.5")
    assert "Azerbaijan" in az["country"]
    assert az["last_seen"] == "2026-01-01"


@pytest.mark.asyncio
async def test_viewdns_history_recency_confidence():
    # 2026-01-01 is < 90 days from 2026-04-27 (116 days) - actually that's medium
    # Let me use a very recent date by generating it dynamically
    today = datetime.datetime.now()
    recent = (today - datetime.timedelta(days=10)).strftime("%Y-%m-%d")
    old    = (today - datetime.timedelta(days=600)).strftime("%Y-%m-%d")
    html = f"""
    <table><tr><td>IP Address</td><td>Loc</td><td>Own</td><td>Last seen</td></tr>
    <tr><td>85.132.10.5</td><td>AZ</td><td>ISP</td><td>{recent}</td></tr>
    <tr><td>1.2.3.4</td><td>DE</td><td>ISP</td><td>{old}</td></tr>
    </table>"""
    with patch("modules.real_ip._fetch_get", return_value=html):
        results = await _method_viewdns_history("example.com")
    by_ip = {r["ip"]: r for r in results}
    assert by_ip["85.132.10.5"]["confidence"] == "high"
    assert by_ip["1.2.3.4"]["confidence"] == "low"


@pytest.mark.asyncio
async def test_viewdns_history_empty_response():
    with patch("modules.real_ip._fetch_get", return_value=""):
        results = await _method_viewdns_history("example.com")
    assert results == []


# ── CrimeFlare ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_crimeflare_found():
    with patch("modules.real_ip._fetch_post", return_value="Found: ip=85.132.10.5"):
        results = await _method_crimeflare("example.com")
    assert len(results) == 1
    assert results[0]["ip"] == "85.132.10.5"
    assert results[0]["confidence"] == "high"
    assert results[0]["method"] == "crimeflare"


@pytest.mark.asyncio
async def test_crimeflare_cdn_ip_excluded():
    with patch("modules.real_ip._fetch_post", return_value="ip=104.16.1.1"):
        results = await _method_crimeflare("example.com")
    assert results == []


@pytest.mark.asyncio
async def test_crimeflare_no_response():
    with patch("modules.real_ip._fetch_post", return_value=""):
        results = await _method_crimeflare("example.com")
    assert results == []


# ── crt.sh ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_crtsh_extracts_ip_sans():
    fake_json = [{"common_name": "example.com", "name_value": "85.132.10.5"}]
    with patch("modules.real_ip._fetch_json", return_value=fake_json):
        results = await _method_crtsh("example.com")
    assert any(r["ip"] == "85.132.10.5" for r in results)
    assert all(r["method"] == "crtsh" for r in results)


@pytest.mark.asyncio
async def test_crtsh_no_ips_in_json():
    fake_json = [{"common_name": "example.com", "name_value": "www.example.com"}]
    with patch("modules.real_ip._fetch_json", return_value=fake_json):
        results = await _method_crtsh("example.com")
    assert results == []


@pytest.mark.asyncio
async def test_crtsh_invalid_response():
    with patch("modules.real_ip._fetch_json", return_value=None):
        results = await _method_crtsh("example.com")
    assert results == []


# ── Subdomain DNS ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_subdomain_dns_resolves_non_cdn():
    fingerprint = {"title": "My Site", "body_hash": "abc123", "proto": "https"}

    def fake_resolve(hostname):
        return ["85.132.10.5"] if "mail." in hostname else []

    with patch("modules.real_ip._dns_resolve", side_effect=fake_resolve), \
         patch("modules.real_ip._http_matches_site", return_value=False):
        results = await _method_subdomain_dns("example.com", fingerprint)

    assert any(r["ip"] == "85.132.10.5" for r in results)
    assert any(r["method"] == "subdomain:mail" for r in results)


@pytest.mark.asyncio
async def test_subdomain_dns_filters_cdn():
    def fake_resolve(hostname):
        return ["104.16.1.1"]  # CDN IP

    with patch("modules.real_ip._dns_resolve", side_effect=fake_resolve), \
         patch("modules.real_ip._http_matches_site", return_value=False):
        results = await _method_subdomain_dns("example.com", {})

    assert results == []


@pytest.mark.asyncio
async def test_subdomain_dns_verified_inline():
    """When HTTP match succeeds, confidence should be 'confirmed'."""
    def fake_resolve(hostname):
        return ["85.132.10.5"] if "direct." in hostname else []

    with patch("modules.real_ip._dns_resolve", side_effect=fake_resolve), \
         patch("modules.real_ip._http_matches_site", return_value=True):
        results = await _method_subdomain_dns("example.com", {"title": "Test"})

    confirmed = [r for r in results if r["ip"] == "85.132.10.5"]
    assert confirmed
    assert confirmed[0]["confidence"] == "confirmed"
    assert confirmed[0]["verified"] is True


# ══════════════════════════════════════════════════════════════════════════════
# Verification helper tests
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_shodan_verify_matches():
    fake_data = {"ip": "85.132.10.5", "hostnames": ["dim.gov.az", "www.dim.gov.az"]}
    with patch("modules.real_ip._fetch_json", return_value=fake_data):
        assert await _shodan_verify("85.132.10.5", "dim.gov.az") is True


@pytest.mark.asyncio
async def test_shodan_verify_no_match():
    fake_data = {"ip": "1.2.3.4", "hostnames": ["unrelated.com"]}
    with patch("modules.real_ip._fetch_json", return_value=fake_data):
        assert await _shodan_verify("1.2.3.4", "example.com") is False


@pytest.mark.asyncio
async def test_shodan_verify_empty_hostnames():
    with patch("modules.real_ip._fetch_json", return_value={"hostnames": []}):
        assert await _shodan_verify("1.2.3.4", "example.com") is False


@pytest.mark.asyncio
async def test_shodan_verify_null_response():
    with patch("modules.real_ip._fetch_json", return_value=None):
        assert await _shodan_verify("1.2.3.4", "example.com") is False


@pytest.mark.asyncio
async def test_http_matches_site_by_title():
    fp = {"title": "My Site Title", "body_hash": "aaaa", "proto": "https"}
    html = "<html><head><title>My Site Title</title></head></html>"
    with patch("modules.real_ip._fetch_get", return_value=html):
        assert await _http_matches_site("85.132.10.5", "example.com", fp) is True


@pytest.mark.asyncio
async def test_http_matches_site_by_body_hash():
    content = "<html><body><p>Unique content here 12345</p></body></html>"
    fp = {"title": "", "body_hash": _body_hash(content), "proto": "https"}
    with patch("modules.real_ip._fetch_get", return_value=content):
        assert await _http_matches_site("85.132.10.5", "example.com", fp) is True


@pytest.mark.asyncio
async def test_http_matches_site_no_match():
    fp = {"title": "Expected Title", "body_hash": "expected_hash", "proto": "https"}
    other_html = "<html><title>Different Title</title><body>Other content</body></html>"
    with patch("modules.real_ip._fetch_get", return_value=other_html):
        assert await _http_matches_site("1.2.3.4", "example.com", fp) is False


@pytest.mark.asyncio
async def test_http_matches_site_empty_fingerprint():
    with patch("modules.real_ip._fetch_get", return_value="<title>X</title>"):
        assert await _http_matches_site("1.2.3.4", "example.com", {}) is False


@pytest.mark.asyncio
async def test_get_site_fingerprint():
    html = "<html><head><title>Test Site</title></head><body>Hello</body></html>"
    with patch("modules.real_ip._fetch_get", return_value=html):
        fp = await _get_site_fingerprint("example.com")
    assert fp["title"] == "Test Site"
    assert len(fp["body_hash"]) == 32
    assert fp["proto"] in ("https", "http")


@pytest.mark.asyncio
async def test_get_site_fingerprint_all_fail():
    with patch("modules.real_ip._fetch_get", return_value=""):
        fp = await _get_site_fingerprint("example.com")
    assert fp == {}


# ══════════════════════════════════════════════════════════════════════════════
# Full-pipeline integration tests
# ══════════════════════════════════════════════════════════════════════════════

_TODAY = datetime.datetime.now()
_RECENT_DATE = (_TODAY - datetime.timedelta(days=20)).strftime("%Y-%m-%d")

_VIEWDNS_RECENT = f"""
<table><tr><td>IP Address</td><td>Location</td><td>Owner</td><td>Last seen</td></tr>
<tr><td>85.132.10.5</td><td>Azerbaijan</td><td>Delta</td><td>{_RECENT_DATE}</td></tr>
<tr><td>104.16.1.1</td><td>US</td><td>CF</td><td>{_RECENT_DATE}</td></tr>
</table>"""

_SITE_HTML = "<html><title>Gov Portal</title><body>Official content here</body></html>"


@pytest.mark.asyncio
async def test_full_pipeline_basic():
    """Core: non-CDN IP from ViewDNS appears in results; CDN is excluded."""
    async def fake_fetch_get(url, **kwargs):
        if "viewdns.info/iphistory" in url:
            return _VIEWDNS_RECENT
        if "example.com" in url:
            return _SITE_HTML
        return ""

    with patch("modules.real_ip._fetch_get", side_effect=fake_fetch_get), \
         patch("modules.real_ip._fetch_post", return_value=""), \
         patch("modules.real_ip._fetch_json", return_value=None), \
         patch("modules.real_ip._dns_resolve", return_value=[]):
        results = await run_real_ip_discovery("example.com")

    ips = [r["ip"] for r in results]
    assert "85.132.10.5" in ips
    assert "104.16.1.1" not in ips


@pytest.mark.asyncio
async def test_full_pipeline_no_results():
    """Returns empty list when all discovered IPs are CDN."""
    with patch("modules.real_ip._fetch_get",
               return_value="<body>104.16.1.1 172.67.0.1</body>"), \
         patch("modules.real_ip._fetch_post", return_value="104.16.1.1"), \
         patch("modules.real_ip._fetch_json", return_value=None), \
         patch("modules.real_ip._dns_resolve", return_value=["172.67.0.1"]):
        results = await run_real_ip_discovery("cf-site.com")

    assert results == []


@pytest.mark.asyncio
async def test_full_pipeline_dedup_keeps_highest_confidence():
    """Same IP from CrimeFlare (high) and crt.sh (medium) → keep high."""
    crimeflare_html = "ip=85.132.10.5"
    crtsh_json = [{"name_value": "85.132.10.5"}]

    async def fake_fetch_get(url, **kwargs):
        return ""

    with patch("modules.real_ip._fetch_get", side_effect=fake_fetch_get), \
         patch("modules.real_ip._fetch_post", return_value=crimeflare_html), \
         patch("modules.real_ip._fetch_json", return_value=crtsh_json), \
         patch("modules.real_ip._dns_resolve", return_value=[]):
        results = await run_real_ip_discovery("example.com")

    matches = [r for r in results if r["ip"] == "85.132.10.5"]
    assert len(matches) == 1
    assert matches[0]["confidence"] in ("high", "confirmed")  # dedup kept higher


@pytest.mark.asyncio
async def test_full_pipeline_http_verification_upgrades_to_confirmed():
    """IP that passes HTTP fingerprint match must have confidence='confirmed'."""
    site_html = "<html><title>Real Site</title><body>content</body></html>"
    viewdns_html = f"""
    <table><tr><td>IP</td><td>L</td><td>O</td><td>Last seen</td></tr>
    <tr><td>85.132.10.5</td><td>AZ</td><td>ISP</td><td>{_RECENT_DATE}</td></tr>
    </table>"""

    call_count = {"n": 0}

    async def fake_fetch_get(url, **kwargs):
        call_count["n"] += 1
        if "viewdns.info/iphistory" in url:
            return viewdns_html
        return site_html  # fingerprint + verification both return same content

    with patch("modules.real_ip._fetch_get", side_effect=fake_fetch_get), \
         patch("modules.real_ip._fetch_post", return_value=""), \
         patch("modules.real_ip._fetch_json", return_value=None), \
         patch("modules.real_ip._dns_resolve", return_value=[]):
        results = await run_real_ip_discovery("example.com")

    match = next((r for r in results if r["ip"] == "85.132.10.5"), None)
    assert match is not None
    assert match["confidence"] == "confirmed"
    assert match["verified"] is True


@pytest.mark.asyncio
async def test_full_pipeline_shodan_upgrades_confidence():
    """IP confirmed by Shodan gets verified=True and confidence≥high."""
    viewdns_html = f"""
    <table><tr><td>IP</td><td>L</td><td>O</td><td>Last seen</td></tr>
    <tr><td>85.132.10.5</td><td>AZ</td><td>ISP</td><td>2024-01-01</td></tr>
    </table>"""

    shodan_resp = {"ip": "85.132.10.5", "hostnames": ["example.com"]}

    async def fake_fetch_get(url, **kwargs):
        if "viewdns.info/iphistory" in url:
            return viewdns_html
        return ""

    with patch("modules.real_ip._fetch_get", side_effect=fake_fetch_get), \
         patch("modules.real_ip._fetch_post", return_value=""), \
         patch("modules.real_ip._fetch_json", return_value=shodan_resp), \
         patch("modules.real_ip._dns_resolve", return_value=[]):
        results = await run_real_ip_discovery("example.com")

    match = next((r for r in results if r["ip"] == "85.132.10.5"), None)
    assert match is not None
    assert match["verified"] is True
    assert match["confidence"] in ("high", "confirmed")


@pytest.mark.asyncio
async def test_full_pipeline_sorted_confirmed_first():
    """confirmed entries must appear before high/medium/low entries."""
    site_html = "<html><title>My Site</title><body>unique body 99999</body></html>"
    viewdns_html = f"""
    <table><tr><td>IP</td><td>L</td><td>O</td><td>Last seen</td></tr>
    <tr><td>85.132.10.5</td><td>AZ</td><td>ISP</td><td>{_RECENT_DATE}</td></tr>
    <tr><td>203.0.113.1</td><td>DE</td><td>ISP2</td><td>2020-01-01</td></tr>
    </table>"""

    call_urls: list[str] = []

    async def fake_fetch_get(url, **kwargs):
        call_urls.append(url)
        if "viewdns.info/iphistory" in url:
            return viewdns_html
        return site_html  # all other fetches (fingerprint + verification) match

    with patch("modules.real_ip._fetch_get", side_effect=fake_fetch_get), \
         patch("modules.real_ip._fetch_post", return_value=""), \
         patch("modules.real_ip._fetch_json", return_value=None), \
         patch("modules.real_ip._dns_resolve", return_value=[]):
        results = await run_real_ip_discovery("example.com")

    assert results, "Expected at least one result"
    order = {"confirmed": 0, "high": 1, "medium": 2, "low": 3}
    confs = [r["confidence"] for r in results]
    assert confs == sorted(confs, key=lambda c: order.get(c, 9))


@pytest.mark.asyncio
async def test_full_pipeline_result_schema():
    """Every result must have all required keys with correct types."""
    viewdns_html = f"""
    <table><tr><td>IP</td><td>Loc</td><td>Own</td><td>Last seen</td></tr>
    <tr><td>85.132.10.5</td><td>AZ</td><td>ISP</td><td>{_RECENT_DATE}</td></tr>
    </table>"""

    async def fake_fetch_get(url, **kwargs):
        return viewdns_html if "viewdns" in url else ""

    with patch("modules.real_ip._fetch_get", side_effect=fake_fetch_get), \
         patch("modules.real_ip._fetch_post", return_value=""), \
         patch("modules.real_ip._fetch_json", return_value=None), \
         patch("modules.real_ip._dns_resolve", return_value=[]):
        results = await run_real_ip_discovery("example.com")

    for r in results:
        assert "ip"         in r and isinstance(r["ip"],         str)
        assert "method"     in r and isinstance(r["method"],     str)
        assert "confidence" in r and r["confidence"] in ("confirmed","high","medium","low")
        assert "country"    in r and isinstance(r["country"],    str)
        assert "last_seen"  in r and isinstance(r["last_seen"],  str)
        assert "verified"   in r and isinstance(r["verified"],   bool)
