"""
Tests for modules/real_ip.py
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.real_ip import (
    is_cdn_ip,
    _valid_public_ip,
    _extract_ips,
    _filter_ips,
    run_real_ip_discovery,
)


# ── is_cdn_ip ─────────────────────────────────────────────────────────────────

def test_cdn_ip_cloudflare():
    assert is_cdn_ip("104.16.1.2")
    assert is_cdn_ip("172.67.0.1")
    assert is_cdn_ip("188.114.96.1")
    assert is_cdn_ip("162.158.0.1")

def test_cdn_ip_akamai():
    assert is_cdn_ip("23.32.100.1")
    assert is_cdn_ip("23.192.5.10")

def test_cdn_ip_fastly():
    assert is_cdn_ip("151.101.0.1")
    assert is_cdn_ip("199.232.0.1")

def test_non_cdn_ip():
    assert not is_cdn_ip("1.2.3.4")
    assert not is_cdn_ip("85.132.10.5")
    assert not is_cdn_ip("203.0.113.1")

def test_cdn_ip_empty():
    assert not is_cdn_ip("")
    assert not is_cdn_ip(None)


# ── _valid_public_ip ──────────────────────────────────────────────────────────

def test_valid_public():
    assert _valid_public_ip("1.2.3.4")
    assert _valid_public_ip("85.132.10.5")
    assert _valid_public_ip("203.0.113.50")

def test_private_ips_invalid():
    assert not _valid_public_ip("10.0.0.1")
    assert not _valid_public_ip("192.168.1.1")
    assert not _valid_public_ip("172.16.0.1")
    assert not _valid_public_ip("172.31.255.255")
    assert not _valid_public_ip("127.0.0.1")
    assert not _valid_public_ip("169.254.1.1")
    assert not _valid_public_ip("0.0.0.0")

def test_multicast_invalid():
    assert not _valid_public_ip("224.0.0.1")
    assert not _valid_public_ip("239.255.255.255")

def test_garbage_invalid():
    assert not _valid_public_ip("not-an-ip")
    assert not _valid_public_ip("")
    assert not _valid_public_ip("999.1.2.3")


# ── _extract_ips ──────────────────────────────────────────────────────────────

def test_extract_ips_basic():
    text = "Some text 1.2.3.4 and also 10.20.30.40 here."
    assert "1.2.3.4" in _extract_ips(text)
    assert "10.20.30.40" in _extract_ips(text)

def test_extract_ips_empty():
    assert _extract_ips("") == []
    assert _extract_ips(None) == []

def test_extract_ips_table_html():
    html = "<td>85.132.10.5</td><td>104.16.1.1</td>"
    ips = _extract_ips(html)
    assert "85.132.10.5" in ips
    assert "104.16.1.1" in ips


# ── _filter_ips ───────────────────────────────────────────────────────────────

def test_filter_removes_cdn_and_private():
    raw = ["1.2.3.4", "104.16.1.1", "10.0.0.1", "85.132.10.5"]
    filtered = _filter_ips(raw)
    assert "1.2.3.4" in filtered
    assert "85.132.10.5" in filtered
    assert "104.16.1.1" not in filtered   # CDN
    assert "10.0.0.1" not in filtered     # private


# ── run_real_ip_discovery integration (mocked network) ───────────────────────

FAKE_HISTORY_HTML = """
<html><body>
<table>
<tr><td>85.132.10.5</td><td>2024-01-01</td></tr>
<tr><td>104.16.1.1</td><td>2023-06-01</td></tr>
</table>
</body></html>
"""

FAKE_DNS_REPORT_HTML = """
<html><body>
<tr><td>MX</td><td>203.0.113.20</td></tr>
</body></html>
"""


@pytest.mark.asyncio
async def test_run_real_ip_discovery_mocked():
    """Full pipeline with mocked HTTP and DNS — verifies dedup and confidence."""
    async def fake_fetch(url: str, timeout: int = 12) -> str:
        if "iphistory" in url:
            return FAKE_HISTORY_HTML
        if "dnsreport" in url:
            return FAKE_DNS_REPORT_HTML
        return ""

    def fake_resolve(hostname: str):
        # Direct DNS returns a CDN IP so it's filtered out
        return ["104.16.1.1"]

    with patch("modules.real_ip._fetch", side_effect=fake_fetch), \
         patch("modules.real_ip._resolve", side_effect=fake_resolve):
        results = await run_real_ip_discovery("example.com")

    ips = [r["ip"] for r in results]
    methods = {r["ip"]: r["method"] for r in results}
    confs   = {r["ip"]: r["confidence"] for r in results}

    # 85.132.10.5 found via history (high)
    assert "85.132.10.5" in ips
    assert methods["85.132.10.5"] == "viewdns_history"
    assert confs["85.132.10.5"] == "high"

    # 203.0.113.20 found via dns_report (medium)
    assert "203.0.113.20" in ips
    assert methods["203.0.113.20"] == "dns_report"

    # CDN IP must be excluded
    assert "104.16.1.1" not in ips


@pytest.mark.asyncio
async def test_run_real_ip_discovery_no_results():
    """Returns empty list when all IPs are CDN/private."""
    async def fake_fetch(url, timeout=12):
        return "<html><body>104.16.1.1</body></html>"

    def fake_resolve(hostname):
        return ["172.67.0.1"]

    with patch("modules.real_ip._fetch", side_effect=fake_fetch), \
         patch("modules.real_ip._resolve", side_effect=fake_resolve):
        results = await run_real_ip_discovery("cloudflare-protected.com")

    assert results == []


@pytest.mark.asyncio
async def test_run_real_ip_discovery_dedup_keeps_high_confidence():
    """When the same IP appears in history AND dns_report, keep 'high'."""
    async def fake_fetch(url, timeout=12):
        # Both methods return the same IP
        return "<html><body>85.132.10.5</body></html>"

    def fake_resolve(_):
        return []

    with patch("modules.real_ip._fetch", side_effect=fake_fetch), \
         patch("modules.real_ip._resolve", side_effect=fake_resolve):
        results = await run_real_ip_discovery("example.com")

    assert len(results) == 1
    assert results[0]["ip"] == "85.132.10.5"
    assert results[0]["confidence"] == "high"


@pytest.mark.asyncio
async def test_run_real_ip_discovery_sorted_by_confidence():
    """Results must be sorted: high first, then medium, then low."""
    async def fake_fetch(url, timeout=12):
        if "iphistory" in url:
            return "<html>85.132.10.5</html>"       # high
        if "dnsreport" in url:
            return "<html>203.0.113.20</html>"       # medium
        return ""

    def fake_resolve(hostname):
        # Subdomain direct DNS returns non-CDN → low
        if hostname.startswith("direct.") or hostname.startswith("ftp."):
            return ["1.2.3.4"]
        return []

    with patch("modules.real_ip._fetch", side_effect=fake_fetch), \
         patch("modules.real_ip._resolve", side_effect=fake_resolve):
        results = await run_real_ip_discovery("example.com")

    confs = [r["confidence"] for r in results]
    order = {"high": 0, "medium": 1, "low": 2}
    assert confs == sorted(confs, key=lambda c: order.get(c, 9))
