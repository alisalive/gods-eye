"""
Tests for modules/web.py — security headers, email harvesting, cookie analysis.
"""

import sys
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.orchestrator import EngagementState, Mode
from modules.web import (
    check_security_headers,
    run_web_analysis,
    SECURITY_HEADERS,
    extract_emails,
    analyze_set_cookie_headers,
)


# ── Unit tests ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_check_security_headers_all_missing():
    """When no security headers present, all should be in missing list."""
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.headers = {}

    mock_session = MagicMock()
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_cm.__aexit__ = AsyncMock(return_value=False)
    mock_session.get.return_value = mock_cm

    result = await check_security_headers(mock_session, "http://example.com")
    assert "missing" in result
    assert len(result["missing"]) == len(SECURITY_HEADERS)


@pytest.mark.asyncio
async def test_check_security_headers_some_present():
    """Headers that are present should not appear in missing list."""
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.headers = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000",
    }

    mock_session = MagicMock()
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_cm.__aexit__ = AsyncMock(return_value=False)
    mock_session.get.return_value = mock_cm

    result = await check_security_headers(mock_session, "http://example.com")
    missing_names = [h["header"] for h in result.get("missing", [])]
    assert "X-Frame-Options" not in missing_names
    assert "Strict-Transport-Security" not in missing_names


@pytest.mark.asyncio
async def test_run_web_analysis_no_web_services():
    """Should handle state with no web services gracefully."""
    state = EngagementState(
        target="127.0.0.1", mode=Mode.PENTEST, scope=["127.0.0.1"]
    )
    state.recon_data = {"open_ports": {}, "web": {}}

    result = await run_web_analysis(state, console=None)
    assert result == {}


# ══════════════════════════════════════════════════════════════════════════════
# extract_emails — pure function
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractEmails:
    def test_basic_email(self):
        assert "admin@example.org" in extract_emails("contact admin@example.org for help")

    def test_multiple_emails(self):
        text = "reach us at info@company.com or sales@company.com"
        result = extract_emails(text)
        assert "info@company.com" in result
        assert "sales@company.com" in result

    def test_mailto_link(self):
        html = '<a href="mailto:contact@firm.io">Email us</a>'
        result = extract_emails(html)
        assert "contact@firm.io" in result

    def test_mailto_with_query_string(self):
        html = '<a href="mailto:hr@company.net?subject=Job">Apply</a>'
        result = extract_emails(html)
        assert "hr@company.net" in result

    def test_filters_example_com(self):
        result = extract_emails("user@example.com is a placeholder")
        assert "user@example.com" not in result

    def test_filters_test_domain(self):
        result = extract_emails("ping test@test.com")
        assert not any("test.com" in e for e in result)

    def test_filters_noreply(self):
        result = extract_emails("sent from noreply@company.com")
        assert not any("noreply" in e for e in result)

    def test_filters_no_reply_hyphen(self):
        result = extract_emails("no-reply@company.com")
        assert not any("no-reply" in e for e in result)

    def test_empty_text(self):
        assert extract_emails("") == []
        assert extract_emails(None) == []

    def test_no_emails(self):
        assert extract_emails("just regular text here") == []

    def test_returns_sorted_list(self):
        text = "z@z.com a@a.com m@m.com"
        result = extract_emails(text)
        assert result == sorted(result)

    def test_deduplication(self):
        text = "info@co.com and info@co.com again"
        result = extract_emails(text)
        assert result.count("info@co.com") == 1

    def test_case_normalised_to_lowercase(self):
        result = extract_emails("Info@Company.COM")
        assert "info@company.com" in result


# ══════════════════════════════════════════════════════════════════════════════
# analyze_set_cookie_headers — pure function
# ══════════════════════════════════════════════════════════════════════════════

class TestAnalyzeSetCookieHeaders:
    def test_detects_php_from_phpsessid(self):
        techs, _ = analyze_set_cookie_headers(
            ["PHPSESSID=abc123; Path=/; HttpOnly; Secure; SameSite=Lax"]
        )
        assert "PHP" in techs

    def test_detects_django_from_sessionid(self):
        techs, _ = analyze_set_cookie_headers(
            ["sessionid=xyz; Path=/; HttpOnly; Secure; SameSite=Lax"]
        )
        assert "Django" in techs

    def test_detects_laravel_from_cookie_name(self):
        techs, _ = analyze_set_cookie_headers(
            ["laravel_session=abc; Path=/; HttpOnly; Secure; SameSite=Lax"]
        )
        assert "Laravel" in techs

    def test_detects_node_from_connect_sid(self):
        techs, _ = analyze_set_cookie_headers(
            ["connect.sid=s%3Aabc; Path=/; HttpOnly; Secure; SameSite=Lax"]
        )
        assert "Node.js" in techs

    def test_detects_java_from_jsessionid(self):
        techs, _ = analyze_set_cookie_headers(
            ["JSESSIONID=ABCD1234; Path=/; HttpOnly; Secure; SameSite=Lax"]
        )
        assert "Java/JSP" in techs

    def test_missing_httponly_flag(self):
        _, findings = analyze_set_cookie_headers(
            ["sessionid=abc; Path=/; Secure; SameSite=Lax"]
        )
        titles = [f["title"] for f in findings]
        assert any("HttpOnly" in t for t in titles)

    def test_missing_secure_flag(self):
        _, findings = analyze_set_cookie_headers(
            ["sessionid=abc; Path=/; HttpOnly; SameSite=Lax"]
        )
        titles = [f["title"] for f in findings]
        assert any("Secure" in t for t in titles)

    def test_missing_samesite(self):
        _, findings = analyze_set_cookie_headers(
            ["sessionid=abc; Path=/; HttpOnly; Secure"]
        )
        titles = [f["title"] for f in findings]
        assert any("SameSite" in t for t in titles)

    def test_all_flags_present_no_security_issues(self):
        _, findings = analyze_set_cookie_headers(
            ["PHPSESSID=abc; Path=/; HttpOnly; Secure; SameSite=Strict"]
        )
        assert findings == []

    def test_non_session_cookie_not_flagged(self):
        """Tracking/analytics cookies should not generate security findings."""
        _, findings = analyze_set_cookie_headers(
            ["_ga=GA1.2.abc; Path=/; Expires=Wed, 01 Jan 2025 00:00:00 GMT"]
        )
        assert findings == []

    def test_empty_list(self):
        techs, findings = analyze_set_cookie_headers([])
        assert techs == []
        assert findings == []

    def test_finding_severity_httponly(self):
        _, findings = analyze_set_cookie_headers(
            ["sessionid=abc; Path=/; Secure; SameSite=Lax"]
        )
        httponly_f = next(f for f in findings if "HttpOnly" in f["title"])
        assert httponly_f["severity"] == "medium"

    def test_finding_severity_samesite(self):
        _, findings = analyze_set_cookie_headers(
            ["sessionid=abc; Path=/; HttpOnly; Secure"]
        )
        ss_f = next(f for f in findings if "SameSite" in f["title"])
        assert ss_f["severity"] == "low"

    def test_finding_has_required_keys(self):
        _, findings = analyze_set_cookie_headers(
            ["PHPSESSID=abc; Path=/"]
        )
        for f in findings:
            assert "title"       in f
            assert "severity"    in f
            assert "description" in f
            assert "evidence"    in f
            assert "remediation" in f


# ══════════════════════════════════════════════════════════════════════════════
# Original test suite (unchanged)
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_run_web_analysis_with_mock_service():
    """Should process web services and populate state.web_data."""
    state = EngagementState(
        target="127.0.0.1", mode=Mode.PENTEST, scope=["127.0.0.1"]
    )
    state.recon_data = {
        "open_ports": {80: {"service": "HTTP", "banner": ""}},
        "web": {80: {"url": "http://127.0.0.1", "technologies": [], "waf": None,
                     "cves": [], "vulns": [], "status_code": 200}},
    }

    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session = AsyncMock()
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Security-Policy": "default-src 'self'"}
        mock_resp_cm = AsyncMock()
        mock_resp_cm.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp_cm.__aexit__ = AsyncMock(return_value=False)
        mock_session.get.return_value = mock_resp_cm

        result = await run_web_analysis(state, console=None)

    assert isinstance(result, dict)
