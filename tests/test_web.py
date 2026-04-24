"""
Tests for modules/web.py — mock aiohttp header check.
"""

import sys
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.orchestrator import EngagementState, Mode
from modules.web import check_security_headers, run_web_analysis, SECURITY_HEADERS


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
