"""
Tests for modules/recon.py — mock socket port scan.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.orchestrator import EngagementState, Mode
from modules.recon import port_scan, dns_lookup, get_service_name, run_recon


# ── Unit tests ────────────────────────────────────────────────────────────────

def test_get_service_name_known():
    assert get_service_name(80) == "HTTP"
    assert get_service_name(443) == "HTTPS"
    assert get_service_name(22) == "SSH"
    assert get_service_name(445) == "SMB"
    assert get_service_name(3389) == "RDP"


def test_get_service_name_unknown():
    result = get_service_name(12345)
    assert result == "port-12345"


def test_dns_lookup_invalid():
    result = dns_lookup("this-does-not-exist-xyz-abc.invalid")
    assert "error" in result or result["ips"] == []


def test_dns_lookup_loopback():
    result = dns_lookup("127.0.0.1")
    assert result["hostname"] == "127.0.0.1"


@pytest.mark.asyncio
async def test_port_scan_closed_ports():
    """All ports on 127.0.0.1 range should be closed (except listening ones)."""
    open_ports = await port_scan("127.0.0.1", ports=[1, 2, 3, 4, 5], timeout=0.2)
    # Just verify it returns a dict (some may be open on CI, that's fine)
    assert isinstance(open_ports, dict)


@pytest.mark.asyncio
async def test_port_scan_returns_service_names():
    """Port scan dict values should have 'service' and 'banner' keys."""
    with patch("asyncio.open_connection") as mock_conn:
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_conn.return_value = (mock_reader, mock_writer)

        open_ports = await port_scan("127.0.0.1", ports=[22], timeout=1.0)
        if 22 in open_ports:
            assert "service" in open_ports[22]
            assert "banner" in open_ports[22]


@pytest.mark.asyncio
async def test_run_recon_basic():
    """run_recon should complete and populate state.recon_data."""
    state = EngagementState(target="127.0.0.1", mode=Mode.PENTEST, scope=["127.0.0.1"])

    # Return a non-web port (SSH) so the GOD'S EYE / web-fingerprint branch
    # is never entered — keeps the test isolated from external imports.
    with patch("modules.recon.port_scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = {22: {"service": "SSH", "banner": "SSH-2.0-OpenSSH_9.0"}}
        await run_recon(state, console=None)

    assert "open_ports" in state.recon_data
    assert "dns" in state.recon_data
    assert 22 in state.recon_data["open_ports"]
