"""
Real IP Discovery — uncovers origin IPs hidden behind CDN/WAF layers.

Four complementary techniques:
  1. ViewDNS IP history  — scrapes historical A records for the domain
  2. ViewDNS DNS report  — mines MX/TXT/A entries for non-CDN IPs
  3. Direct DNS resolve  — checks whether the live A record is non-CDN
  4. Subdomain probe     — resolves bypass-friendly subdomains hoping for
                          an origin IP that wasn't routed through the CDN
"""

import asyncio
import re
import socket
from typing import TypedDict


# ── CDN / WAF IP-range prefixes ───────────────────────────────────────────────
# Each entry is matched as a *startswith* prefix against "a.b.c.d".
_CDN_PREFIXES: tuple[str, ...] = (
    # Cloudflare ----------------------------------------------------------------
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "104.28.", "104.29.", "104.30.", "104.31.",
    "172.64.", "172.65.", "172.66.", "172.67.", "172.68.",
    "172.69.", "172.70.", "172.71.",
    "188.114.", "103.21.", "103.22.", "103.31.",
    "141.101.", "162.158.", "198.41.", "190.93.",
    "108.162.", "197.234.", "198.41.",
    # Akamai --------------------------------------------------------------------
    "23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.",
    "23.38.", "23.39.", "23.40.", "23.41.", "23.42.", "23.43.",
    "23.44.", "23.45.", "23.46.", "23.47.", "23.48.", "23.49.",
    "23.50.", "23.51.", "23.52.", "23.53.", "23.54.", "23.55.",
    "23.56.", "23.57.", "23.58.", "23.59.",
    "23.192.", "23.193.", "23.194.", "23.195.", "23.196.", "23.197.",
    "23.198.", "23.199.", "23.200.", "23.201.", "23.202.", "23.203.",
    "23.204.", "23.205.", "23.206.", "23.207.", "23.208.", "23.209.",
    "23.210.", "23.211.", "23.212.", "23.213.", "23.214.", "23.215.",
    "23.216.", "23.217.", "23.218.", "23.219.", "23.220.", "23.221.",
    "23.222.", "23.223.",
    "72.246.", "96.6.", "96.7.",
    # Fastly --------------------------------------------------------------------
    "151.101.", "199.232.",
    # Sucuri --------------------------------------------------------------------
    "185.93.228.", "185.93.229.", "185.93.230.", "185.93.231.",
    "192.88.134.", "192.88.135.",
    # AWS CloudFront (commonly used) -------------------------------------------
    "13.32.", "13.33.", "13.35.", "52.84.", "52.85.",
    "54.182.", "54.192.", "54.230.", "64.252.", "70.132.",
    # Imperva / Incapsula -------------------------------------------------------
    "45.60.", "45.223.",
)

_CONF_ORDER = {"high": 0, "medium": 1, "low": 2}

_BYPASS_SUBDOMAINS = [
    "direct", "origin", "mail", "cpanel", "ftp", "smtp",
    "webmail", "ns1", "ns2", "staging", "dev", "beta",
    "api", "admin", "vpn", "remote",
]

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def is_cdn_ip(ip: str) -> bool:
    """Return True if *ip* belongs to a known CDN / WAF range."""
    if not ip:
        return False
    for prefix in _CDN_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def _extract_ips(text: str) -> list[str]:
    """Extract all IPv4 addresses from *text*."""
    return re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text or "")


def _valid_public_ip(ip: str) -> bool:
    """Return True only for plausible public unicast IPs."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if not all(0 <= o <= 255 for o in octets):
        return False
    first = octets[0]
    # Exclude private / link-local / loopback / broadcast / multicast
    if first in (0, 10, 127) or octets == [255, 255, 255, 255]:
        return False
    if first == 172 and 16 <= octets[1] <= 31:
        return False
    if first == 192 and octets[1] == 168:
        return False
    if first == 169 and octets[1] == 254:
        return False
    if 224 <= first <= 255:
        return False
    return True


async def _fetch(url: str, timeout: int = 12) -> str:
    """Async GET; returns body text or empty string on any failure."""
    try:
        import aiohttp
        import ssl as ssl_lib
        ctx = ssl_lib.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_lib.CERT_NONE
        async with aiohttp.ClientSession(
            headers=_HEADERS,
            connector=aiohttp.TCPConnector(ssl=ctx),
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as session:
            async with session.get(url) as resp:
                return await resp.text(errors="ignore")
    except Exception:
        return ""


def _resolve(hostname: str) -> list[str]:
    """Synchronous A-record resolution (IPv4 only)."""
    try:
        info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return list({i[4][0] for i in info})
    except Exception:
        return []


def _filter_ips(ips: list[str]) -> list[str]:
    """Keep only public, non-CDN IPs."""
    return [ip for ip in ips if _valid_public_ip(ip) and not is_cdn_ip(ip)]


# ── Method 1: ViewDNS IP history ──────────────────────────────────────────────

async def _method_viewdns_history(target: str) -> list[dict]:
    """Scrape historical A records from viewdns.info/iphistory."""
    html = await _fetch(f"https://viewdns.info/iphistory/?domain={target}")
    if not html:
        return []
    seen: set[str] = set()
    results = []
    for ip in _filter_ips(_extract_ips(html)):
        if ip not in seen:
            seen.add(ip)
            results.append({"ip": ip, "method": "viewdns_history", "confidence": "high"})
    return results


# ── Method 2: ViewDNS DNS report ─────────────────────────────────────────────

async def _method_viewdns_dnsreport(target: str) -> list[dict]:
    """Mine MX/TXT/A entries from viewdns.info/dnsreport."""
    html = await _fetch(f"https://viewdns.info/dnsreport/?domain={target}")
    if not html:
        return []
    seen: set[str] = set()
    results = []
    for ip in _filter_ips(_extract_ips(html)):
        if ip not in seen:
            seen.add(ip)
            results.append({"ip": ip, "method": "dns_report", "confidence": "medium"})
    return results


# ── Method 3: Direct DNS resolve ─────────────────────────────────────────────

async def _method_direct_dns(target: str) -> list[dict]:
    """Resolve the domain's live A record; flag if it's non-CDN."""
    loop = asyncio.get_event_loop()
    ips = await loop.run_in_executor(None, _resolve, target)
    return [
        {"ip": ip, "method": "direct_dns", "confidence": "low"}
        for ip in _filter_ips(ips)
    ]


# ── Method 4: Subdomain bypass probe ─────────────────────────────────────────

async def _method_subdomain_check(target: str) -> list[dict]:
    """Resolve bypass subdomains hoping for an origin IP."""
    loop = asyncio.get_event_loop()
    results: list[dict] = []
    seen: set[str] = set()

    async def check(sub: str):
        ips = await loop.run_in_executor(None, _resolve, f"{sub}.{target}")
        for ip in _filter_ips(ips):
            if ip not in seen:
                seen.add(ip)
                results.append({
                    "ip": ip,
                    "method": f"subdomain:{sub}",
                    "confidence": "medium",
                })

    await asyncio.gather(*[check(s) for s in _BYPASS_SUBDOMAINS],
                         return_exceptions=True)
    return results


# ── Public entry point ────────────────────────────────────────────────────────

async def run_real_ip_discovery(target: str, console=None) -> list[dict]:
    """
    Run all four real-IP discovery methods and return a deduplicated list of
    potential origin-IP dicts::

        [{"ip": "1.2.3.4", "method": "viewdns_history", "confidence": "high"}, ...]

    When the same IP is found by multiple methods the highest-confidence entry
    (high > medium > low) is kept.  Results are sorted: high first, then medium,
    then low.

    Args:
        target:  Hostname to investigate (e.g. "example.com").
        console: Optional Rich Console for progress logging.

    Returns:
        List of dicts — may be empty if no non-CDN IPs are found.
    """
    def log(msg: str):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    log("ViewDNS IP history lookup...")
    m1 = await _method_viewdns_history(target)

    log("ViewDNS DNS report lookup...")
    m2 = await _method_viewdns_dnsreport(target)

    log("Direct DNS resolution...")
    m3 = await _method_direct_dns(target)

    log("Subdomain bypass probe...")
    m4 = await _method_subdomain_check(target)

    # Merge — process high-confidence sources first so they win ties
    by_ip: dict[str, dict] = {}
    for entry in m1 + m4 + m2 + m3:   # descending confidence order
        ip = entry["ip"]
        existing = by_ip.get(ip)
        if existing is None:
            by_ip[ip] = entry
        elif (_CONF_ORDER.get(entry["confidence"], 9) <
              _CONF_ORDER.get(existing["confidence"], 9)):
            by_ip[ip] = entry

    return sorted(
        by_ip.values(),
        key=lambda e: _CONF_ORDER.get(e["confidence"], 9),
    )
