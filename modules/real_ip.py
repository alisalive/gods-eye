"""
Real IP Discovery — uncovers origin IPs hidden behind CDN/WAF layers.

Two phases:

Discovery (collect candidates):
  1. ViewDNS IP history  — historical A records with recency-based confidence
  2. SecurityTrails page — best-effort HTML scrape (JS-heavy; often limited)
  3. CrimeFlare DB       — POST Cloudflare-bypass crowd-sourced database
  4. crt.sh cert logs    — IP SANs extracted from certificate transparency JSON
  5. Subdomain DNS       — resolve bypass-friendly prefixes; HTTP-verify inline

Verification (upgrade confidence):
  6. Shodan InternetDB   — confirm IP serves target via hostname list
  7. HTTP fingerprint    — connect to IP with Host: {target}, match title/body
"""

import asyncio
import datetime
import hashlib
import json as _json
import re
import socket
from typing import Any, Optional


# ── CDN / WAF IP-range prefixes ───────────────────────────────────────────────
_CDN_PREFIXES: tuple[str, ...] = (
    # Cloudflare
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "104.28.", "104.29.", "104.30.", "104.31.",
    "172.64.", "172.65.", "172.66.", "172.67.", "172.68.",
    "172.69.", "172.70.", "172.71.",
    "188.114.", "103.21.", "103.22.", "103.31.",
    "141.101.", "162.158.", "198.41.", "190.93.",
    "108.162.", "197.234.",
    # Akamai
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
    # Fastly
    "151.101.", "199.232.",
    # Sucuri
    "185.93.228.", "185.93.229.", "185.93.230.", "185.93.231.",
    "192.88.134.", "192.88.135.",
    # AWS CloudFront
    "13.32.", "13.33.", "13.35.", "52.84.", "52.85.",
    "54.182.", "54.192.", "54.230.", "64.252.", "70.132.",
    # Imperva / Incapsula
    "45.60.", "45.223.",
)

_CONF_ORDER: dict[str, int] = {"confirmed": 0, "high": 1, "medium": 2, "low": 3}

_BYPASS_SUBDOMAINS: list[str] = [
    "direct", "origin", "backend", "real", "server", "host", "app", "api",
    "mail", "smtp", "ftp", "cpanel", "webmail", "admin", "portal",
    "staging", "dev", "test", "beta", "old", "legacy", "www2",
    "m", "mobile", "cdn", "static", "assets", "media",
]

_BROWSER_HEADERS: dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


# ── Pure helpers (no I/O — fast to test) ─────────────────────────────────────

def is_cdn_ip(ip: str) -> bool:
    """Return True if *ip* belongs to a known CDN / WAF range."""
    if not ip:
        return False
    for prefix in _CDN_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


def _valid_public_ip(ip: str) -> bool:
    """Return True only for valid, routable (non-CDN) IPv4 addresses."""
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


def _extract_ips(text: str) -> list[str]:
    """Return all IPv4 strings found in *text*."""
    return re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text or "")


def _filter_ips(ips: list[str]) -> list[str]:
    """Keep only public, non-CDN IPs from *ips*."""
    return [ip for ip in ips if _valid_public_ip(ip) and not is_cdn_ip(ip)]


def _strip_tags(html: str) -> str:
    """Strip HTML tags and decode common entities."""
    text = re.sub(r'<[^>]+>', '', html or "")
    for ent, ch in (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                    ("&nbsp;", " "), ("&#160;", " ")):
        text = text.replace(ent, ch)
    return text.strip()


def _date_confidence(date_str: str) -> str:
    """Score recency of *date_str*: recent→high, moderate→medium, old→low."""
    if not date_str:
        return "low"
    for fmt in ("%Y-%m-%d", "%d %b %Y", "%B %d, %Y",
                "%d/%m/%Y", "%m/%d/%Y", "%Y/%m/%d"):
        try:
            dt = datetime.datetime.strptime(date_str.strip(), fmt)
            days = (datetime.datetime.now() - dt).days
            if days < 90:
                return "high"
            if days < 365:
                return "medium"
            return "low"
        except ValueError:
            continue
    return "low"


def _extract_title(html: str) -> str:
    """Return the text content of <title> (stripped)."""
    m = re.search(r'<title[^>]*>(.*?)</title>', html or "",
                  re.DOTALL | re.IGNORECASE)
    return _strip_tags(m.group(1)) if m else ""


def _body_hash(html: str) -> str:
    """MD5 of the visible text (first 4 KB, whitespace-normalised)."""
    clean = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', '', (html or "")[:8192]))
    return hashlib.md5(clean[:4096].encode("utf-8", errors="replace")).hexdigest()


def _blank_entry(ip: str, method: str, confidence: str,
                 country: str = "", last_seen: str = "") -> dict:
    """Return a canonical result dict."""
    return {
        "ip":         ip,
        "method":     method,
        "confidence": confidence,
        "country":    country,
        "last_seen":  last_seen,
        "verified":   False,
    }


# ── Network primitives (all I/O goes through these — easy to mock) ────────────

async def _fetch_get(url: str, timeout: int = 12,
                     extra_headers: Optional[dict] = None,
                     verify_ssl: bool = True) -> str:
    """Async GET; returns body text or '' on any failure."""
    try:
        import aiohttp
        import ssl as ssl_lib
        if not verify_ssl:
            ctx = ssl_lib.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_lib.CERT_NONE
        else:
            ctx = None
        hdrs = {**_BROWSER_HEADERS, **(extra_headers or {})}
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ctx),
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as s:
            async with s.get(url, headers=hdrs) as resp:
                return await resp.text(errors="ignore")
    except Exception:
        return ""


async def _fetch_post(url: str, form_data: dict, timeout: int = 10) -> str:
    """Async POST form-data; returns body text or '' on failure."""
    try:
        import aiohttp
        import ssl as ssl_lib
        ctx = ssl_lib.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_lib.CERT_NONE
        async with aiohttp.ClientSession(
            headers=_BROWSER_HEADERS,
            connector=aiohttp.TCPConnector(ssl=ctx),
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as s:
            async with s.post(url, data=form_data) as resp:
                return await resp.text(errors="ignore")
    except Exception:
        return ""


async def _fetch_json(url: str, timeout: int = 12) -> Any:
    """Async GET JSON; returns parsed object or None on failure."""
    text = await _fetch_get(url, timeout=timeout, verify_ssl=False)
    if not text:
        return None
    try:
        return _json.loads(text)
    except Exception:
        return None


def _dns_resolve(hostname: str) -> list[str]:
    """Synchronous IPv4 A-record resolution."""
    try:
        info = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return list({i[4][0] for i in info})
    except Exception:
        return []


# ── Discovery methods ─────────────────────────────────────────────────────────

async def _method_viewdns_history(target: str) -> list[dict]:
    """Method 1 — ViewDNS IP history: historical A records + recency scoring.

    Table columns: IP Address | Location | Owner | Last seen
    """
    html = await _fetch_get(f"https://viewdns.info/iphistory/?domain={target}")
    if not html:
        return []

    results: list[dict] = []
    seen: set[str] = set()

    rows = re.findall(r'<tr[^>]*>(.*?)</tr>', html, re.DOTALL | re.IGNORECASE)
    for row in rows:
        cells = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL | re.IGNORECASE)
        if len(cells) < 4:
            continue
        ip        = _strip_tags(cells[0])
        country   = _strip_tags(cells[1])[:60]
        last_seen = _strip_tags(cells[3])
        if not _valid_public_ip(ip) or is_cdn_ip(ip) or ip in seen:
            continue
        seen.add(ip)
        results.append(_blank_entry(
            ip, "viewdns_history",
            _date_confidence(last_seen),
            country, last_seen,
        ))

    return results


async def _method_securitytrails(target: str) -> list[dict]:
    """Method 2 — SecurityTrails DNS history page (best-effort; JS-heavy)."""
    html = await _fetch_get(f"https://securitytrails.com/domain/{target}/dns")
    if not html:
        return []
    results: list[dict] = []
    seen: set[str] = set()
    for ip in _filter_ips(_extract_ips(html)):
        if ip not in seen:
            seen.add(ip)
            results.append(_blank_entry(ip, "securitytrails", "medium"))
    return results


async def _method_crimeflare(target: str) -> list[dict]:
    """Method 3 — CrimeFlare crowd-sourced Cloudflare-bypass database."""
    text = await _fetch_post(
        "https://api.crimeflare.com:82/cfs.php",
        {"domain": target},
    )
    if not text:
        return []
    results: list[dict] = []
    seen: set[str] = set()
    for ip in _filter_ips(_extract_ips(text)):
        if ip not in seen:
            seen.add(ip)
            results.append(_blank_entry(ip, "crimeflare", "high"))
    return results


async def _method_crtsh(target: str) -> list[dict]:
    """Method 4 — crt.sh certificate transparency: IP SANs from cert JSON."""
    data = await _fetch_json(f"https://crt.sh/?q={target}&output=json")
    if not data or not isinstance(data, list):
        return []
    raw_text = _json.dumps(data)
    results: list[dict] = []
    seen: set[str] = set()
    for ip in _filter_ips(_extract_ips(raw_text)):
        if ip not in seen:
            seen.add(ip)
            results.append(_blank_entry(ip, "crtsh", "medium"))
    return results


async def _method_subdomain_dns(target: str, site_fp: dict) -> list[dict]:
    """Method 5 — resolve bypass subdomains; HTTP-verify inline with Host header."""
    loop = asyncio.get_event_loop()
    results: list[dict] = []
    seen: set[str] = set()

    async def probe(sub: str) -> None:
        hostname = f"{sub}.{target}"
        ips = await loop.run_in_executor(None, _dns_resolve, hostname)
        for ip in _filter_ips(ips):
            if ip in seen:
                continue
            seen.add(ip)
            verified = await _http_matches_site(ip, target, site_fp)
            results.append(_blank_entry(
                ip, f"subdomain:{sub}",
                "confirmed" if verified else "medium",
            ) | {"verified": verified})

    await asyncio.gather(*[probe(s) for s in _BYPASS_SUBDOMAINS],
                         return_exceptions=True)
    return results


# ── Verification helpers ──────────────────────────────────────────────────────

async def _get_site_fingerprint(target: str) -> dict:
    """Fetch the canonical site; return title + body-hash fingerprint."""
    for proto in ("https", "http"):
        html = await _fetch_get(f"{proto}://{target}/", timeout=10)
        if html:
            return {
                "title":     _extract_title(html),
                "body_hash": _body_hash(html),
                "proto":     proto,
            }
    return {}


async def _http_matches_site(ip: str, target: str, fingerprint: dict) -> bool:
    """Return True if GETting *ip* with Host: *target* serves the same page."""
    if not fingerprint:
        return False
    for proto in ("https", "http"):
        html = await _fetch_get(
            f"{proto}://{ip}/",
            timeout=8,
            extra_headers={"Host": target},
            verify_ssl=False,
        )
        if not html:
            continue
        fp_title = fingerprint.get("title", "")
        fp_bh    = fingerprint.get("body_hash", "")
        title = _extract_title(html)
        bh    = _body_hash(html)
        if fp_title and title and fp_title.lower() == title.lower():
            return True
        if fp_bh and bh and fp_bh == bh:
            return True
    return False


async def _shodan_verify(ip: str, target: str) -> bool:
    """Return True if Shodan InternetDB lists *target* in hostnames for *ip*."""
    data = await _fetch_json(f"https://internetdb.shodan.io/{ip}")
    if not data or not isinstance(data, dict):
        return False
    tgt = target.lower().lstrip("www.")
    return any(tgt in h.lower() for h in data.get("hostnames", []))


# ── Public entry point ────────────────────────────────────────────────────────

async def run_real_ip_discovery(target: str, console=None) -> list[dict]:
    """
    Run all seven real-IP discovery techniques and return a deduplicated,
    confidence-sorted list of potential origin-IP dicts::

        [
          {
            "ip":         "1.2.3.4",
            "method":     "viewdns_history",
            "confidence": "confirmed|high|medium|low",
            "country":    "Azerbaijan",
            "last_seen":  "2024-03-15",
            "verified":   True,
          },
          ...
        ]

    ``confidence="confirmed"`` means HTTP fingerprint or Shodan independently
    verified that the IP serves the target domain.

    Args:
        target:  Hostname to investigate (e.g. "example.com").
        console: Optional Rich Console for progress logging.
    """
    def log(msg: str) -> None:
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    log("Real IP discovery (7 methods)...")

    # ── Phase 1: site fingerprint (needed for subdomain + HTTP verification) ──
    log("Fetching site fingerprint for HTTP verification...")
    site_fp = await _get_site_fingerprint(target)

    # ── Phase 2: passive discovery sources ───────────────────────────────────
    log("ViewDNS IP history...")
    m1 = await _method_viewdns_history(target)

    log("SecurityTrails DNS history...")
    m2 = await _method_securitytrails(target)

    log("CrimeFlare Cloudflare-bypass DB...")
    m3 = await _method_crimeflare(target)

    log("crt.sh certificate transparency...")
    m4 = await _method_crtsh(target)

    log("Subdomain bypass probe + inline HTTP verification...")
    m5 = await _method_subdomain_dns(target, site_fp)

    # ── Phase 3: deduplicate (highest confidence wins per IP) ─────────────────
    by_ip: dict[str, dict] = {}
    # Process highest-confidence sources first so they win on IP collision
    for entry in m3 + m1 + m5 + m2 + m4:
        ip = entry["ip"]
        existing = by_ip.get(ip)
        if existing is None:
            by_ip[ip] = entry
        elif (_CONF_ORDER.get(entry["confidence"], 9) <
              _CONF_ORDER.get(existing["confidence"], 9)):
            by_ip[ip] = entry

    if not by_ip:
        if console:
            console.print("  [dim]→ No non-CDN IPs discovered[/dim]")
        return []

    # ── Phase 4: Shodan InternetDB hostname verification ──────────────────────
    log(f"Shodan InternetDB verification ({len(by_ip)} candidates)...")
    for entry in by_ip.values():
        if entry.get("verified"):
            continue
        if await _shodan_verify(entry["ip"], target):
            entry["verified"] = True
            if entry["confidence"] not in ("confirmed",):
                entry["confidence"] = "high"

    # ── Phase 5: HTTP fingerprint verification for remaining candidates ───────
    log("HTTP fingerprint verification...")
    unverified = [e for e in by_ip.values() if not e.get("verified")]
    if unverified and site_fp:
        checks = await asyncio.gather(
            *[_http_matches_site(e["ip"], target, site_fp) for e in unverified],
            return_exceptions=True,
        )
        for entry, matched in zip(unverified, checks):
            if matched is True:
                entry["verified"] = True
                entry["confidence"] = "confirmed"

    # ── Phase 6: sort and report ──────────────────────────────────────────────
    sorted_results = sorted(
        by_ip.values(),
        key=lambda e: _CONF_ORDER.get(e["confidence"], 9),
    )

    for entry in sorted_results:
        ip      = entry["ip"]
        method  = entry["method"]
        conf    = entry["confidence"]
        country = f", {entry['country']}" if entry.get("country") else ""
        if conf == "confirmed":
            if console:
                console.print(
                    f"  [green]✓[/green] [bold]CONFIRMED[/bold] real IP: "
                    f"[bold cyan]{ip}[/bold cyan] "
                    f"([yellow]{method}[/yellow] + verified via HTTP)"
                )
        else:
            if console:
                console.print(
                    f"  [dim]→[/dim] Possible real IP: "
                    f"[cyan]{ip}[/cyan] "
                    f"([yellow]{method}[/yellow], {conf} confidence{country})"
                )

    return sorted_results
