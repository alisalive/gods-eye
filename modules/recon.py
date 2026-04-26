"""
Recon Module — powered by GOD'S EYE with fallback to built-in scanner.
"""

import asyncio
import socket
import re
import os
import sys
from pathlib import Path
from core.orchestrator import EngagementState, Finding, Severity

# ── GOD'S EYE path setup ──────────────────────────────────────────────────────
def _add_gods_eye(path: str = None):
    candidates = [
        path,
        os.environ.get("GODS_EYE_PATH"),
        r"C:\Users\User\Documents\GODs_EYE",
        str(Path.home() / "Documents" / "GODs_EYE"),
    ]
    for c in candidates:
        if c and os.path.isdir(c) and c not in sys.path:
            sys.path.insert(0, c)
            return True
    return False

_add_gods_eye()

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                389, 636, 993, 995, 1433, 1521, 3268, 3269, 3306, 3389,
                5432, 5900, 5985, 5986, 6379, 8080, 8443, 27017]

STEALTH_PORTS = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389, 8080]


def get_service_name(port: int) -> str:
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
        389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kpasswd",
        636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
        1521: "Oracle", 3268: "GC-LDAP", 3269: "GC-LDAPS",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    }
    return services.get(port, f"port-{port}")


async def port_scan(target: str, ports: list = None, timeout: float = 1.0,
                    stealth: bool = False) -> dict:
    if ports is None:
        ports = STEALTH_PORTS if stealth else COMMON_PORTS

    if stealth:
        timeout = max(timeout, 3.0)

    open_ports = {}

    async def check_port(port):
        try:
            if stealth:
                await asyncio.sleep(0.1)
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            banner = ""
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=0.5)
                banner = data.decode("utf-8", errors="ignore").strip()[:100]
            except Exception:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port, True, banner
        except Exception:
            return port, False, ""

    if stealth:
        # Sequential in stealth mode
        for p in ports:
            result = await check_port(p)
            if result[1]:
                open_ports[result[0]] = {"service": get_service_name(result[0]), "banner": result[2]}
    else:
        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, tuple) and result[1]:
                port, _, banner = result
                open_ports[port] = {"service": get_service_name(port), "banner": banner}

    return open_ports


def dns_lookup(target: str) -> dict:
    result = {"hostname": target, "ips": [], "reverse": []}
    try:
        info = socket.getaddrinfo(target, None)
        ips = list(set(i[4][0] for i in info))
        result["ips"] = ips
        for ip in ips[:3]:
            try:
                rev = socket.gethostbyaddr(ip)[0]
                result["reverse"].append(rev)
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)
    return result


async def _fetch_response_headers(url: str) -> dict:
    """HEAD request to *url*; returns response headers as a plain dict.

    Used to supplement wdata['headers'] when the GOD'S EYE bridge doesn't
    populate that field, so that header-presence vuln filters work correctly.
    Returns an empty dict on any failure — callers treat that as 'unknown'.
    """
    if not url:
        return {}
    import aiohttp
    import ssl as ssl_lib
    try:
        ssl_ctx = ssl_lib.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl_lib.CERT_NONE
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ssl_ctx),
            timeout=aiohttp.ClientTimeout(total=5),
        ) as session:
            async with session.head(url, allow_redirects=True) as resp:
                return dict(resp.headers)
    except Exception:
        return {}


def _sync_check_redirect(url: str) -> bool:
    """Synchronous fallback redirect check using the requests library.

    Used when the aiohttp probe returns a non-redirect (e.g. Cloudflare
    serves a 200 challenge page to aiohttp but a proper 301 to requests).
    Returns True on any exception — benefit of the doubt, suppress finding.
    """
    try:
        import requests as req_lib
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = req_lib.get(url, allow_redirects=False, timeout=10, verify=False)
        if r.status_code in (301, 302, 307, 308):
            loc = r.headers.get("Location", "")
            return loc.lower().startswith("https://")
    except Exception:
        return True  # can't confirm — assume redirect, suppress finding
    return False


async def _check_https_redirect(target: str, port: int) -> bool:
    """Return True if an HTTP request to this port receives a 301/302/307/308
    redirect whose Location starts with 'https://'.  Used to suppress the
    'HTTPS not used' false positive on sites that properly enforce HTTPS.

    Strategy:
    1. aiohttp probe  — fast async check, ssl=False to avoid TLS handshake noise
    2. requests fallback (thread executor) — Cloudflare and some CDNs return a
       200 challenge page to aiohttp but issue a proper 301 to a stock UA;
       the synchronous probe uses a different TLS stack and User-Agent.

    Returns True on any unrecoverable exception so network errors suppress
    the finding rather than surface it as a false positive.
    """
    import aiohttp
    url = f"http://{target}" if port == 80 else f"http://{target}:{port}"
    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=10),
        ) as session:
            async with session.get(url, allow_redirects=False) as resp:
                if resp.status in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "")
                    return location.lower().startswith("https://")
                # Non-redirect from aiohttp — try requests fallback
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(None, _sync_check_redirect, url)
    except Exception:
        # aiohttp failed entirely — try requests fallback before giving up
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _sync_check_redirect, url)
        except Exception:
            return True  # both probes failed — suppress finding


async def web_fingerprint_fallback(target: str, port: int = 80, ssl: bool = False) -> dict:
    """Fallback web fingerprinting when GOD'S EYE is unavailable."""
    import aiohttp
    import ssl as ssl_lib

    TECH_FINGERPRINTS = {
        "WordPress": [r"wp-content", r"wp-includes", r"WordPress"],
        "Joomla": [r"Joomla!", r"/components/com_"],
        "Drupal": [r"Drupal", r"/sites/default/"],
        "Laravel": [r"laravel_session", r"Laravel"],
        "Django": [r"csrfmiddlewaretoken", r"django"],
        "React": [r"react\.production\.min\.js", r"__NEXT_DATA__", r"data-reactroot"],
        "Angular": [r"ng-version", r"angular\.min\.js"],
        "Vue.js": [r"vue\.runtime", r"__vue__"],
        "Apache": [r"Apache/", r"Server: Apache"],
        "Nginx": [r"nginx/", r"Server: nginx"],
        "IIS": [r"Microsoft-IIS", r"X-Powered-By: ASP.NET"],
        "PHP": [r"X-Powered-By: PHP", r"PHPSESSID"],
    }

    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
        "ModSecurity": ["mod_security", "NAXSI", "modsec"],
        "Sucuri": ["sucuri", "x-sucuri-id"],
        "Imperva": ["imperva", "incapsula", "visid_incap"],
        "AWS WAF": ["awselb", "x-amzn-requestid"],
        "Akamai": ["akamai", "ak_bmsc"],
        "F5 BIG-IP": ["bigipserver", "f5_cspm"],
        "Barracuda": ["barra_counter_session", "barracuda_"],
    }

    proto = "https" if ssl or port == 443 else "http"
    url = f"{proto}://{target}:{port}" if port not in (80, 443) else f"{proto}://{target}"

    result = {
        "url": url, "status_code": None, "server": "", "technologies": [],
        "waf": None, "headers": {}, "error": None,
        "technologies_detailed": [], "waf_results": [], "cves": [], "vulns": [],
        "_body": "",
    }

    try:
        ssl_ctx = ssl_lib.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl_lib.CERT_NONE
        connector = aiohttp.TCPConnector(ssl=ssl_ctx)
        timeout = aiohttp.ClientTimeout(total=8)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get(url, allow_redirects=True) as resp:
                result["status_code"] = resp.status
                result["server"] = resp.headers.get("Server", "")
                result["headers"] = dict(resp.headers)
                body = await resp.text(errors="ignore")
                result["_body"] = body
                all_content = body + str(resp.headers)

                for tech, patterns in TECH_FINGERPRINTS.items():
                    for pattern in patterns:
                        if re.search(pattern, all_content, re.IGNORECASE):
                            if tech not in result["technologies"]:
                                result["technologies"].append(tech)
                            break

                headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                for waf, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if any(sig in v for v in headers_lower.values()):
                            result["waf"] = waf
                            break
                    if result["waf"]:
                        break
    except Exception as e:
        result["error"] = str(e)[:100]

    return result


async def run_recon(state: EngagementState, console=None,
                    stealth: bool = False, gods_eye_path: str = None) -> dict:
    target = state.target

    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    log(f"DNS lookup: {target}")
    dns = dns_lookup(target)

    port_list = STEALTH_PORTS if stealth else COMMON_PORTS
    timeout = 3.0 if stealth else 1.0
    log(f"Port scan ({len(port_list)} ports, stealth={stealth})...")
    open_ports = await port_scan(target, port_list, timeout=timeout, stealth=stealth)

    web_results = {}
    for port, info in open_ports.items():
        svc = info["service"]
        if svc in ("HTTP", "HTTP-Alt", "HTTPS", "HTTPS-Alt"):
            ssl = svc in ("HTTPS", "HTTPS-Alt")
            proto = "https" if ssl else "http"
            base_port = port
            url = f"{proto}://{target}:{base_port}" if base_port not in (80, 443) else f"{proto}://{target}"

            log(f"GOD'S EYE scan on {url}...")
            try:
                from modules.gods_eye_bridge import run_gods_eye_scan, gods_eye_to_recon_format
                ge_result = await run_gods_eye_scan(url, gods_eye_path)
                web_results[port] = gods_eye_to_recon_format(ge_result, port, ssl)
                if ge_result.get("error"):
                    log(f"  GOD'S EYE fallback: {ge_result['error']}")
                    web_results[port] = await web_fingerprint_fallback(target, port, ssl)
            except Exception as e:
                log(f"  Fingerprint fallback ({e})")
                web_results[port] = await web_fingerprint_fallback(target, port, ssl)

    recon_data = {
        "dns": dns,
        "open_ports": open_ports,
        "web": web_results,
        "stealth": stealth,
    }

    state.recon_data = recon_data

    # ── Generate findings ─────────────────────────────────────────────────────
    risky = {
        22: ("SSH", Severity.MEDIUM),
        23: ("Telnet", Severity.HIGH),
        445: ("SMB", Severity.MEDIUM),
        3389: ("RDP", Severity.MEDIUM),
        6379: ("Redis (no auth)", Severity.HIGH),
        27017: ("MongoDB (no auth)", Severity.HIGH),
        5900: ("VNC", Severity.HIGH),
    }
    for port, (svc, sev) in risky.items():
        if port in open_ports:
            f = Finding(
                title=f"{svc} exposed on port {port}",
                severity=sev,
                description=f"{svc} service detected. May allow unauthorized access.",
                evidence=f"Port {port} open, banner: {open_ports[port].get('banner', 'N/A')}",
                mitre_tactic="Discovery",
                mitre_technique="T1046 - Network Service Scanning",
                remediation=f"Restrict {svc} access via firewall. Use VPN or IP allowlist.",
                phase="recon",
            )
            if not any(x.title == f.title for x in state.findings):
                state.add_finding(f)

    def _add(finding):
        if not any(x.title == finding.title for x in state.findings):
            state.add_finding(finding)

    for port, wdata in web_results.items():
        # Pre-compute HTTPS-redirect flag.
        # Use the port number — not the stored URL — to identify HTTP ports,
        # because GOD'S EYE stores the *final* (post-redirect) URL.  For port 80
        # that redirects to HTTPS the stored URL already starts with "https://"
        # which would wrongly set _svc_is_http=False and skip the redirect check.
        redirects_to_https = False
        if port in (80, 8080):
            redirects_to_https = await _check_https_redirect(target, port)

        # If GOD'S EYE didn't populate response headers (the bridge omits them),
        # fetch them with a single HEAD request so header-presence filters work.
        if not wdata.get("headers"):
            wdata["headers"] = await _fetch_response_headers(wdata.get("url", ""))

        if wdata.get("waf"):
            _add(Finding(
                title=f"WAF detected: {wdata['waf']} on port {port}",
                severity=Severity.INFO,
                description=f"{wdata['waf']} WAF protecting port {port}. Bypass attempts needed.",
                evidence="WAF signatures found in response headers",
                mitre_tactic="Defense Evasion",
                mitre_technique="T1562 - Impair Defenses",
                phase="recon",
            ))

        # GOD'S EYE CVE findings
        for cve in wdata.get("cves", []):
            if cve.get("cvss_score", 0) >= 7.0:
                sev = Severity.CRITICAL if cve["cvss_score"] >= 9.0 else Severity.HIGH
                _add(Finding(
                    title=f"{cve['cve_id']}: {cve['technology']} vulnerability",
                    severity=sev,
                    description=cve["description"][:300],
                    evidence=f"Detected version matches affected range: {cve['affected_versions']}",
                    mitre_tactic="Initial Access",
                    mitre_technique="T1190 - Exploit Public-Facing Application",
                    remediation=f"Upgrade {cve['technology']} to version {cve['fixed_version']} or later.",
                    cvss=cve["cvss_score"],
                    phase="recon",
                ))

        # GOD'S EYE vuln findings
        for vuln in wdata.get("vulns", []):
            vuln_name    = vuln.get("name", "")
            evidence     = vuln.get("evidence", "")
            vuln_name_lc = vuln_name.lower()
            server_hdr   = wdata.get("server", "")
            body_text    = wdata.get("_body", "")
            technologies = wdata.get("technologies", [])

            # ── False-positive guards ─────────────────────────────────────────

            # 1. "HTTPS not used / missing / not enforced / HTTP only"
            #    Match any vuln whose name suggests HTTPS is absent.
            #    • URL already https:// OR port is 443/8443 → skip unconditionally
            #    • HTTP port that redirects → HTTPS → skip
            #    • Any other HTTP port where redirect check failed → skip
            #      (redirect check returns True on exception → benefit of doubt)
            _is_https_vuln = (
                "https" in vuln_name_lc
                and any(w in vuln_name_lc for w in ("not", "miss", "no ", "lack", "without", "enforc"))
            ) or "http only" in vuln_name_lc
            if _is_https_vuln:
                _url_is_https = wdata.get("url", "").startswith("https://")
                if _url_is_https or port in (443, 8443):
                    continue
                if redirects_to_https:   # True for HTTP ports that redirect, or on exception
                    continue

            # 2. "Open redirect" — only flag when Location is an absolute URL
            #    pointing to a host OTHER than the target.
            #    Relative paths (/foo), same-domain URLs, and missing Location
            #    are all skipped.
            if "redirect" in vuln_name_lc:
                loc_match = re.search(r'[Ll]ocation:\s*(\S+)', evidence)
                if loc_match:
                    location = loc_match.group(1)
                    is_absolute = (location.startswith("http://") or
                                   location.startswith("https://"))
                    is_external = target not in location
                    if not (is_absolute and is_external):
                        continue
                else:
                    # No Location in evidence — can't verify, skip
                    continue

            # 3. "jQuery outdated / vulnerable" — skip when jQuery not on the page
            if "jquery" in vuln_name_lc:
                jquery_present = (
                    any("jquery" in t.lower() for t in technologies)
                    or "jquery" in body_text.lower()
                )
                if not jquery_present:
                    continue

            # 4. "Server version disclosed / banner" — skip when Server header
            #    contains only a product name with no version number.
            if "server" in vuln_name_lc and any(w in vuln_name_lc for w in ("version", "banner", "disclos")):
                if not re.search(r'\w+/\d+[\d.]+', server_hdr):
                    continue

            # 5. "X-Content-Type-Options missing / not set"
            #    Primary check: case-insensitive header lookup in wdata["headers"].
            #    Fallback: if "nosniff" appears in the evidence the header IS set —
            #    some scanner backends embed the header value rather than storing
            #    it in the headers dict.
            if "x-content-type-options" in vuln_name_lc:
                _resp_hdrs_lc = {k.lower() for k in wdata.get("headers", {}).keys()}
                _xcto_in_hdrs = "x-content-type-options" in _resp_hdrs_lc
                _xcto_in_evidence = "nosniff" in evidence.lower()
                if _xcto_in_hdrs or _xcto_in_evidence:
                    continue

            sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                       "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO}
            sev = sev_map.get(vuln.get("severity", "INFO"), Severity.INFO)
            _add(Finding(
                title=vuln_name,
                severity=sev,
                description=evidence[:300],
                evidence=evidence,
                mitre_tactic="Discovery",
                mitre_technique="T1083 - File and Directory Discovery",
                remediation=vuln.get("recommendation", ""),
                phase="recon",
            ))

    state.recon_data.update({"gods_eye_used": True})
    state.add_note(f"Recon complete: {len(open_ports)} open ports, {len(web_results)} web services")
    return recon_data
