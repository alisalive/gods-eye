"""
Technology / Version Fingerprinting — detects CMS, frameworks, servers, languages.

All network I/O is routed through the _fetch_page() primitive so tests can
patch it without spinning up a real HTTP server.
"""

import re

# ── Module-level I/O primitive (patchable in tests) ──────────────────────────

async def _fetch_page(url: str, timeout: int = 10) -> tuple:
    """
    Async GET; returns (status, headers_dict, body, set_cookie_list).
    Returns (0, {}, '', []) on any failure.
    set_cookie_list contains raw Set-Cookie header strings (may have duplicates).
    """
    try:
        import aiohttp
        import ssl as ssl_lib
        ctx = ssl_lib.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_lib.CERT_NONE
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=ctx),
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"},
        ) as s:
            async with s.get(url, allow_redirects=True) as resp:
                body = await resp.text(errors="ignore")
                headers = dict(resp.headers)
                try:
                    set_cookies = list(resp.headers.getall("Set-Cookie", []))
                except (AttributeError, TypeError):
                    set_cookies = []
                return resp.status, headers, body, set_cookies
    except Exception:
        return 0, {}, "", []


# ── Helper ────────────────────────────────────────────────────────────────────

def _hget(headers: dict, *keys: str) -> str:
    """Case-insensitive multi-key header lookup; returns first non-empty value."""
    for key in keys:
        val = (headers.get(key) or headers.get(key.lower()) or
               headers.get(key.upper()) or "")
        if val:
            return val
    return ""


# ── Pure detection functions (all testable without I/O) ──────────────────────

def detect_server(headers: dict) -> list:
    """Detect web server name and version from the Server header."""
    results = []
    server = _hget(headers, "Server")
    if not server:
        return results

    # Apache
    m = re.match(r"Apache(?:/([\d.]+\w*))?", server, re.IGNORECASE)
    if m:
        results.append({"name": "Apache", "version": m.group(1) or "",
                        "confidence": "high", "category": "Server",
                        "evidence": f"Server: {server}"})

    # Nginx
    m = re.match(r"nginx(?:/([\d.]+\w*))?", server, re.IGNORECASE)
    if m:
        results.append({"name": "Nginx", "version": m.group(1) or "",
                        "confidence": "high", "category": "Server",
                        "evidence": f"Server: {server}"})

    # IIS
    m = re.match(r"Microsoft-IIS(?:/([\d.]+\w*))?", server, re.IGNORECASE)
    if m:
        results.append({"name": "IIS", "version": m.group(1) or "",
                        "confidence": "high", "category": "Server",
                        "evidence": f"Server: {server}"})

    # Flask / Werkzeug
    if re.search(r"Werkzeug", server, re.IGNORECASE):
        mv = re.search(r"Werkzeug/([\d.]+)", server, re.IGNORECASE)
        results.append({"name": "Flask/Werkzeug", "version": mv.group(1) if mv else "",
                        "confidence": "high", "category": "Framework",
                        "evidence": f"Server: {server}"})

    return results


def detect_language(headers: dict) -> list:
    """Detect backend language/runtime from X-Powered-By header."""
    results = []
    powered_by = _hget(headers, "X-Powered-By")
    if not powered_by:
        return results

    # PHP
    m = re.search(r"PHP(?:/([\d.]+\w*))?", powered_by, re.IGNORECASE)
    if m:
        results.append({"name": "PHP", "version": m.group(1) or "",
                        "confidence": "high", "category": "Language",
                        "evidence": f"X-Powered-By: {powered_by}"})

    # Node.js / Express
    if re.search(r"\bExpress\b", powered_by, re.IGNORECASE):
        results.append({"name": "Node.js/Express", "version": "",
                        "confidence": "high", "category": "Server",
                        "evidence": f"X-Powered-By: {powered_by}"})

    return results


def detect_cms_from_headers(headers: dict) -> list:
    """Detect CMS from response-only headers (X-Generator, X-Drupal-Cache)."""
    results = []

    xgen = _hget(headers, "X-Generator")
    if xgen:
        m = re.search(r"Drupal\s*([\d.]+)?", xgen, re.IGNORECASE)
        if m:
            results.append({"name": "Drupal", "version": m.group(1) or "",
                            "confidence": "high", "category": "CMS",
                            "evidence": f"X-Generator: {xgen}"})
        else:
            mv = re.search(r"WordPress\s*([\d.]+)", xgen, re.IGNORECASE)
            if mv or re.search(r"WordPress", xgen, re.IGNORECASE):
                results.append({"name": "WordPress",
                                "version": mv.group(1) if mv else "",
                                "confidence": "high", "category": "CMS",
                                "evidence": f"X-Generator: {xgen}"})

    if _hget(headers, "X-Drupal-Cache") or _hget(headers, "X-Drupal-Dynamic-Cache"):
        results.append({"name": "Drupal", "version": "",
                        "confidence": "high", "category": "CMS",
                        "evidence": "X-Drupal-Cache header present"})

    return results


def _joomla_body_indicators(body: str) -> tuple:
    """
    Count Joomla-specific indicators present in an HTML body.

    Checks three body-only signals:
      1. /media/system/js/ path referenced in HTML
      2. <meta name="generator"> contains "Joomla"
      3. literal "Joomla!" text appears in the page

    Returns (score: int, evidence: list[str]).
    A score of 2+ is required before reporting Joomla — this prevents false
    positives on sites (e.g. Bitrix, Laravel) that share superficially similar
    path patterns such as /components/com_*.
    """
    score = 0
    evidence: list = []

    if re.search(r'/media/system/js/', body, re.IGNORECASE):
        score += 1
        evidence.append("/media/system/js/ path in HTML")

    if (re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*Joomla',
                  body, re.IGNORECASE)
            or re.search(r'content=["\'][^"\']*Joomla[^"\']*["\'][^>]+name=["\']generator["\']',
                         body, re.IGNORECASE)):
        score += 1
        evidence.append("meta generator: Joomla")

    if re.search(r'\bJoomla!', body):
        score += 1
        evidence.append('"Joomla!" text in body')

    return score, evidence


def detect_cms_from_body(body: str) -> list:
    """Detect CMS from HTML body (asset paths, meta generator tag)."""
    results = []
    if not body:
        return results

    # WordPress — asset paths are the most reliable indicator
    if re.search(r'/wp-includes/|/wp-content/|/wp-json/', body, re.IGNORECASE):
        version = ""
        m = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*WordPress\s+([\d.]+)',
            body, re.IGNORECASE,
        )
        if not m:
            m = re.search(
                r'content=["\'][^"\']*WordPress\s+([\d.]+)[^"\']*["\'][^>]+name=["\']generator["\']',
                body, re.IGNORECASE,
            )
        if m:
            version = m.group(1)
        results.append({"name": "WordPress", "version": version,
                        "confidence": "high", "category": "CMS",
                        "evidence": "/wp-includes/ or /wp-content/ paths in HTML"})

    # Joomla — require 2+ distinct indicators to prevent false positives.
    # A single path pattern like /components/com_* also appears in Bitrix,
    # Laravel, and other frameworks, so it is deliberately excluded here.
    _jscore, _jev = _joomla_body_indicators(body)
    if _jscore >= 2:
        version = ""
        m = re.search(r'content=["\'][^"\']*Joomla!\s*([\d.]+)', body, re.IGNORECASE)
        if m:
            version = m.group(1)
        results.append({"name": "Joomla", "version": version,
                        "confidence": "high", "category": "CMS",
                        "evidence": "; ".join(_jev)})
    # _jscore == 1: only one body signal — not reported from body alone;
    # run_fingerprint() may still promote to "high" via /administrator/ probe.

    # Drupal
    if re.search(r'/sites/default/files/|drupalSettings|Drupal\.settings', body, re.IGNORECASE):
        version = ""
        m = re.search(r'"version"\s*:\s*"(\d[\d.]+)"', body)
        if m:
            version = m.group(1)
        results.append({"name": "Drupal", "version": version,
                        "confidence": "medium", "category": "CMS",
                        "evidence": "/sites/default/ or drupalSettings in HTML"})

    # Generic meta generator — catch remaining CMS that expose themselves
    m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        body, re.IGNORECASE,
    )
    if not m:
        m = re.search(
            r'content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']',
            body, re.IGNORECASE,
        )
    if m:
        gen = m.group(1).strip()
        already_detected = {"wordpress", "joomla", "drupal"}
        if not any(k in gen.lower() for k in already_detected) and 2 < len(gen) < 80:
            results.append({"name": gen, "version": "",
                            "confidence": "medium", "category": "CMS",
                            "evidence": f"meta generator: {gen}"})

    return results


def detect_frameworks_from_body(body: str) -> list:
    """Detect JS/server-side frameworks and libraries from page body."""
    results = []
    if not body:
        return results

    # Laravel
    if re.search(r'laravel_session|laravel\.js|Laravel\s+Framework', body, re.IGNORECASE):
        results.append({"name": "Laravel", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "laravel_session or Laravel reference in body"})

    # Django — CSRF middleware token is unmistakable
    if re.search(r'csrfmiddlewaretoken', body, re.IGNORECASE):
        results.append({"name": "Django", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "csrfmiddlewaretoken in HTML body"})

    # Flask — signed session cookies begin with eyJ (base64-encoded JSON)
    if re.search(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+', body):
        results.append({"name": "Flask", "version": "",
                        "confidence": "medium", "category": "Framework",
                        "evidence": "Flask-style signed session token in body"})

    # Next.js (React SSR)
    if re.search(r'__NEXT_DATA__|/_next/static/', body, re.IGNORECASE):
        results.append({"name": "Next.js", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "__NEXT_DATA__ or /_next/static/ in body"})
    elif re.search(r'data-react-root|__react_fiber|react-root', body, re.IGNORECASE):
        results.append({"name": "React", "version": "",
                        "confidence": "medium", "category": "Framework",
                        "evidence": "React root marker in body"})

    # Vue.js
    if re.search(r'__vue_app__|vue\.min\.js|vue\.global\.js', body, re.IGNORECASE):
        results.append({"name": "Vue.js", "version": "",
                        "confidence": "high", "category": "Framework",
                        "evidence": "__vue_app__ or Vue.js script in body"})

    # Angular — ng-version attribute discloses exact version
    m = re.search(r'ng-version=["\']?([\d.]+)', body, re.IGNORECASE)
    if m:
        results.append({"name": "Angular", "version": m.group(1),
                        "confidence": "high", "category": "Framework",
                        "evidence": f"ng-version={m.group(1)}"})
    elif re.search(r'angular(?:\.min)?\.js|/angular/core', body, re.IGNORECASE):
        results.append({"name": "Angular", "version": "",
                        "confidence": "medium", "category": "Framework",
                        "evidence": "angular.js script reference"})

    # jQuery — version from versioned filename
    m = re.search(r'["\'/]jquery[/\-]([\d.]+)(?:\.min)?\.js', body, re.IGNORECASE)
    if m:
        results.append({"name": "jQuery", "version": m.group(1),
                        "confidence": "high", "category": "Library",
                        "evidence": f"jquery-{m.group(1)}.js in asset path"})
    elif re.search(r'jquery(?:\.min)?\.js', body, re.IGNORECASE):
        results.append({"name": "jQuery", "version": "",
                        "confidence": "medium", "category": "Library",
                        "evidence": "jQuery script reference"})

    # Bootstrap — version from versioned filename
    m = re.search(r'bootstrap[/\-]([\d.]+)(?:\.min)?\.(?:css|js)', body, re.IGNORECASE)
    if m:
        results.append({"name": "Bootstrap", "version": m.group(1),
                        "confidence": "high", "category": "Library",
                        "evidence": f"bootstrap-{m.group(1)} in asset path"})

    return results


# ── CMS path probing ──────────────────────────────────────────────────────────

# Joomla is handled separately via _joomla_body_indicators + /administrator/ probe
# because it requires a multi-indicator score to avoid false positives.
_CMS_PROBE_PATHS = [
    ("/wp-login.php",   "WordPress", "CMS"),
    ("/sites/default/", "Drupal",    "CMS"),
]


# ── Main async entry point ────────────────────────────────────────────────────

async def run_fingerprint(base_url: str, console=None) -> dict:
    """
    Detect technologies for a single base_url.

    Combines:
      - Header-based detection (Server, X-Powered-By, X-Generator)
      - Body-based detection (asset paths, meta generator, framework markers)
      - CMS path probing (/wp-login.php, /administrator/, /sites/default/)

    Returns:
        {
            "base_url":     str,
            "technologies": [{"name", "version", "confidence", "category", "evidence"}, ...],
        }
    """
    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    technologies: list = []
    seen: set = set()

    def _add(entry: dict):
        key = entry["name"].lower()
        if key not in seen:
            seen.add(key)
            technologies.append(entry)

    log(f"Fingerprinting {base_url} ...")

    # 1. Homepage — headers + body analysis
    status, headers, body, _ = await _fetch_page(base_url, timeout=10)
    if status:
        for t in detect_server(headers):
            _add(t)
        for t in detect_language(headers):
            _add(t)
        for t in detect_cms_from_headers(headers):
            _add(t)
        for t in detect_cms_from_body(body):
            _add(t)
        for t in detect_frameworks_from_body(body):
            _add(t)

    # 2. CMS path probing (WordPress, Drupal)
    for path, cms_name, category in _CMS_PROBE_PATHS:
        url = base_url.rstrip("/") + path
        p_status, _, _, _ = await _fetch_page(url, timeout=6)
        if p_status in (200, 301, 302, 403):
            confidence = "high" if p_status in (200, 403) else "medium"
            _add({
                "name": cms_name, "version": "",
                "confidence": confidence, "category": category,
                "evidence": f"HTTP {p_status} on {path}",
            })

    # 3. Joomla — dedicated multi-indicator check (requires 2+ signals).
    #    Body analysis in detect_cms_from_body() already handles the case where
    #    2+ body indicators are present.  Here we handle the "1 body indicator +
    #    /administrator/ probe" path so we don't over-fire on non-Joomla sites.
    if "joomla" not in seen:
        _jscore, _jev = _joomla_body_indicators(body)
        if _jscore == 1:
            # One body indicator found — probe /administrator/ to confirm
            _adm_url = base_url.rstrip("/") + "/administrator/"
            _adm_status, _, _adm_body, _ = await _fetch_page(_adm_url, timeout=6)
            if (_adm_status == 200
                    and re.search(r'administrator|joomla', _adm_body or "", re.IGNORECASE)):
                _jev.append("HTTP 200 on /administrator/ with matching content")
                _jscore += 1

        if _jscore >= 2:
            _version = ""
            _vm = re.search(r'content=["\'][^"\']*Joomla!\s*([\d.]+)', body, re.IGNORECASE)
            if _vm:
                _version = _vm.group(1)
            _add({
                "name": "Joomla", "version": _version,
                "confidence": "high", "category": "CMS",
                "evidence": "; ".join(_jev),
            })

    return {"base_url": base_url, "technologies": technologies}
