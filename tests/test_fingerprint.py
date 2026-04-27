"""
Tests for modules/fingerprint.py — technology fingerprinting.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.fingerprint import (
    _hget,
    detect_server,
    detect_language,
    detect_cms_from_headers,
    detect_cms_from_body,
    detect_frameworks_from_body,
    run_fingerprint,
)


# ══════════════════════════════════════════════════════════════════════════════
# _hget helper
# ══════════════════════════════════════════════════════════════════════════════

class TestHget:
    def test_exact_key(self):
        assert _hget({"Server": "nginx"}, "Server") == "nginx"

    def test_lowercase_key(self):
        assert _hget({"server": "nginx"}, "Server") == "nginx"

    def test_uppercase_key(self):
        assert _hget({"SERVER": "nginx"}, "Server") == "nginx"

    def test_missing_returns_empty(self):
        assert _hget({}, "Server") == ""

    def test_first_non_empty_wins(self):
        assert _hget({"Server": "Apache"}, "Server", "X-Powered-By") == "Apache"

    def test_falls_through_to_second(self):
        # First key absent → should return value of second key
        assert _hget({"X-Powered-By": "PHP/8.1"}, "Server", "X-Powered-By") == "PHP/8.1"


# ══════════════════════════════════════════════════════════════════════════════
# detect_server
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectServer:
    def test_apache_with_version(self):
        r = detect_server({"Server": "Apache/2.4.54 (Ubuntu)"})
        assert len(r) == 1
        assert r[0]["name"] == "Apache"
        assert r[0]["version"] == "2.4.54"
        assert r[0]["confidence"] == "high"
        assert r[0]["category"] == "Server"

    def test_apache_no_version(self):
        r = detect_server({"Server": "Apache"})
        assert r[0]["name"] == "Apache"
        assert r[0]["version"] == ""

    def test_nginx_with_version(self):
        r = detect_server({"Server": "nginx/1.24.0"})
        assert r[0]["name"] == "Nginx"
        assert r[0]["version"] == "1.24.0"

    def test_nginx_no_version(self):
        r = detect_server({"Server": "nginx"})
        assert r[0]["name"] == "Nginx"

    def test_iis_with_version(self):
        r = detect_server({"Server": "Microsoft-IIS/10.0"})
        assert r[0]["name"] == "IIS"
        assert r[0]["version"] == "10.0"

    def test_werkzeug_flask(self):
        r = detect_server({"Server": "Werkzeug/2.3.4 Python/3.11.0"})
        names = [e["name"] for e in r]
        assert "Flask/Werkzeug" in names
        wz = next(e for e in r if e["name"] == "Flask/Werkzeug")
        assert wz["version"] == "2.3.4"
        assert wz["category"] == "Framework"

    def test_unknown_server_returns_empty(self):
        assert detect_server({"Server": "CoolServer/99"}) == []

    def test_no_server_header(self):
        assert detect_server({}) == []

    def test_lowercase_header(self):
        r = detect_server({"server": "nginx/1.18.0"})
        assert r[0]["name"] == "Nginx"


# ══════════════════════════════════════════════════════════════════════════════
# detect_language
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectLanguage:
    def test_php_with_version(self):
        r = detect_language({"X-Powered-By": "PHP/8.2.1"})
        assert r[0]["name"] == "PHP"
        assert r[0]["version"] == "8.2.1"
        assert r[0]["category"] == "Language"

    def test_php_no_version(self):
        r = detect_language({"X-Powered-By": "PHP"})
        assert r[0]["name"] == "PHP"
        assert r[0]["version"] == ""

    def test_express_node(self):
        r = detect_language({"X-Powered-By": "Express"})
        assert r[0]["name"] == "Node.js/Express"
        assert r[0]["category"] == "Server"

    def test_no_header(self):
        assert detect_language({}) == []

    def test_lowercase_header(self):
        r = detect_language({"x-powered-by": "PHP/7.4.33"})
        assert r[0]["name"] == "PHP"


# ══════════════════════════════════════════════════════════════════════════════
# detect_cms_from_headers
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectCmsFromHeaders:
    def test_drupal_x_generator(self):
        r = detect_cms_from_headers({"X-Generator": "Drupal 10 (https://www.drupal.org)"})
        assert r[0]["name"] == "Drupal"
        assert r[0]["version"] == "10"
        assert r[0]["confidence"] == "high"

    def test_drupal_x_generator_no_version(self):
        r = detect_cms_from_headers({"X-Generator": "Drupal"})
        assert r[0]["name"] == "Drupal"
        assert r[0]["version"] == ""

    def test_drupal_cache_header(self):
        r = detect_cms_from_headers({"X-Drupal-Cache": "HIT"})
        names = [e["name"] for e in r]
        assert "Drupal" in names

    def test_drupal_dynamic_cache_header(self):
        r = detect_cms_from_headers({"X-Drupal-Dynamic-Cache": "UNCACHEABLE"})
        names = [e["name"] for e in r]
        assert "Drupal" in names

    def test_wordpress_x_generator(self):
        r = detect_cms_from_headers({"X-Generator": "WordPress 6.4.2"})
        assert r[0]["name"] == "WordPress"
        assert r[0]["version"] == "6.4.2"

    def test_no_relevant_headers(self):
        assert detect_cms_from_headers({"Content-Type": "text/html"}) == []


# ══════════════════════════════════════════════════════════════════════════════
# detect_cms_from_body
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectCmsFromBody:
    _WP_BODY = """
    <html>
      <head>
        <meta name="generator" content="WordPress 6.4.2">
        <link rel="stylesheet" href="/wp-content/themes/mytheme/style.css">
      </head>
      <body><script src="/wp-includes/js/jquery/jquery.min.js"></script></body>
    </html>"""

    _JOOMLA_BODY = """
    <html>
      <head><meta name="generator" content="Joomla! 4.3.3"></head>
      <body><script src="/media/system/js/core.min.js"></script></body>
    </html>"""

    _DRUPAL_BODY = """
    <html><body>
      <script>var drupalSettings = {"path": "/"};</script>
      <link href="/sites/default/files/css/style.css" rel="stylesheet">
    </body></html>"""

    def test_wordpress_detected(self):
        r = detect_cms_from_body(self._WP_BODY)
        names = [e["name"] for e in r]
        assert "WordPress" in names

    def test_wordpress_version_extracted(self):
        r = detect_cms_from_body(self._WP_BODY)
        wp = next(e for e in r if e["name"] == "WordPress")
        assert wp["version"] == "6.4.2"

    def test_joomla_detected(self):
        r = detect_cms_from_body(self._JOOMLA_BODY)
        names = [e["name"] for e in r]
        assert "Joomla" in names

    def test_joomla_version_extracted(self):
        r = detect_cms_from_body(self._JOOMLA_BODY)
        joomla = next(e for e in r if e["name"] == "Joomla")
        assert joomla["version"] == "4.3.3"

    def test_drupal_detected(self):
        r = detect_cms_from_body(self._DRUPAL_BODY)
        names = [e["name"] for e in r]
        assert "Drupal" in names

    def test_generic_generator_tag(self):
        body = '<meta name="generator" content="MyCustomCMS 2.0">'
        r = detect_cms_from_body(body)
        names = [e["name"] for e in r]
        assert any("MyCustomCMS" in n for n in names)

    def test_empty_body(self):
        assert detect_cms_from_body("") == []
        assert detect_cms_from_body(None) == []

    def test_no_cms_markers(self):
        body = "<html><body><p>Hello world</p></body></html>"
        # Plain page — no CMS markers
        r = detect_cms_from_body(body)
        # No WordPress/Joomla/Drupal should be detected
        names = [e["name"] for e in r]
        assert "WordPress" not in names
        assert "Joomla" not in names
        assert "Drupal" not in names


# ══════════════════════════════════════════════════════════════════════════════
# detect_frameworks_from_body
# ══════════════════════════════════════════════════════════════════════════════

class TestDetectFrameworksFromBody:
    def test_nextjs(self):
        body = '<script id="__NEXT_DATA__" type="application/json">{}</script>'
        r = detect_frameworks_from_body(body)
        assert any(e["name"] == "Next.js" for e in r)

    def test_nextjs_static_path(self):
        body = '<script src="/_next/static/chunks/main.js"></script>'
        r = detect_frameworks_from_body(body)
        assert any(e["name"] == "Next.js" for e in r)

    def test_vuejs(self):
        body = '<div id="app" __vue_app__></div>'
        r = detect_frameworks_from_body(body)
        assert any(e["name"] == "Vue.js" for e in r)

    def test_angular_with_version(self):
        body = '<app-root ng-version="17.3.1"></app-root>'
        r = detect_frameworks_from_body(body)
        ang = next((e for e in r if e["name"] == "Angular"), None)
        assert ang is not None
        assert ang["version"] == "17.3.1"
        assert ang["confidence"] == "high"

    def test_angular_script_ref(self):
        body = '<script src="/assets/angular.min.js"></script>'
        r = detect_frameworks_from_body(body)
        assert any(e["name"] == "Angular" for e in r)

    def test_jquery_with_version(self):
        body = '<script src="/js/jquery-3.7.1.min.js"></script>'
        r = detect_frameworks_from_body(body)
        jq = next((e for e in r if e["name"] == "jQuery"), None)
        assert jq is not None
        assert jq["version"] == "3.7.1"
        assert jq["confidence"] == "high"

    def test_jquery_no_version(self):
        body = '<script src="/js/jquery.min.js"></script>'
        r = detect_frameworks_from_body(body)
        assert any(e["name"] == "jQuery" for e in r)

    def test_bootstrap_with_version(self):
        body = '<link href="/css/bootstrap-5.3.2.min.css" rel="stylesheet">'
        r = detect_frameworks_from_body(body)
        bs = next((e for e in r if e["name"] == "Bootstrap"), None)
        assert bs is not None
        assert bs["version"] == "5.3.2"

    def test_django_csrf(self):
        body = '<input type="hidden" name="csrfmiddlewaretoken" value="abc123">'
        r = detect_frameworks_from_body(body)
        assert any(e["name"] == "Django" for e in r)

    def test_laravel(self):
        body = '<meta name="csrf-token" content="xxx"> laravel_session cookie'
        r = detect_frameworks_from_body(body)
        assert any(e["name"] == "Laravel" for e in r)

    def test_flask_session_token(self):
        body = 'Set-Cookie: session=eyJrZXkiOiJ2YWx1ZSJ9.abc123.signature'
        r = detect_frameworks_from_body(body)
        assert any(e["name"] == "Flask" for e in r)

    def test_empty_body(self):
        assert detect_frameworks_from_body("") == []
        assert detect_frameworks_from_body(None) == []


# ══════════════════════════════════════════════════════════════════════════════
# run_fingerprint (async, mocked I/O)
# ══════════════════════════════════════════════════════════════════════════════

_WORDPRESS_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta name="generator" content="WordPress 6.4.2">
  <link rel="stylesheet" href="/wp-content/themes/theme/style.css?ver=6.4.2">
</head>
<body>
  <script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
</body>
</html>"""

_APACHE_HEADERS = {"Server": "Apache/2.4.54 (Ubuntu)", "X-Powered-By": "PHP/8.2.0"}


@pytest.mark.asyncio
async def test_run_fingerprint_detects_wordpress():
    async def fake_fetch(url, timeout=10):
        if url.endswith("/wp-login.php"):
            return 200, {}, "<html>WordPress login</html>", []
        if url.endswith("/administrator/") or url.endswith("/sites/default/"):
            return 404, {}, "", []
        return 200, _APACHE_HEADERS, _WORDPRESS_HTML, []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    names = [t["name"] for t in result["technologies"]]
    assert "WordPress" in names
    assert "Apache" in names
    assert "PHP" in names


@pytest.mark.asyncio
async def test_run_fingerprint_extracts_wordpress_version():
    async def fake_fetch(url, timeout=10):
        return 200, _APACHE_HEADERS, _WORDPRESS_HTML, []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    wp = next((t for t in result["technologies"] if t["name"] == "WordPress"), None)
    assert wp is not None
    assert wp["version"] == "6.4.2"


@pytest.mark.asyncio
async def test_run_fingerprint_deduplicates():
    """WordPress detected via body AND via /wp-login.php — only one entry."""
    async def fake_fetch(url, timeout=10):
        if url.endswith("/wp-login.php"):
            return 200, {}, "<html>wp-login</html>", []
        return 200, {}, _WORDPRESS_HTML, []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    wp_entries = [t for t in result["technologies"] if t["name"] == "WordPress"]
    assert len(wp_entries) == 1


@pytest.mark.asyncio
async def test_run_fingerprint_failed_fetch_returns_empty():
    async def fake_fetch(url, timeout=10):
        return 0, {}, "", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://unreachable.example")

    assert result["technologies"] == []


@pytest.mark.asyncio
async def test_run_fingerprint_result_schema():
    """Every technology entry must have the required keys with correct types."""
    async def fake_fetch(url, timeout=10):
        if url.endswith("/wp-login.php"):
            return 200, {}, "", []
        return 200, {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.1"}, _WORDPRESS_HTML, []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    for t in result["technologies"]:
        assert "name"       in t and isinstance(t["name"],       str)
        assert "version"    in t and isinstance(t["version"],    str)
        assert "confidence" in t and t["confidence"] in ("high", "medium", "low")
        assert "category"   in t and isinstance(t["category"],   str)
        assert "evidence"   in t and isinstance(t["evidence"],   str)


@pytest.mark.asyncio
async def test_run_fingerprint_nginx():
    async def fake_fetch(url, timeout=10):
        return 200, {"Server": "nginx/1.25.3"}, "<html></html>", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    ng = next((t for t in result["technologies"] if t["name"] == "Nginx"), None)
    assert ng is not None
    assert ng["version"] == "1.25.3"


@pytest.mark.asyncio
async def test_run_fingerprint_angular_version():
    body = '<app-root ng-version="16.2.12"></app-root>'

    async def fake_fetch(url, timeout=10):
        return 200, {}, body, []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    ang = next((t for t in result["technologies"] if t["name"] == "Angular"), None)
    assert ang is not None
    assert ang["version"] == "16.2.12"


@pytest.mark.asyncio
async def test_run_fingerprint_cms_probe_joomla_403():
    """A 403 on /administrator/ still signals Joomla with medium confidence."""
    async def fake_fetch(url, timeout=10):
        if "/administrator/" in url:
            return 403, {}, "Forbidden", []
        return 200, {}, "<html></html>", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://example.com")

    joomla = next((t for t in result["technologies"] if t["name"] == "Joomla"), None)
    assert joomla is not None
    assert joomla["confidence"] in ("high", "medium")


@pytest.mark.asyncio
async def test_run_fingerprint_returns_base_url():
    async def fake_fetch(url, timeout=10):
        return 0, {}, "", []

    with patch("modules.fingerprint._fetch_page", side_effect=fake_fetch):
        result = await run_fingerprint("https://target.example.com")

    assert result["base_url"] == "https://target.example.com"
