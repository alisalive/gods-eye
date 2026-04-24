# AI Attack Orchestrator — Claude Code Instructions

Read this file completely before doing anything. Implement everything described here.

---

## Project Overview

AI Attack Orchestrator is an AI-powered penetration testing and red team tool built in Python.
It uses Claude (Anthropic API): recon -> web analysis -> AD attack -> AI analysis -> HTML report.

**Current structure:**
```
ai_attack_orchestrator/
├── main.py                  <- CLI entry point (Rich TUI)
├── core/orchestrator.py     <- State machine, Finding, EngagementState
├── modules/
│   ├── recon.py             <- Async port scan, DNS, WAF, tech fingerprint
│   ├── web.py               <- Security headers, endpoint enum, SQLi, WAF bypass
│   ├── ad.py                <- AD port check, SMB signing, attack chain
│   └── ai_engine.py         <- Claude API analysis engine
└── output/report.py         <- HTML + JSON report generator
```

---

## TASK 1: GOD'S EYE Integration

GOD'S EYE is at: C:\Users\User\Documents\GODs_EYE\

Structure:
- gods_eye/engine.py        <- Main async scan engine
- gods_eye/fingerprint.py   <- 35+ technology fingerprints
- gods_eye/waf.py           <- WAF detection
- gods_eye/crawler.py       <- Web crawler
- gods_eye/vuln.py          <- Vulnerability checks
- gods_eye/cve.py           <- CVE matching
- gods_eye/output.py        <- Output formatting

Steps:
1. Read ALL files in C:\Users\User\Documents\GODs_EYE\gods_eye\
2. Read C:\Users\User\Documents\GODs_EYE\main.py
3. Create modules/gods_eye_bridge.py - bridge between GOD'S EYE and orchestrator
4. Update modules/recon.py - replace simple port scan with GOD'S EYE engine
5. Add GODs_EYE path to sys.path for imports
6. Add all GOD'S EYE results to EngagementState.recon_data

---

## TASK 2: New Modules

### modules/subdomain.py
- Subdomain brute-force using dnspython
- Create config/wordlists/subdomains.txt with 500+ subdomains
- Async - check 50 subdomains at once
- Run recon on each found subdomain
- Add subdomains field to EngagementState
- Create Finding for each found subdomain

### modules/screenshot.py
- Use playwright (asyncio) for screenshots
- Screenshot every open web port
- Save to reports/screenshots/
- Embed in HTML report as base64
- If playwright missing - skip gracefully

### modules/waf_bypass.py
- WAF-specific payloads: Cloudflare, ModSecurity, Akamai, F5, Generic
- Types: XSS, SQLi, LFI, XXE, SSRF, RCE, Path Traversal
- Encodings: URL, double URL, unicode, HTML entity, base64
- Add to ai_engine.py: async def generate_waf_bypass(waf_type, vuln_type) -> list[str]
- Integrate into web.py - suggest bypass payloads when WAF detected

### modules/opsec.py
- Calculate OPSEC score (0-100) for red team mode
- Deductions: port scan -15, web crawl -10, SQLi -20, AD enum -15, WAF bypass -25
- Bonuses: UA rotation +10, delays +10, stealth mode +20
- Use existing opsec_score in EngagementState
- Show live score in TUI
- Add OPSEC section to report

### modules/cve.py
- NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
- Search by detected technology + version
- Also use GOD'S EYE cve.py
- CVSS 7.0+ -> HIGH/CRITICAL finding
- Cache in config/cve_cache.json

### utils/logger.py
- Log to logs/engagement_TIMESTAMP.log
- Levels: DEBUG, INFO, WARNING, ERROR
- Mask passwords/hashes with ****

---

## TASK 3: Update Existing Files

### modules/ad.py - add:
- LDAP anonymous bind check (ldap3)
- Null session SMB check
- MS17-010 fingerprint on port 445
- Kerberos pre-auth enumeration (raw socket, no impacket)
- BloodHound JSON import if bloodhound.json exists
- ntlmrelayx scenario when SMB signing disabled

### output/report.py - add:
- Base64 embedded screenshots
- CVE table section
- OPSEC timeline (red team mode)
- Executive Summary (AI written)
- ASCII kill chain diagram
- Print-friendly CSS
- Dark mode toggle (JavaScript)

### main.py - add flags:
--stealth          Enable stealth mode
--interactive      Pause between phases
--subdomains       Enable subdomain enum
--screenshot       Enable screenshots
--config PATH      Config file path
--output-dir PATH  Output directory
--no-report        Skip report
--api-key KEY      Anthropic API key

### New phase order:
Phase 0: Load config
Phase 1: Recon (GOD'S EYE)
Phase 2: Subdomain enum (if --subdomains)
Phase 3: Web + WAF bypass
Phase 4: AD analysis
Phase 5: CVE correlation
Phase 6: Screenshots (if --screenshot)
Phase 7: AI analysis
Phase 8: Report

### Stealth mode behavior:
- Random 1-3s delay between requests
- Rotate User-Agent (10+ browsers)
- Slow sequential port scan (3s timeout)
- Random extra HTTP headers
- OPSEC +20 bonus

---

## TASK 4: Config File

Create config/config.yaml:

scan:
  timeout: 2.0
  max_parallel_ports: 50
  port_list: "common"

ai:
  model: "claude-sonnet-4-20250514"
  max_tokens: 2000
  enabled: true

output:
  screenshots: true
  json: true
  html: true
  open_browser: false

stealth:
  min_delay: 1.0
  max_delay: 3.0
  rotate_ua: true

paths:
  gods_eye: "C:\\Users\\User\\Documents\\GODs_EYE"
  wordlists: "./config/wordlists"
  reports: "./reports"

---

## TASK 5: Wordlists

Create config/wordlists/subdomains.txt (500+ entries):
www, mail, ftp, admin, portal, dev, staging, test, api, app,
vpn, remote, webmail, blog, shop, store, cdn, static, media,
images, img, assets, files, docs, wiki, help, support, status,
beta, alpha, demo, sandbox, uat, qa, prod, production, backup,
db, database, mysql, redis, mongo, elastic, kibana, grafana,
jenkins, gitlab, github, git, jira, confluence, sonar,
smtp, pop, imap, mx, ns1, ns2, dns, ntp, proxy, gateway,
internal, intranet, corporate, hr, finance, accounting, crm,
auth, login, sso, oauth, id, identity, accounts, profile,
payment, payments, billing, invoice, order, orders, cart,
search, graphql, rest, webhook, monitor, monitoring, splunk,
log, logs, logging, audit, security, waf, ids, ips, firewall,
mobile, android, ios, download, upload, video, audio, stream,
chat, forum, community, social, m, www2, old, new, secure,
dashboard, panel, cp, cpanel, whm, plesk, phpmyadmin, pma

Create config/wordlists/endpoints.txt (200+ sensitive paths)
Create config/wordlists/passwords.txt (top 100 weak passwords)

---

## TASK 6: Tests

Create tests/test_recon.py - mock socket port scan test
Create tests/test_web.py - mock aiohttp header check test
Create tests/test_report.py - empty state report generation test

---

## TASK 7: Setup Script

Create setup.bat:
@echo off
echo Installing dependencies...
pip install -r requirements.txt
playwright install chromium
echo Setup complete!
pause

Update requirements.txt:
rich>=13.0.0
typer>=0.9.0
aiohttp>=3.9.0
anthropic>=0.25.0
pydantic>=2.0.0
requests>=2.31.0
dnspython>=2.4.0
playwright>=1.40.0
ldap3>=2.9.0
PyYAML>=6.0.0
packaging>=23.0

---

## Important Notes

1. Windows paths: use os.path.join, never hardcode backslashes
2. Python 3.13 compatibility required
3. All I/O must use asyncio
4. Every module needs try/except - one failure must not stop others
5. GOD'S EYE path from config.yaml: C:\Users\User\Documents\GODs_EYE
6. Always show "For authorized security testing only" disclaimer
7. Never hardcode API keys - use --api-key flag or ANTHROPIC_API_KEY env var

---

## Test After Implementation

Basic test:
python main.py --target 127.0.0.1 --mode pentest --skip-ai

Full test:
python main.py --target TARGET_IP --mode redteam --stealth --subdomains --screenshot
