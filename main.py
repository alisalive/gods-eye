#!/usr/bin/env python3
# Force UTF-8 output before any other imports (Windows cp1252 compatibility)
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
"""
GOD'S EYE v1.0.0 — Main CLI
For authorized security testing only.

Usage:
  python main.py --target 10.0.0.1 --mode pentest
  python main.py --target example.com --mode redteam --stealth --subdomains --screenshot
  python main.py --target 192.168.1.1 --mode pentest --ai --api-key sk-ant-... --output ./reports
"""

import asyncio
import os
import io
import time
import random
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich import box

from core.orchestrator import EngagementState, Mode, Phase, Severity
from modules.recon import run_recon
from modules.web import run_web_analysis
from modules.ad import run_ad_analysis
from modules.ai_engine import get_ai_analysis
from output.report import save_report

console = Console(legacy_windows=False)

BANNER = """
[bold green]
  ██████╗  ██████╗ ██████╗ ███████╗    ███████╗██╗   ██╗███████╗
 ██╔════╝ ██╔═══██╗██╔══██╗██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝
 ██║  ███╗██║   ██║██║  ██║███████╗    █████╗   ╚████╔╝ █████╗
 ██║   ██║██║   ██║██║  ██║╚════██╗    ██╔══╝    ╚██╔╝  ██╔══╝
 ╚██████╔╝╚██████╔╝██████╔╝███████║    ███████╗   ██║   ███████╗
  ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝    ╚══════╝   ╚═╝   ╚══════╝
[/bold green][dim]  GOD'S EYE v1.0.0 -- by alisalive[/dim]
[red]  For authorized security testing only[/red]
"""

SEVERITY_STYLE = {
    "critical": "bold red", "high": "red", "medium": "yellow",
    "low": "blue", "info": "dim",
}

STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",
]


def load_config(config_path: str = None) -> dict:
    """Load config from YAML file."""
    default_config = {
        "scan": {"timeout": 2.0, "max_parallel_ports": 50, "port_list": "common"},
        "ai": {"model": "claude-sonnet-4-6", "max_tokens": 2000, "enabled": True},
        "output": {"screenshots": True, "json": True, "html": True, "open_browser": False},
        "stealth": {"min_delay": 1.0, "max_delay": 3.0, "rotate_ua": True},
        "paths": {
            "gods_eye": r"C:\Users\User\Documents\GODs_EYE",
            "wordlists": "./config/wordlists",
            "reports": "./reports",
        },
    }
    candidates = [
        config_path,
        "config/config.yaml",
        os.path.join(os.path.dirname(__file__), "config", "config.yaml"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            try:
                import yaml
                with open(path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f) or {}
                # Deep merge
                for section, values in loaded.items():
                    if section in default_config and isinstance(values, dict):
                        default_config[section].update(values)
                    else:
                        default_config[section] = values
                break
            except ImportError:
                pass
            except Exception as e:
                console.print(f"[yellow]Config load warning: {e}[/yellow]")
    return default_config


def print_banner():
    console.print(BANNER)
    console.print(Rule(style="dim"))


def print_phase_header(phase: str, icon: str = "\u25c6"):
    console.print(f"\n[bold cyan]{icon} {phase.upper()}[/bold cyan]")
    console.print(Rule(style="cyan dim"))


def print_findings_table(state: EngagementState):
    if not state.findings:
        console.print("[dim]  No findings yet[/dim]")
        return
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold", padding=(0, 1))
    table.add_column("Sev", style="bold", width=8)
    table.add_column("Title", min_width=40)
    table.add_column("MITRE", style="dim", width=10)
    table.add_column("Phase", style="dim", width=8)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(state.findings, key=lambda x: sev_order.get(x.severity.value, 5)):
        style = SEVERITY_STYLE.get(f.severity.value, "")
        tactic = f.mitre_tactic[:8] + ".." if len(f.mitre_tactic) > 10 else f.mitre_tactic
        table.add_row(
            Text(f.severity.value.upper(), style=style),
            f.title[:60], tactic, f.phase,
        )
    console.print(table)


def print_summary_panel(state: EngagementState):
    counts = state.finding_counts()

    def bar(n, total, color):
        pct = int((n / max(total, 1)) * 20)
        return f"[{color}]{'#' * pct}{'.' * (20 - pct)}[/{color}] {n}"

    total = sum(counts.values())
    opsec_color = "green" if state.opsec_score >= 70 else "yellow" if state.opsec_score >= 40 else "red"
    content = (
        f"[bold]Target:[/bold]  {state.target}\n"
        f"[bold]Mode:[/bold]    {state.mode.value.upper()}\n"
        f"[bold]Duration:[/bold] {state.elapsed()}\n"
        f"[bold]OPSEC:[/bold]   [{opsec_color}]{state.opsec_score}/100[/{opsec_color}]\n\n"
        f"[bold red]CRITICAL[/bold red] {bar(counts.get('critical',0), total, 'red')}\n"
        f"[red]HIGH    [/red] {bar(counts.get('high',0), total, 'red')}\n"
        f"[yellow]MEDIUM  [/yellow] {bar(counts.get('medium',0), total, 'yellow')}\n"
        f"[blue]LOW     [/blue] {bar(counts.get('low',0), total, 'blue')}\n"
        f"[dim]INFO    [/dim] {bar(counts.get('info',0), total, 'white')}\n\n"
        f"[bold]Total:[/bold] {total} findings"
    )
    console.print(Panel(content, title="[bold]Engagement Summary[/bold]", border_style="cyan"))


async def stealth_delay(config: dict):
    """Apply random delay in stealth mode."""
    min_d = config.get("stealth", {}).get("min_delay", 1.0)
    max_d = config.get("stealth", {}).get("max_delay", 3.0)
    delay = random.uniform(min_d, max_d)
    await asyncio.sleep(delay)


async def run_engagement(
    target: str,
    mode: str,
    api_key: str = None,
    output_dir: str = "./reports",
    enable_ai: bool = False,
    stealth: bool = False,
    interactive: bool = False,
    enable_subdomains: bool = False,
    enable_screenshots: bool = False,
    config_path: str = None,
    no_report: bool = False,
    shodan_key: str = None,
    enable_dirbrute: bool = False,
    enable_pdf: bool = False,
    enable_real_ip: bool = False,
):
    print_banner()
    config = load_config(config_path)

    # Resolve output dir from config if not explicitly set
    if output_dir == "./reports":
        output_dir = config.get("paths", {}).get("reports", "./reports")

    gods_eye_path = config.get("paths", {}).get("gods_eye")

    state = EngagementState(
        target=target,
        mode=Mode(mode),
        scope=[target],
        opsec_score=100,
    )

    mode_color = "green" if mode == "pentest" else "red"
    console.print(Panel(
        f"[bold]Target:[/bold] [cyan]{target}[/cyan]\n"
        f"[bold]Mode:[/bold]   [{mode_color}]{mode.upper()}[/{mode_color}]\n"
        f"[bold]Stealth:[/bold] {'[green]ON[/green]' if stealth else '[dim]OFF[/dim]'}\n"
        f"[bold]Time:[/bold]   {time.strftime('%Y-%m-%d %H:%M:%S')}",
        title="[bold]Engagement Start[/bold]",
        border_style=mode_color,
    ))

    # ── Phase 0: Config loaded ────────────────────────────────────────────────
    console.print(f"  [green]✓[/green] Config loaded | GOD'S EYE: {gods_eye_path}")

    # ── Phase 1: Recon ────────────────────────────────────────────────────────
    print_phase_header("Phase 1 — Reconnaissance (GOD'S EYE)", "◆")
    if stealth:
        console.print("  [yellow]⚡ Stealth mode: slow scan, UA rotation, random delays[/yellow]")
    with console.status("[cyan]Running GOD'S EYE recon...[/cyan]", spinner="dots"):
        await run_recon(state, console, stealth=stealth, gods_eye_path=gods_eye_path)
    if stealth:
        await stealth_delay(config)

    open_port_count = len(state.recon_data.get("open_ports", {}))
    console.print(f"  [green]✓[/green] Recon complete: [bold]{open_port_count}[/bold] open ports found")

    if state.recon_data.get("open_ports"):
        t = Table(box=box.SIMPLE, padding=(0, 1), show_header=True, header_style="dim")
        t.add_column("Port", width=6)
        t.add_column("Service", width=14)
        t.add_column("Banner", min_width=30)
        for port, info in sorted(state.recon_data["open_ports"].items()):
            t.add_row(str(port), info["service"], (info.get("banner", "") or "—")[:50])
        console.print(t)

    # ── Phase 1b: Real IP discovery ───────────────────────────────────────────
    if enable_real_ip:
        print_phase_header("Phase 1b — Real IP Discovery", "◆")
        with console.status("[cyan]Discovering real IP behind CDN/WAF...[/cyan]", spinner="dots"):
            from modules.real_ip import run_real_ip_discovery
            real_ips = await run_real_ip_discovery(target, console)
        state.recon_data["real_ips"] = real_ips
        if real_ips:
            for entry in real_ips:
                console.print(
                    f"  [green]✓[/green] Potential real IP found: "
                    f"[bold cyan]{entry['ip']}[/bold cyan] "
                    f"(via [yellow]{entry['method']}[/yellow], "
                    f"[dim]{entry['confidence']} confidence[/dim])"
                )
        else:
            console.print("  [dim]→ No non-CDN IPs discovered[/dim]")
        if stealth:
            await stealth_delay(config)

    # ── Phase 1c: Shodan enrichment ───────────────────────────────────────────
    if shodan_key:
        with console.status("[cyan]Querying Shodan...[/cyan]", spinner="dots"):
            from modules.shodan_recon import run_shodan_recon
            await run_shodan_recon(state, shodan_key, console)

    if interactive:
        console.input("\n[dim]  Press Enter to continue to next phase...[/dim]")

    # ── Phase 2: Subdomain enum ───────────────────────────────────────────────
    if enable_subdomains:
        print_phase_header("Phase 2 — Subdomain Enumeration", "◆")
        with console.status("[cyan]Brute-forcing subdomains...[/cyan]", spinner="dots"):
            from modules.subdomain import run_subdomain_enum
            sub_data = await run_subdomain_enum(state, console)
        console.print(f"  [green]✓[/green] Subdomains: [bold]{len(sub_data.get('found', []))}[/bold] found")
        if stealth:
            await stealth_delay(config)

    # ── Phase 3: Web + WAF bypass ─────────────────────────────────────────────
    print_phase_header("Phase 3 — Web Analysis + WAF Bypass", "◆")
    with console.status("[cyan]Analyzing web services...[/cyan]", spinner="dots"):
        await run_web_analysis(state, console)
    web_count = len(state.web_data) if state.web_data else 0
    console.print(f"  [green]✓[/green] Web analysis: [bold]{web_count}[/bold] services analyzed")

    if state.web_data:
        from modules.waf_bypass import run_waf_bypass_analysis
        with console.status("[cyan]Generating WAF bypass payloads...[/cyan]", spinner="dots"):
            await run_waf_bypass_analysis(state, console)

    # JWT analysis integrated into web phase
    if state.web_data:
        with console.status("[cyan]Analyzing JWT tokens...[/cyan]", spinner="dots"):
            from modules.jwt_analyzer import run_jwt_analysis
            await run_jwt_analysis(state, console)

    if stealth:
        await stealth_delay(config)

    # ── Phase 2.5: Default Credentials ───────────────────────────────────────
    if state.recon_data.get("open_ports"):
        print_phase_header("Phase 2.5 — Default Credentials Check", "◆")
        with console.status("[cyan]Testing default credentials...[/cyan]", spinner="dots"):
            from modules.default_creds import run_default_creds_check
            creds_data = await run_default_creds_check(state, console)
        vuln_count = len(creds_data.get("vulnerable", []))
        if vuln_count:
            console.print(
                f"  [bold red]⚠ {vuln_count} service(s) with default credentials![/bold red]"
            )
        else:
            console.print("  [green]✓[/green] No default credentials found")
        if stealth:
            await stealth_delay(config)

    # ── Directory Brute-Force ─────────────────────────────────────────────────
    if enable_dirbrute:
        print_phase_header("Phase 3b — Directory Brute-Force", "◆")
        with console.status("[cyan]Brute-forcing directories...[/cyan]", spinner="dots"):
            from modules.dirbrute import run_dirbrute
            dirbrute_data = await run_dirbrute(state, console)
        dir_total = dirbrute_data.get("total", 0)
        console.print(f"  [green]✓[/green] Dirbrute: [bold]{dir_total}[/bold] interesting paths")
        if stealth:
            await stealth_delay(config)

    # ── Phase 4: AD analysis ──────────────────────────────────────────────────
    print_phase_header("Phase 4 — AD Analysis", "◆")
    with console.status("[cyan]Checking for Active Directory...[/cyan]", spinner="dots"):
        await run_ad_analysis(state, console)
    if state.ad_data.get("ad_detected"):
        plan = state.ad_data.get("attack_plan", [])
        console.print(f"  [bold red]⚡ AD DETECTED[/bold red] — [bold]{len(plan)}[/bold] attack vectors identified")
        for step in plan[:3]:
            console.print(f"    [dim]→[/dim] Step {step['step']}: {step['name']}")
    else:
        console.print("  [dim]→ No AD services detected[/dim]")

    # ── Phase 5: CVE correlation ──────────────────────────────────────────────
    print_phase_header("Phase 5 — CVE Correlation", "◆")
    with console.status("[cyan]Correlating CVEs...[/cyan]", spinner="dots"):
        from modules.cve import run_cve_correlation
        cve_data = await run_cve_correlation(state, console)
    cve_total = cve_data.get("total", 0)
    console.print(f"  [green]✓[/green] CVE correlation: [bold]{cve_total}[/bold] CVEs found")

    # ── Metasploit Bridge ─────────────────────────────────────────────────────
    from modules.msf_bridge import run_msf_bridge, print_msf_table
    run_msf_bridge(state, console)
    if state.findings:
        mapped = len([f for f in state.findings if getattr(f, "msf_module", "")])
        if mapped:
            console.print(f"  [cyan]MSF modules mapped:[/cyan] {mapped} finding(s)")
            print_msf_table(state, console)

    # ── Phase 6: Screenshots ──────────────────────────────────────────────────
    if enable_screenshots:
        print_phase_header("Phase 6 — Screenshots", "◆")
        screenshot_dir = os.path.join(output_dir, "screenshots")
        with console.status("[cyan]Taking screenshots...[/cyan]", spinner="dots"):
            from modules.screenshot import run_screenshots
            screenshots = await run_screenshots(state, console, output_dir=screenshot_dir)
        ss_count = sum(1 for s in screenshots.values() if not s.get("error"))
        console.print(f"  [green]✓[/green] Screenshots: [bold]{ss_count}[/bold] captured")

    # ── OPSEC score ───────────────────────────────────────────────────────────
    from modules.opsec import calculate_opsec_score
    opsec_score = calculate_opsec_score(
        state, stealth=stealth,
        ua_rotation=stealth,
        delays=stealth,
    )
    opsec_color = "green" if opsec_score >= 70 else "yellow" if opsec_score >= 40 else "red"
    console.print(f"\n  [bold]OPSEC Score:[/bold] [{opsec_color}]{opsec_score}/100[/{opsec_color}] "
                  f"({getattr(state, 'opsec_tracker_data', {}).get('rating', 'N/A')})")

    # ── Phase 7: AI analysis ──────────────────────────────────────────────────
    ai_result = {}
    if enable_ai:
        print_phase_header("Phase 7 — AI Analysis (Claude)", "◆")
        with console.status("[cyan]Claude is analyzing findings...[/cyan]", spinner="dots"):
            ai_result = await get_ai_analysis(state, api_key)
        if "error" not in ai_result:
            console.print(f"  [green]✓[/green] AI analysis complete ({ai_result.get('tokens_used', '?')} tokens)")
        else:
            console.print(f"  [yellow]⚠[/yellow] AI: {ai_result.get('error', 'failed')} — using fallback")
    else:
        console.print("\n  [dim]Phase 7 — AI Analysis skipped (use --ai to enable)[/dim]")

    # ── Summary ───────────────────────────────────────────────────────────────
    console.print()
    print_summary_panel(state)
    console.print("\n[bold]All Findings:[/bold]")
    print_findings_table(state)

    # ── Phase 8: Report ───────────────────────────────────────────────────────
    if not no_report:
        print_phase_header("Phase 8 — Report Generation", "◆")
        os.makedirs(output_dir, exist_ok=True)
        paths = save_report(state, ai_result if ai_result else None, output_dir)
        console.print(f"  [green]✓[/green] HTML report: [link={paths['html']}]{paths['html']}[/link]")
        console.print(f"  [green]✓[/green] JSON export: {paths['json']}")

        if enable_pdf:
            from output.pdf_export import export_pdf
            pdf_path = export_pdf(paths["html"], output_dir, target, console)
            if pdf_path:
                console.print(f"  [green]✓[/green] PDF export: {pdf_path}")
    else:
        paths = {}
        console.print("  [dim]Report skipped (--no-report)[/dim]")

    console.print()
    console.print(Rule(style="green"))
    counts = state.finding_counts()
    risk = "CRITICAL" if counts.get("critical", 0) > 0 else "HIGH" if counts.get("high", 0) > 2 else "MEDIUM"
    console.print(
        f"[bold green]Engagement complete.[/bold green] "
        f"Risk: [bold red]{risk}[/bold red] | "
        f"{sum(counts.values())} findings | "
        f"OPSEC: {state.opsec_score}/100"
    )
    console.print("[dim]For authorized security testing only.[/dim]")
    console.print()

    return state, paths


def main():
    parser = argparse.ArgumentParser(
        description="GOD'S EYE v1.0.0 — AI-powered penetration testing and red team automation\nFor authorized security testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target 10.0.0.1 --mode pentest
  python main.py --target 10.0.0.1 --mode pentest --ai --api-key sk-ant-...
  python main.py --target example.com --mode redteam --stealth --subdomains --screenshot
  python main.py --target 192.168.1.1 --mode pentest --ai --output ./reports
        """
    )
    parser.add_argument("--target", "-t", required=True, help="Target IP or hostname")
    parser.add_argument("--mode", "-m", choices=["pentest", "redteam"], default="pentest")
    parser.add_argument("--ai", action="store_true", help="Enable Claude AI analysis (requires --api-key or ANTHROPIC_API_KEY)")
    parser.add_argument("--api-key", "-k", help="Anthropic API key (or ANTHROPIC_API_KEY env var)")
    parser.add_argument("--output", "-o", default="./reports", help="Output directory")
    parser.add_argument("--output-dir", dest="output_dir", default=None, help="Output directory (alias)")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode (delays, UA rotation)")
    parser.add_argument("--interactive", action="store_true", help="Pause between phases")
    parser.add_argument("--subdomains", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("--screenshot", action="store_true", help="Enable screenshots (requires playwright)")
    parser.add_argument("--config", default=None, help="Config file path (YAML)")
    parser.add_argument("--no-report", action="store_true", help="Skip report generation")
    parser.add_argument("--shodan-key", default=None, help="Shodan API key for host enrichment")
    parser.add_argument("--dirbrute", action="store_true", help="Enable directory brute-force")
    parser.add_argument("--pdf", action="store_true", help="Export report as PDF")
    parser.add_argument("--real-ip", dest="real_ip", action="store_true",
                        help="Attempt to discover the real IP behind CDN/WAF")

    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    shodan_key = args.shodan_key or os.environ.get("SHODAN_API_KEY")
    output_dir = args.output_dir or args.output

    if args.ai and not api_key:
        parser.error(
            "--ai flag requires --api-key or the ANTHROPIC_API_KEY environment variable.\n"
            "  Set it with:  --api-key sk-ant-...\n"
            "  Or export:    set ANTHROPIC_API_KEY=sk-ant-..."
        )

    try:
        asyncio.run(run_engagement(
            target=args.target,
            mode=args.mode,
            api_key=api_key,
            output_dir=output_dir,
            enable_ai=args.ai,
            stealth=args.stealth,
            interactive=args.interactive,
            enable_subdomains=args.subdomains,
            enable_screenshots=args.screenshot,
            config_path=args.config,
            no_report=args.no_report,
            shodan_key=shodan_key,
            enable_dirbrute=args.dirbrute,
            enable_pdf=args.pdf,
            enable_real_ip=args.real_ip,
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
