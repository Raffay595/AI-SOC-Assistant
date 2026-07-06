"""
SOC AI Assistant — MITRE ATT&CK Service

Loads a high-fidelity lookup mapping for top enterprise MITRE ATT&CK tactics, techniques,
and sub-techniques. Allows searching, listing, and mapping alerts to techniques.
"""

from backend.schemas import MITRETechnique, MITRETactic
import json
import os

# We will bundle a high-fidelity representation of the most common enterprise MITRE ATT&CK tactics and techniques.
# This ensures it runs completely offline without downloading massive STIX bundles, but provides full details, descriptions,
# and detection recommendations.
MITRE_DATA = {
    "tactics": [
        {
            "tactic_id": "TA0001",
            "name": "Initial Access",
            "description": "The adversary is trying to get into your network.",
            "techniques": [
                {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program to gain access.", "detection": "Monitor application logs for unexpected behavior, crashes, or commands. Audit web server logs for exploitation attempts.", "url": "https://attack.mitre.org/techniques/T1190"},
                {"technique_id": "T1566", "name": "Phishing", "tactic": "Initial Access", "description": "Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are targeted at individuals.", "detection": "Analyze incoming email logs, attachment extensions, and links. Monitor endpoint execution of attachments.", "url": "https://attack.mitre.org/techniques/T1566"},
                {"technique_id": "T1566.001", "name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "description": "Adversaries may send spearphishing emails with malicious attachments to gain entry.", "detection": "Monitor email gateway attachments. Check for spawning of shells (cmd.exe, powershell.exe) by Office documents.", "url": "https://attack.mitre.org/techniques/T1566/001"},
                {"technique_id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access", "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.", "detection": "Monitor logon logs (Event ID 4624/4625). Analyze source IP and unusual geolocations or logon times.", "url": "https://attack.mitre.org/techniques/T1078"}
            ]
        },
        {
            "tactic_id": "TA0002",
            "name": "Execution",
            "description": "The adversary is trying to run malicious code.",
            "techniques": [
                {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.", "detection": "Monitor shell command executions, commands referencing scripts, and arguments. Audit process creations.", "url": "https://attack.mitre.org/techniques/T1059"},
                {"technique_id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution", "description": "Adversaries may use PowerShell commands to perform execution and script automation.", "detection": "Enable PowerShell script block logging (Event ID 4104). Check for '-EncodedCommand' or '-ep bypass' flags.", "url": "https://attack.mitre.org/techniques/T1059/001"},
                {"technique_id": "T1204.002", "name": "User Execution: Malicious File", "tactic": "Execution", "description": "An adversary may rely on a user opening a malicious file (e.g. email attachment, link) to execute code.", "detection": "Monitor process creation events for browser or email client spawning script execution files.", "url": "https://attack.mitre.org/techniques/T1204/002"}
            ]
        },
        {
            "tactic_id": "TA0003",
            "name": "Persistence",
            "description": "The adversary is trying to maintain their foothold.",
            "techniques": [
                {"technique_id": "T1098", "name": "Account Manipulation", "tactic": "Persistence", "description": "Adversaries may manipulate accounts to maintain access to victim systems (e.g. modifying permissions or details).", "detection": "Monitor account modification events (Event ID 4738, 4724). Check for modifications to critical files like /etc/passwd.", "url": "https://attack.mitre.org/techniques/T1098"},
                {"technique_id": "T1136.001", "name": "Create Account: Local Account", "tactic": "Persistence", "description": "Adversaries may create local accounts to maintain persistence on compromised endpoints.", "detection": "Monitor local user creation events (Event ID 4720). Alert on unexpected account creations.", "url": "https://attack.mitre.org/techniques/T1136/001"},
                {"technique_id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task", "tactic": "Persistence", "description": "Adversaries may abuse task scheduling utilities (like schtasks or Task Scheduler) to execute code.", "detection": "Monitor Event ID 4698 (Scheduled task created) and schtasks.exe command line execution.", "url": "https://attack.mitre.org/techniques/T1053/005"},
                {"technique_id": "T1053.003", "name": "Scheduled Task/Job: Cron", "tactic": "Persistence", "description": "Adversaries may use cron jobs to automate execution of malicious code for persistence.", "detection": "Monitor modifications to /etc/cron* files and /var/spool/cron/crontabs/* directory.", "url": "https://attack.mitre.org/techniques/T1053/003"},
                {"technique_id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys", "tactic": "Persistence", "description": "Adversaries may modify startup registry keys (e.g. Run or RunOnce) to achieve persistent execution on logon.", "detection": "Monitor registry modifications to Run keys (Sysmon Event ID 13). Audit autorun programs.", "url": "https://attack.mitre.org/techniques/T1547/001"},
                {"technique_id": "T1543.003", "name": "Create or Modify System Process: Windows Service", "tactic": "Persistence", "description": "Adversaries may create or modify Windows services to execute malicious commands or payloads.", "detection": "Monitor Event ID 7045 (New service installed) and HKLM\\SYSTEM\\CurrentControlSet\\Services modifications.", "url": "https://attack.mitre.org/techniques/T1543/003"},
                {"technique_id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence", "description": "Adversaries may install web shells to maintain persistent web server access and execute code.", "detection": "Monitor web server directory file integrity (FIM alerts). Check for unusual file uploads with scripting extensions (.php, .jsp).", "url": "https://attack.mitre.org/techniques/T1505/003"}
            ]
        },
        {
            "tactic_id": "TA0004",
            "name": "Privilege Escalation",
            "description": "The adversary is trying to gain higher-level permissions.",
            "techniques": [
                {"technique_id": "T1078.002", "name": "Valid Accounts: Domain Accounts", "tactic": "Privilege Escalation", "description": "Adversaries may abuse domain credentials to elevate permissions or log into critical systems.", "detection": "Audit Domain Controller authentication logs. Alert on unusual permission assignments.", "url": "https://attack.mitre.org/techniques/T1078/002"},
                {"technique_id": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "tactic": "Privilege Escalation", "description": "Adversaries may exploit sudo permissions or configuration flaws to elevate privilege to root on Unix/Linux systems.", "detection": "Monitor sudo command execution logs. Alert on user not in sudoers attempts.", "url": "https://attack.mitre.org/techniques/T1548/003"}
            ]
        },
        {
            "tactic_id": "TA0005",
            "name": "Defense Evasion",
            "description": "The adversary is trying to avoid detection.",
            "techniques": [
                {"technique_id": "T1014", "name": "Rootkit", "tactic": "Defense Evasion", "description": "Adversaries may use rootkits to hide processes, files, or network connections from system tools.", "detection": "Use host-based rootkit checkers (Rootcheck). Monitor differences between API-level and kernel-level listings.", "url": "https://attack.mitre.org/techniques/T1014"},
                {"technique_id": "T1070.001", "name": "Indicator Removal: Clear Windows Event Logs", "tactic": "Defense Evasion", "description": "Adversaries may clear event logs to remove evidence of their activities.", "detection": "Monitor Event ID 1102 (Security event log cleared) or command line calls targeting log deletion (wevtutil.exe).", "url": "https://attack.mitre.org/techniques/T1070/001"},
                {"technique_id": "T1055.003", "name": "Process Injection: Thread Execution Hijacking", "tactic": "Defense Evasion", "description": "Adversaries may inject code into target processes by hijacking thread execution to evade monitoring.", "detection": "Monitor CreateRemoteThread Sysmon Event ID 8 calls targeting sensitive system binaries (svchost.exe, lsass.exe).", "url": "https://attack.mitre.org/techniques/T1055/003"},
                {"technique_id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion", "description": "Adversaries may modify or disable security tools (like Windows Defender, firewalls, or EDR agents).", "detection": "Monitor logs indicating service status changes for security programs. Audit defender disable commands.", "url": "https://attack.mitre.org/techniques/T1562/001"}
            ]
        },
        {
            "tactic_id": "TA0006",
            "name": "Credential Access",
            "description": "The adversary is trying to steal passwords and hashes.",
            "techniques": [
                {"technique_id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access", "description": "Adversaries may guess passwords to gain access to valid accounts.", "detection": "Alert on multiple failed logon events (Event ID 4625) from the same source IP in a short period.", "url": "https://attack.mitre.org/techniques/T1110/001"},
                {"technique_id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access", "description": "Adversaries may dump memory from the LSASS process to extract plaintext passwords or NTLM hashes.", "detection": "Monitor process access targeting lsass.exe (Sysmon Event ID 10) with access masks like 0x1010 or 0x1F0FFF.", "url": "https://attack.mitre.org/techniques/T1003/001"},
                {"technique_id": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting", "tactic": "Credential Access", "description": "Adversaries may abuse Kerberos service tickets to perform offline password cracking.", "detection": "Monitor ticket request Event ID 4769 with encryption type RC4 (0x17) and service accounts.", "url": "https://attack.mitre.org/techniques/T1558/003"}
            ]
        },
        {
            "tactic_id": "TA0007",
            "name": "Discovery",
            "description": "The adversary is trying to figure out your environment.",
            "techniques": [
                {"technique_id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "description": "Adversaries may attempt to list port/service mappings on target hosts to identify vulnerable points.", "detection": "Monitor firewall or IDS logs indicating multiple outbound connection attempts to distinct ports/IPs.", "url": "https://attack.mitre.org/techniques/T1046"}
            ]
        },
        {
            "tactic_id": "TA0008",
            "name": "Lateral Movement",
            "description": "The adversary is trying to move through your environment.",
            "techniques": [
                {"technique_id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement", "description": "Adversaries may transfer files from one local system to another to facilitate execution.", "detection": "Monitor Sysmon Event ID 11 (File create) involving remote file paths or administrative shares.", "url": "https://attack.mitre.org/techniques/T1570"},
                {"technique_id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement", "description": "Adversaries may utilize SMB and admin shares (like C$ or ADMIN$) to move laterally.", "detection": "Monitor Event ID 5140 (network share access). Check for administrative logins over SMB.", "url": "https://attack.mitre.org/techniques/T1021/002"}
            ]
        },
        {
            "tactic_id": "TA0011",
            "name": "Command and Control",
            "description": "The adversary is trying to communicate with compromised systems to control them.",
            "techniques": [
                {"technique_id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "description": "Adversaries may communicate with C2 servers using standard web protocols (HTTP/HTTPS) to blend in.", "detection": "Analyze outbound traffic logs for unusual domains, beacons, or HTTP user-agents. Monitor external IP reputation.", "url": "https://attack.mitre.org/techniques/T1071/001"},
                {"technique_id": "T1568.002", "name": "Dynamic Resolution: Domain Generation Algorithms", "tactic": "Command and Control", "description": "Adversaries may use DGAs to dynamically resolve domain names for command and control channels.", "detection": "Monitor DNS logs (Sysmon Event ID 22) for high frequency of NXDOMAIN responses or random-looking query strings.", "url": "https://attack.mitre.org/techniques/T1568/002"}
            ]
        },
        {
            "tactic_id": "TA0010",
            "name": "Exfiltration",
            "description": "The adversary is trying to steal data.",
            "techniques": [
                {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "description": "Adversaries may exfiltrate data back to command and control servers.", "detection": "Monitor traffic volume on established sockets. Alert on unusual outbound bandwidth spikes from endpoints.", "url": "https://attack.mitre.org/techniques/T1041"}
            ]
        },
        {
            "tactic_id": "TA0040",
            "name": "Impact",
            "description": "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
            "techniques": [
                {"technique_id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Adversaries may encrypt data on victim systems to interrupt availability (ransomware).", "detection": "Audit file monitoring logs for rapid, high-volume file modification and renaming events. Look for ransomware note creations.", "url": "https://attack.mitre.org/techniques/T1486"},
                {"technique_id": "T1496", "name": "Resource Hijacking", "tactic": "Impact", "description": "Adversaries may leverage compromised system resources for mining cryptocurrency or hosting unauthorized software.", "detection": "Monitor CPU/GPU usage indicators. Analyze process listing for mining programs (e.g. xmrig) and outbound pool connections.", "url": "https://attack.mitre.org/techniques/T1496"}
            ]
        }
    ]
}


def get_all_tactics() -> list[MITRETactic]:
    """Get all tactics and nested techniques."""
    tactics = []
    for t in MITRE_DATA["tactics"]:
        techniques = [MITRETechnique(**tech) for tech in t["techniques"]]
        tactics.append(MITRETactic(
            tactic_id=t["tactic_id"],
            name=t["name"],
            description=t["description"],
            techniques=techniques
        ))
    return tactics


def get_all_techniques() -> list[MITRETechnique]:
    """Flat list of all techniques."""
    techs = []
    for t in MITRE_DATA["tactics"]:
        for tech in t["techniques"]:
            techs.append(MITRETechnique(**tech))
    return techs


def get_technique_by_id(technique_id: str) -> MITRETechnique | None:
    """Lookup a technique details by technique ID (e.g. T1059.001)."""
    for t in MITRE_DATA["tactics"]:
        for tech in t["techniques"]:
            if tech["technique_id"] == technique_id:
                return MITRETechnique(**tech)
            # Allow matching parent if searching subclass
            if "." in technique_id and tech["technique_id"] == technique_id.split(".")[0]:
                # Fallback to parent details if exact subtechnique details are not present
                return MITRETechnique(
                    technique_id=technique_id,
                    name=f"{tech['name']} (Subtechnique)",
                    tactic=tech["tactic"],
                    description=tech["description"],
                    detection=tech["detection"],
                    url=tech["url"]
                )
    return None
