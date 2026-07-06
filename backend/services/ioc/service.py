"""
SOC AI Assistant — IOC Extraction Service

Regex-based extraction of Indicators of Compromise (IOCs) from arbitrary logs or text.
Guarantees extraction of IP addresses, domains, URLs, email addresses, file hashes, registry keys, and file paths.
"""

import re

# Regex patterns for IOC extraction
IP_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b'
URL_PATTERN = r'https?://(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,6}(?:/[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]*)?'
EMAIL_PATTERN = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
SHA1_PATTERN = r'\b[a-fA-F0-9]{40}\b'
SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'

# Windows & Linux file path patterns
FILE_PATH_PATTERN = r'\b(?:[a-zA-Z]:\\[\\\w\s._\-()]+|\/[\w._\-]+(?:\/[\w._\-]+)+)\b'

# Windows Registry patterns
REGISTRY_PATTERN = r'\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[\w\s._\-()\\]+\b'

# CVE patterns
CVE_PATTERN = r'\bCVE-\d{4}-\d{4,7}\b'


def extract_iocs(text: str) -> list[dict]:
    """
    Extracts all IOCs from the given text and returns a list of dictionaries with type and value.
    Filters out duplicates and overlaps (e.g. domains extracted from URLs, MD5s inside SHA256s).
    """
    iocs = []
    seen = set()

    if not text:
        return iocs

    # 1. Extract URLs
    urls = re.findall(URL_PATTERN, text)
    for url in urls:
        val = url.strip()
        if val not in seen:
            iocs.append({"type": "URL", "value": val})
            seen.add(val)

    # 2. Extract Emails
    emails = re.findall(EMAIL_PATTERN, text)
    for email in emails:
        val = email.strip()
        if val not in seen:
            iocs.append({"type": "Email", "value": val})
            seen.add(val)

    # 3. Extract IPs (IPv4)
    ips = re.findall(IP_PATTERN, text)
    for ip in ips:
        val = ip.strip()
        # Avoid simple localhost or broadcast ranges
        if val not in seen and val not in ("127.0.0.1", "0.0.0.0", "255.255.255.255"):
            iocs.append({"type": "IP", "value": val})
            seen.add(val)

    # 4. Extract Hashes (Order: SHA256, SHA1, MD5)
    sha256s = re.findall(SHA256_PATTERN, text)
    for hash_val in sha256s:
        val = hash_val.lower().strip()
        if val not in seen:
            iocs.append({"type": "Hash", "value": val})
            seen.add(val)

    sha1s = re.findall(SHA1_PATTERN, text)
    for hash_val in sha1s:
        val = hash_val.lower().strip()
        if val not in seen:
            iocs.append({"type": "Hash", "value": val})
            seen.add(val)

    md5s = re.findall(MD5_PATTERN, text)
    for hash_val in md5s:
        val = hash_val.lower().strip()
        # Make sure it wasn't extracted as part of a larger hash
        is_part = False
        for s in seen:
            if val in s:
                is_part = True
                break
        if val not in seen and not is_part:
            iocs.append({"type": "Hash", "value": val})
            seen.add(val)

    # 5. Extract Domains
    domains = re.findall(DOMAIN_PATTERN, text)
    for domain in domains:
        val = domain.strip().lower()
        # Avoid common file extensions or protocols appearing as domains
        if val.endswith(('.exe', '.dll', '.sys', '.sh', '.py', '.txt', '.log', '.json', '.xml', '.dat', '.tmp', '.iso', '.ps1')):
            continue
        # Avoid overlaps with already extracted URLs or IPs
        is_part = False
        for s in seen:
            if val in s:
                is_part = True
                break
        if val not in seen and not is_part:
            iocs.append({"type": "Domain", "value": val})
            seen.add(val)

    # 6. Extract Registry Keys
    registries = re.findall(REGISTRY_PATTERN, text)
    for reg in registries:
        val = reg.strip()
        if val not in seen:
            iocs.append({"type": "Registry", "value": val})
            seen.add(val)

    # 7. Extract File Paths
    paths = re.findall(FILE_PATH_PATTERN, text)
    for path in paths:
        val = path.strip()
        # Filter out common directories without specific filenames or too short paths
        if val in ('/etc', '/bin', '/usr', '/tmp', '/var', '/opt', 'C:\\Windows', 'C:\\Program Files'):
            continue
        # Check overlaps
        is_part = False
        for s in seen:
            if val in s:
                is_part = True
                break
        if val not in seen and not is_part:
            iocs.append({"type": "FilePath", "value": val})
            seen.add(val)

    # 8. Extract CVEs
    cves = re.findall(CVE_PATTERN, text)
    for cve in cves:
        val = cve.strip().upper()
        if val not in seen:
            iocs.append({"type": "CVE", "value": val})
            seen.add(val)

    return iocs
