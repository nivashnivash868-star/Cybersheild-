import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple

BLOCKED_DOMAINS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal",
    "169.254.169.254", "instance-data", "kubernetes.default.svc"
}

ALLOWED_SCHEMES = {"http", "https"}

def is_ip_private_or_restricted(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_multicast or
            ip.is_reserved or
            ip.is_unspecified
        )
    except ValueError:
        return False

def validate_url_safe_for_inspection(url: str) -> Tuple[bool, str]:
    """
    Validates URL to protect against SSRF and malicious protocol schemes.
    Does NOT initiate outbound socket connections to private endpoints.
    """
    if not url or not isinstance(url, str):
        return False, "Empty or invalid URL supplied."
        
    url_cleaned = url.strip()
    if not (url_cleaned.startswith("http://") or url_cleaned.startswith("https://")):
        url_cleaned = "http://" + url_cleaned

    try:
        parsed = urlparse(url_cleaned)
    except Exception as e:
        return False, f"URL parse failure: {str(e)}"

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"Prohibited URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted for safety."

    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL: missing valid hostname or domain."

    hostname_lower = hostname.lower()

    # Block localhost/internal names
    if hostname_lower in BLOCKED_DOMAINS:
        return False, f"Prohibited target hostname '{hostname_lower}' (loopback/internal service protection)."

    for suffix in [".localhost", ".local", ".internal", ".lan", ".test", ".corp"]:
        if hostname_lower.endswith(suffix):
            return False, f"Prohibited domain ending with '{suffix}' (internal LAN/test domain)."

    # Direct IP checks
    if is_ip_private_or_restricted(hostname_lower):
        return False, f"Prohibited private, loopback, or cloud-metadata IP address: {hostname_lower}"

    # Try resolving hostname to verify it does not resolve to private IP address
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for entry in addr_info:
            resolved_ip = entry[4][0]
            if is_ip_private_or_restricted(resolved_ip):
                return False, f"Hostname '{hostname}' resolves to private/restricted IP ({resolved_ip}). Analysis restricted for SOC safety."
    except socket.gaierror:
        # Unresolvable domains can still be analyzed heuristically, which is expected for fresh phishing domains!
        pass
    except Exception:
        pass

    return True, "URL is safe for static/heuristic inspection."
