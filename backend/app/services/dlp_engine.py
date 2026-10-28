import uuid
import re
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from app.models import SecretFinding, SecurityEvent, Incident, IncidentEvidence, AuditLog

SECRET_PATTERNS = [
    {
        "type": "AWS Access Key ID",
        "regex": r"\b(AKIA[0-9A-Z]{16})\b",
        "severity": "Critical",
        "risk_score": 95,
        "recommendation": "Immediately invalidate the IAM access key in AWS IAM Console and audit AWS CloudTrail for unauthorized API calls."
    },
    {
        "type": "AWS Secret Access Key",
        "regex": r"(?i)aws_secret_access_key\s*=\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?",
        "severity": "Critical",
        "risk_score": 95,
        "recommendation": "Rotate associated AWS credentials immediately and rotate all attached programmatic policies."
    },
    {
        "type": "GitHub Personal Access Token",
        "regex": r"\b(ghp_[a-zA-Z0-9]{36})\b",
        "severity": "Critical",
        "risk_score": 90,
        "recommendation": "Revoke token on GitHub Security Settings and review git commit / repository access logs."
    },
    {
        "type": "Stripe Secret Key",
        "regex": r"\b(sk_(?:live|test)_[a-zA-Z0-9]{24,})\b",
        "severity": "Critical",
        "risk_score": 92,
        "recommendation": "Roll live Stripe API secret in dashboard and inspect webhook endpoints for unauthorized charge activities."
    },
    {
        "type": "RSA / OpenSSH Private Key",
        "regex": r"-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
        "severity": "Critical",
        "risk_score": 98,
        "recommendation": "Revoke private key from authorized_keys on all servers, regenerate 4096-bit keypair, and invalidate current SSH sessions."
    },
    {
        "type": "Database Connection URI with Password",
        "regex": r"\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[a-zA-Z0-9_.-]+:([^@\s]+)@[a-zA-Z0-9_.-]+:[0-9]+\/[a-zA-Z0-9_.-]+",
        "severity": "High",
        "risk_score": 88,
        "recommendation": "Rotate database user password, restrict database listener to internal VPC subnets only, and invalidate connection pool."
    },
    {
        "type": "Slack Webhook URL",
        "regex": r"https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+",
        "severity": "High",
        "risk_score": 75,
        "recommendation": "Revoke webhook in Slack App Management and recreate integration with restricted channel posting permissions."
    },
    {
        "type": "Generic Hardcoded High-Entropy Password / Bearer Token",
        "regex": r"(?i)(?:password|bearer|secret|api_key|token)\s*[:=]\s*['\"]([a-zA-Z0-9!@#$%^&*()_+=-]{12,})['\"]",
        "severity": "Medium",
        "risk_score": 70,
        "recommendation": "Extract credentials into enterprise secret vault (e.g., HashiCorp Vault / AWS Secrets Manager) and invalidate exposed secret."
    }
]

def mask_secret(value: str) -> str:
    """
    Safely masks sensitive secret strings while preserving prefix and suffix for analyst identification.
    Never exposes complete secret.
    """
    if len(value) <= 8:
        return "********"
    if value.startswith("-----BEGIN"):
        return "-----BEGIN PRIVATE KEY [REDACTED BY DLP ENGINE]-----"
    prefix_len = min(4, len(value) // 4)
    suffix_len = min(4, len(value) // 4)
    masked_len = len(value) - prefix_len - suffix_len
    return f"{value[:prefix_len]}{'*' * min(masked_len, 24)}{value[-suffix_len:]}"

def hash_secret(value: str) -> str:
    """Produces SHA-256 hash of raw secret for safe duplicate detection without storing plaintext."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

class DLPEngine:
    def scan_content(
        self,
        text: str,
        source_location: str = "Unknown Stream",
        employee_id: str = None,
        employee_email: str = None
    ) -> List[Dict[str, Any]]:
        findings = []
        if not text:
            return findings

        now = datetime.now(timezone.utc)
        now_ts = int(now.timestamp())

        for p in SECRET_PATTERNS:
            matches = re.finditer(p["regex"], text)
            for m in matches:
                raw_secret = m.group(1) if m.groups() else m.group(0)
                sec_hash = hash_secret(raw_secret)
                masked = mask_secret(raw_secret)
                
                finding_id = f"DLP-{sec_hash[:8].upper()}-{uuid.uuid4().hex[:6].upper()}"
                findings.append({
                    "finding_id": finding_id,
                    "secret_type": p["type"],
                    "masked_value": masked,
                    "secret_hash": sec_hash,
                    "source_location": source_location,
                    "severity": p["severity"],
                    "risk_score": p["risk_score"],
                    "recommendations": p["recommendation"],
                    "employee_id": employee_id,
                    "employee_email": employee_email,
                    "detected_at": now.isoformat()
                })

        return findings

dlp_engine = DLPEngine()
