"""Deterministic, redaction-first checks for configuration secret exposure."""

from __future__ import annotations

import hashlib
import re
from typing import Any


RULES = (
    ("AWS_SECRET_KEY", "CRITICAL", re.compile(r"(?i)\baws_secret_access_key\s*[:=]\s*([^\s#]+)")),
    ("PRIVATE_KEY", "CRITICAL", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("PASSWORD_ASSIGNMENT", "HIGH", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*([^\s#]+)")),
    ("TOKEN_ASSIGNMENT", "HIGH", re.compile(r"(?i)\b(?:api[_-]?token|access[_-]?token|auth[_-]?token)\s*[:=]\s*([^\s#]+)")),
)

PLACEHOLDERS = {"", "changeme", "example", "placeholder", "redacted", "${secret}", "<secret>"}
SEVERITY_ORDER = {"NONE": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _validate(payload: Any) -> list[dict[str, str]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("files"), list):
        raise ValueError("input must contain a files list")
    files = payload["files"]
    if not files:
        raise ValueError("files list cannot be empty")
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not isinstance(item.get("content"), str):
            raise ValueError("each file requires string path and content fields")
        if not item["path"].strip():
            raise ValueError("file path cannot be empty")
    return files


def _fingerprint(path: str, line_number: int, rule: str) -> str:
    return hashlib.sha256(f"{path}:{line_number}:{rule}".encode()).hexdigest()[:12]


def _is_placeholder(match: re.Match[str]) -> bool:
    if match.lastindex is None:
        return False
    value = match.group(match.lastindex).strip().strip('"\'').lower()
    return value in PLACEHOLDERS or value.startswith("${") or value.startswith("{{")


def audit_bundle(payload: Any) -> dict[str, Any]:
    """Return findings without returning or logging the matched secret value."""
    files = _validate(payload)
    findings: list[dict[str, Any]] = []

    for item in files:
        for line_number, line in enumerate(item["content"].splitlines(), start=1):
            for rule, severity, pattern in RULES:
                match = pattern.search(line)
                if match is None or _is_placeholder(match):
                    continue
                findings.append({
                    "id": _fingerprint(item["path"], line_number, rule),
                    "path": item["path"],
                    "line": line_number,
                    "rule": rule,
                    "severity": severity,
                    "evidence": "[REDACTED]",
                    "remediation": "Revoke or rotate the credential, remove it from history, and reference a managed secret store.",
                })

    highest = max((f["severity"] for f in findings), key=SEVERITY_ORDER.get, default="NONE")
    decision = "BLOCK" if highest in {"HIGH", "CRITICAL"} else "PASS"
    return {
        "decision": decision,
        "highest_severity": highest,
        "files_scanned": len(files),
        "finding_count": len(findings),
        "findings": findings,
        "raw_secret_values_returned": False,
        "mutation_performed": False,
        "human_approval_required_for_remediation": True,
    }

