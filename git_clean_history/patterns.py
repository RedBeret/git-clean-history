"""Secret detection patterns."""

import re

PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": r"AKIA[A-Z0-9]{16}",
        "severity": "high",
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
        "severity": "high",
        "requires_context": True,
    },
    {
        "name": "GitHub Token",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "severity": "high",
    },
    {
        "name": "GitHub Classic Token",
        "pattern": r"ghp_[A-Za-z0-9]{36}",
        "severity": "high",
    },
    {
        "name": "GitLab Token",
        "pattern": r"glpat-[A-Za-z0-9\-]{20,}",
        "severity": "high",
    },
    {
        "name": "Slack Bot Token",
        "pattern": r"xoxb-[0-9]{10,}-[A-Za-z0-9]{20,}",
        "severity": "high",
    },
    {
        "name": "Slack Webhook",
        "pattern": r"hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}",
        "severity": "high",
    },
    {
        "name": "Stripe Secret Key",
        "pattern": r"sk_live_[A-Za-z0-9]{24,}",
        "severity": "high",
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": r"pk_live_[A-Za-z0-9]{24,}",
        "severity": "medium",
    },
    {
        "name": "Google API Key",
        "pattern": r"AIza[A-Za-z0-9\-_]{35}",
        "severity": "high",
    },
    {
        "name": "Twilio API Key",
        "pattern": r"SK[a-f0-9]{32}",
        "severity": "high",
    },
    {
        "name": "SendGrid API Key",
        "pattern": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        "severity": "high",
    },
    {
        "name": "Mailgun API Key",
        "pattern": r"key-[A-Za-z0-9]{32}",
        "severity": "high",
    },
    {
        "name": "SSH Private Key",
        "pattern": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        "severity": "critical",
    },
    {
        "name": "Generic Secret",
        "pattern": r"(?:password|secret|token|api_key|apikey)\s*[:=]\s*['\"][A-Za-z0-9]{16,}['\"]",
        "severity": "medium",
    },
    {
        "name": "Private Key (generic)",
        "pattern": r"-----BEGIN PRIVATE KEY-----",
        "severity": "critical",
    },
]


def compile_patterns() -> list:
    """Compile regex patterns for faster matching."""
    compiled = []
    for p in PATTERNS:
        compiled.append({
            "name": p["name"],
            "regex": re.compile(p["pattern"]),
            "severity": p["severity"],
            "requires_context": p.get("requires_context", False),
        })
    return compiled


def scan_text(text: str, compiled_patterns=None) -> list:
    """Scan text for secrets. Returns list of matches."""
    if compiled_patterns is None:
        compiled_patterns = compile_patterns()

    matches = []
    for p in compiled_patterns:
        if p["requires_context"]:
            continue
        for match in p["regex"].finditer(text):
            matches.append({
                "pattern_name": p["name"],
                "severity": p["severity"],
                "match": match.group(),
                "start": match.start(),
                "end": match.end(),
            })
    return matches
