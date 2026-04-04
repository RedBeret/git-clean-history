"""Google/GCP secret patterns."""

PATTERNS = [
    {
        "name": "Google API Key",
        "pattern": r"AIza[A-Za-z0-9\-_]{35}",
        "severity": "high",
        "provider": "google",
    },
    {
        "name": "Google OAuth Client ID",
        "pattern": r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com",
        "severity": "medium",
        "provider": "google",
    },
    {
        "name": "GCP Service Account Key",
        "pattern": r'"type":\s*"service_account"',
        "severity": "critical",
        "provider": "google",
    },
]
