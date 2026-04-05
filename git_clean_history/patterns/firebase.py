"""Firebase and Google Cloud secret patterns."""

PATTERNS = [
    {
        "name": "Firebase Cloud Messaging Key",
        "pattern": r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",
        "severity": "high",
        "provider": "firebase",
    },
    {
        "name": "Firebase Database URL",
        "pattern": r"https://[a-z0-9\-]+\.firebaseio\.com",
        "severity": "medium",
        "provider": "firebase",
    },
]
