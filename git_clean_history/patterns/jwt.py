"""JWT and auth token patterns."""

PATTERNS = [
    {
        "name": "JSON Web Token",
        "pattern": r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        "severity": "medium",
        "provider": "jwt",
    },
]
