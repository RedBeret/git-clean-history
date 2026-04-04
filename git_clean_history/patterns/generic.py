"""Generic secret patterns that catch common password/key assignments."""

PATTERNS = [
    {
        "name": "Generic Secret Assignment",
        "pattern": r"(?:password|secret|token|api_key|apikey|api[-_]?secret)\s*[:=]\s*['\"][A-Za-z0-9]{16,}['\"]",
        "severity": "medium",
        "provider": "generic",
    },
    {
        "name": "Connection String with Password",
        "pattern": r"(?:mysql|postgres|mongodb|redis)://[^:]+:[^@]+@",
        "severity": "high",
        "provider": "generic",
    },
    {
        "name": "Bearer Token in Code",
        "pattern": r"['\"]Bearer\s+[A-Za-z0-9\-._~+/]+=*['\"]",
        "severity": "medium",
        "provider": "generic",
    },
    {
        "name": "Basic Auth Header",
        "pattern": r"['\"]Basic\s+[A-Za-z0-9+/]+=*['\"]",
        "severity": "medium",
        "provider": "generic",
    },
]
