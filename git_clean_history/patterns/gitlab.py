"""GitLab secret patterns."""

PATTERNS = [
    {
        "name": "GitLab Personal Access Token",
        "pattern": r"glpat-[A-Za-z0-9\-]{20,}",
        "severity": "high",
        "provider": "gitlab",
    },
    {
        "name": "GitLab Pipeline Token",
        "pattern": r"glptt-[A-Za-z0-9\-]{20,}",
        "severity": "high",
        "provider": "gitlab",
    },
    {
        "name": "GitLab Runner Token",
        "pattern": r"glrt-[A-Za-z0-9\-]{20,}",
        "severity": "high",
        "provider": "gitlab",
    },
]
