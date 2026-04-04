"""GitHub secret patterns."""

PATTERNS = [
    {
        "name": "GitHub Personal Access Token",
        "pattern": r"ghp_[A-Za-z0-9]{36}",
        "severity": "high",
        "provider": "github",
    },
    {
        "name": "GitHub OAuth Token",
        "pattern": r"gho_[A-Za-z0-9]{36,}",
        "severity": "high",
        "provider": "github",
    },
    {
        "name": "GitHub User-to-Server Token",
        "pattern": r"ghu_[A-Za-z0-9]{36,}",
        "severity": "high",
        "provider": "github",
    },
    {
        "name": "GitHub Server-to-Server Token",
        "pattern": r"ghs_[A-Za-z0-9]{36,}",
        "severity": "high",
        "provider": "github",
    },
    {
        "name": "GitHub Refresh Token",
        "pattern": r"ghr_[A-Za-z0-9]{36,}",
        "severity": "high",
        "provider": "github",
    },
    {
        "name": "GitHub Fine-Grained Token",
        "pattern": r"github_pat_[A-Za-z0-9_]{22,}",
        "severity": "high",
        "provider": "github",
    },
]
