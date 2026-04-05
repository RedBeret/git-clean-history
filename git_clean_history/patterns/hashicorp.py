"""HashiCorp secret patterns."""

PATTERNS = [
    {
        "name": "HashiCorp Vault Token",
        "pattern": r"hvs\.[A-Za-z0-9_\-]{24,}",
        "severity": "critical",
        "provider": "hashicorp",
    },
    {
        "name": "HashiCorp Vault Batch Token",
        "pattern": r"hvb\.[A-Za-z0-9_\-]{24,}",
        "severity": "critical",
        "provider": "hashicorp",
    },
    {
        "name": "HashiCorp Terraform Token",
        "pattern": r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_\-]{60,}",
        "severity": "high",
        "provider": "hashicorp",
    },
]
