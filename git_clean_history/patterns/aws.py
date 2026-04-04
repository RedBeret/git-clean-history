"""AWS secret patterns."""

PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": r"AKIA[A-Z0-9]{16}",
        "severity": "high",
        "provider": "aws",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
        "severity": "high",
        "provider": "aws",
        "requires_context": True,
    },
    {
        "name": "AWS MWS Auth Token",
        "pattern": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "severity": "high",
        "provider": "aws",
    },
]
