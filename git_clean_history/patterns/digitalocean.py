"""DigitalOcean secret patterns."""

PATTERNS = [
    {
        "name": "DigitalOcean Personal Access Token",
        "pattern": r"dop_v1_[a-f0-9]{64}",
        "severity": "high",
        "provider": "digitalocean",
    },
    {
        "name": "DigitalOcean OAuth Token",
        "pattern": r"doo_v1_[a-f0-9]{64}",
        "severity": "high",
        "provider": "digitalocean",
    },
    {
        "name": "DigitalOcean Refresh Token",
        "pattern": r"dor_v1_[a-f0-9]{64}",
        "severity": "high",
        "provider": "digitalocean",
    },
    {
        "name": "DigitalOcean Spaces Access Key",
        "pattern": r"DO[A-Z0-9]{18,}",
        "severity": "high",
        "provider": "digitalocean",
        "requires_context": True,
    },
]
