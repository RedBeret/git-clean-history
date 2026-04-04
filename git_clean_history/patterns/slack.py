"""Slack secret patterns."""

PATTERNS = [
    {
        "name": "Slack Bot Token",
        "pattern": r"xoxb-[0-9]{10,}-[A-Za-z0-9]{20,}",
        "severity": "high",
        "provider": "slack",
    },
    {
        "name": "Slack User Token",
        "pattern": r"xoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}",
        "severity": "high",
        "provider": "slack",
    },
    {
        "name": "Slack Webhook URL",
        "pattern": r"hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}",
        "severity": "high",
        "provider": "slack",
    },
    {
        "name": "Slack App Token",
        "pattern": r"xapp-[0-9]-[A-Za-z0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{60,}",
        "severity": "high",
        "provider": "slack",
    },
]
