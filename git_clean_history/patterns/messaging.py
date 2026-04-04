"""Messaging and communication service patterns."""

PATTERNS = [
    {
        "name": "Twilio API Key",
        "pattern": r"SK[a-f0-9]{32}",
        "severity": "high",
        "provider": "twilio",
    },
    {
        "name": "SendGrid API Key",
        "pattern": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        "severity": "high",
        "provider": "sendgrid",
    },
    {
        "name": "Mailgun API Key",
        "pattern": r"key-[A-Za-z0-9]{32}",
        "severity": "high",
        "provider": "mailgun",
    },
    {
        "name": "Telegram Bot Token",
        "pattern": r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",
        "severity": "high",
        "provider": "telegram",
    },
    {
        "name": "Discord Bot Token",
        "pattern": r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}",
        "severity": "high",
        "provider": "discord",
    },
]
