"""Azure and Microsoft secret patterns."""

PATTERNS = [
    {
        "name": "Azure Storage Account Key",
        "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
        "severity": "critical",
        "provider": "azure",
    },
    {
        "name": "Azure AD Client Secret",
        "pattern": r"[a-zA-Z0-9~_.\-]{3}8Q~[a-zA-Z0-9~_.\-]{34}",
        "severity": "high",
        "provider": "azure",
    },
    {
        "name": "Azure SAS Token",
        "pattern": r"sv=\d{4}-\d{2}-\d{2}&s[a-z]=.*&sig=[A-Za-z0-9%+/=]+",
        "severity": "high",
        "provider": "azure",
    },
    {
        "name": "Azure DevOps PAT",
        "pattern": r"[a-z2-7]{52}",
        "severity": "high",
        "provider": "azure",
        "requires_context": True,
    },
    {
        "name": "Microsoft Teams Webhook",
        "pattern": r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9\-]+",
        "severity": "high",
        "provider": "azure",
    },
]
