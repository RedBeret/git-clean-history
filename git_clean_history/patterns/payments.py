"""Payment and fintech secret patterns beyond Stripe."""

PATTERNS = [
    {
        "name": "Square Access Token",
        "pattern": r"sq0atp-[A-Za-z0-9_\-]{22}",
        "severity": "high",
        "provider": "square",
    },
    {
        "name": "Square OAuth Secret",
        "pattern": r"sq0csp-[A-Za-z0-9_\-]{43}",
        "severity": "high",
        "provider": "square",
    },
    {
        "name": "PayPal Braintree Access Token",
        "pattern": r"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}",
        "severity": "high",
        "provider": "paypal",
    },
    {
        "name": "Plaid Client ID",
        "pattern": r"client_id.*[a-f0-9]{24}",
        "severity": "medium",
        "provider": "plaid",
        "requires_context": True,
    },
]
