"""Stripe secret patterns."""

PATTERNS = [
    {
        "name": "Stripe Secret Key",
        "pattern": r"sk_live_[A-Za-z0-9]{24,}",
        "severity": "high",
        "provider": "stripe",
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": r"pk_live_[A-Za-z0-9]{24,}",
        "severity": "medium",
        "provider": "stripe",
    },
    {
        "name": "Stripe Restricted Key",
        "pattern": r"rk_live_[A-Za-z0-9]{24,}",
        "severity": "high",
        "provider": "stripe",
    },
    {
        "name": "Stripe Test Secret Key",
        "pattern": r"sk_test_[A-Za-z0-9]{24,}",
        "severity": "low",
        "provider": "stripe",
    },
]
