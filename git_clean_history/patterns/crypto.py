"""Cryptographic key and certificate patterns."""

PATTERNS = [
    {
        "name": "RSA Private Key",
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "severity": "critical",
        "provider": "crypto",
    },
    {
        "name": "DSA Private Key",
        "pattern": r"-----BEGIN DSA PRIVATE KEY-----",
        "severity": "critical",
        "provider": "crypto",
    },
    {
        "name": "EC Private Key",
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "severity": "critical",
        "provider": "crypto",
    },
    {
        "name": "OpenSSH Private Key",
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": "critical",
        "provider": "crypto",
    },
    {
        "name": "PGP Private Key",
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "severity": "critical",
        "provider": "crypto",
    },
    {
        "name": "Generic Private Key",
        "pattern": r"-----BEGIN PRIVATE KEY-----",
        "severity": "critical",
        "provider": "crypto",
    },
    {
        "name": "PKCS8 Encrypted Private Key",
        "pattern": r"-----BEGIN ENCRYPTED PRIVATE KEY-----",
        "severity": "high",
        "provider": "crypto",
    },
]
