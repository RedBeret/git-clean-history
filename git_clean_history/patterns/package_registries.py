"""Package registry and container secret patterns."""

PATTERNS = [
    {
        "name": "npm Access Token",
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "severity": "high",
        "provider": "npm",
    },
    {
        "name": "npm Legacy Token",
        "pattern": r"//registry\.npmjs\.org/:_authToken=[A-Za-z0-9\-]{36}",
        "severity": "high",
        "provider": "npm",
    },
    {
        "name": "PyPI API Token",
        "pattern": r"pypi-[A-Za-z0-9_\-]{100,}",
        "severity": "high",
        "provider": "pypi",
    },
    {
        "name": "Docker Hub Access Token",
        "pattern": r"dckr_pat_[A-Za-z0-9_\-]{20,}",
        "severity": "high",
        "provider": "docker",
    },
    {
        "name": "NuGet API Key",
        "pattern": r"oy2[A-Za-z0-9]{43}",
        "severity": "high",
        "provider": "nuget",
    },
    {
        "name": "RubyGems API Key",
        "pattern": r"rubygems_[a-f0-9]{48}",
        "severity": "high",
        "provider": "rubygems",
    },
]
