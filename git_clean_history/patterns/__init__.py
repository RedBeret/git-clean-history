"""Pattern library for secret detection.

Each file in this directory defines patterns for a specific provider or category.
Patterns are loaded automatically at import time.
"""

import importlib
import pkgutil
import re
from pathlib import Path


def _load_all_patterns() -> list:
    """Load patterns from all modules in this package."""
    all_patterns = []
    package_dir = Path(__file__).parent

    for finder, name, ispkg in pkgutil.iter_modules([str(package_dir)]):
        if name.startswith("_"):
            continue
        module = importlib.import_module(f".{name}", package=__package__)
        if hasattr(module, "PATTERNS"):
            all_patterns.extend(module.PATTERNS)

    return all_patterns


def compile_patterns(patterns=None) -> list:
    """Compile regex patterns for faster matching."""
    if patterns is None:
        patterns = _load_all_patterns()

    compiled = []
    for p in patterns:
        compiled.append({
            "name": p["name"],
            "regex": re.compile(p["pattern"]),
            "severity": p["severity"],
            "provider": p.get("provider", "generic"),
            "requires_context": p.get("requires_context", False),
        })
    return compiled


def scan_text(text: str, compiled_patterns=None) -> list:
    """Scan text for secrets. Returns list of matches."""
    if compiled_patterns is None:
        compiled_patterns = compile_patterns()

    matches = []
    for p in compiled_patterns:
        if p["requires_context"]:
            continue
        for match in p["regex"].finditer(text):
            matches.append({
                "pattern_name": p["name"],
                "severity": p["severity"],
                "provider": p["provider"],
                "match": match.group(),
                "start": match.start(),
                "end": match.end(),
            })
    return matches


def list_providers() -> list:
    """List all available pattern providers."""
    providers = set()
    for p in _load_all_patterns():
        providers.add(p.get("provider", "generic"))
    return sorted(providers)
