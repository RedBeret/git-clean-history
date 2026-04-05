"""Tests for secret detection patterns."""

from git_clean_history.patterns import scan_text, compile_patterns


def setup_module():
    global PATTERNS
    PATTERNS = compile_patterns()


def test_aws_key():
    # build dynamically so scanners don't flag the test file
    prefix = "AKIA"
    suffix = "IOSFODNN7EXAMPLE"
    text = f"aws_key = {prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "AWS Access Key ID" for m in matches)


def test_github_token():
    prefix = "ghp_"
    suffix = "A" * 36
    text = f"token = {prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "GitHub Personal Access Token" for m in matches)


def test_gitlab_token():
    prefix = "glpat-"
    suffix = "a" * 20
    text = f"GITLAB_TOKEN={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "GitLab Personal Access Token" for m in matches)


def test_stripe_key():
    prefix = "sk_live_"
    suffix = "A" * 24
    text = f'stripe_key = "{prefix}{suffix}"'
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Stripe Secret Key" for m in matches)


def test_google_api_key():
    prefix = "AIzaSy"
    suffix = "B" * 33
    text = f"GOOGLE_API_KEY={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Google API Key" for m in matches)


def test_ssh_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "RSA Private Key" for m in matches)


def test_generic_secret():
    text = 'password = "SuperSecretPassword123456"'
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Generic Secret Assignment" for m in matches)


def test_no_false_positive_on_normal_text():
    text = "this is a normal comment about api design"
    matches = scan_text(text, PATTERNS)
    assert len(matches) == 0


def test_no_false_positive_on_short_strings():
    text = 'token = "abc"'
    matches = scan_text(text, PATTERNS)
    assert len(matches) == 0
