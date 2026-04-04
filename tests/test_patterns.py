"""Tests for secret detection patterns."""

from git_clean_history.patterns import scan_text, compile_patterns


def setup_module():
    global PATTERNS
    PATTERNS = compile_patterns()


def test_aws_key():
    text = "aws_key = AKIAIOSFODNN7EXAMPLE"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "AWS Access Key" for m in matches)


def test_github_token():
    text = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "GitHub Token" for m in matches)


def test_gitlab_token():
    text = "GITLAB_TOKEN=glpat-abcdefghijklmnopqrst"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "GitLab Token" for m in matches)


def test_stripe_key():
    # use sk_live_ prefix with enough chars to match pattern
    prefix = "sk_live_"
    suffix = "A" * 24
    text = f'stripe_key = "{prefix}{suffix}"'
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Stripe Secret Key" for m in matches)


def test_google_api_key():
    text = "GOOGLE_API_KEY=AIzaSyBcdefghijklmnopqrstuvwxyz12345678"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Google API Key" for m in matches)


def test_ssh_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "SSH Private Key" for m in matches)


def test_generic_secret():
    text = 'password = "SuperSecretPassword123456"'
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Generic Secret" for m in matches)


def test_no_false_positive_on_normal_text():
    text = "this is a normal comment about api design"
    matches = scan_text(text, PATTERNS)
    assert len(matches) == 0


def test_no_false_positive_on_short_strings():
    text = 'token = "abc"'
    matches = scan_text(text, PATTERNS)
    assert len(matches) == 0
