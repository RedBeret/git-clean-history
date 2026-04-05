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


def test_azure_storage_key():
    text = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=" + "A" * 86 + "=="
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Azure Storage Account Key" for m in matches)


def test_hashicorp_vault_token():
    prefix = "hvs."
    suffix = "A" * 30
    text = f"VAULT_TOKEN={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "HashiCorp Vault Token" for m in matches)


def test_terraform_token():
    prefix = "aaaaaaaaaa" + "aaaa"
    mid = ".atlasv1."
    suffix = "b" * 64
    text = f"TF_TOKEN={prefix}{mid}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "HashiCorp Terraform Token" for m in matches)


def test_digitalocean_token():
    prefix = "dop_v1_"
    suffix = "a" * 64
    text = f"DO_TOKEN={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "DigitalOcean Personal Access Token" for m in matches)


def test_jwt_token():
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
    sig = "SflKxwRJSMeKKF2QT4fwpM"
    text = f"token = {header}.{payload}.{sig}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "JSON Web Token" for m in matches)


def test_npm_token():
    prefix = "npm_"
    suffix = "A" * 36
    text = f"NPM_TOKEN={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "npm Access Token" for m in matches)


def test_pypi_token():
    prefix = "pypi-"
    suffix = "A" * 120
    text = f"PYPI_TOKEN={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "PyPI API Token" for m in matches)


def test_docker_hub_token():
    prefix = "dckr_pat_"
    suffix = "A" * 24
    text = f"DOCKER_TOKEN={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Docker Hub Access Token" for m in matches)


def test_shopify_token():
    prefix = "shpat_"
    suffix = "a" * 32
    text = f"SHOPIFY_TOKEN={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Shopify Access Token" for m in matches)


def test_planetscale_token():
    prefix = "pscale_tkn_"
    suffix = "A" * 44
    text = f"DB_TOKEN={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "PlanetScale Database Token" for m in matches)


def test_vercel_token():
    prefix = "vercel_"
    suffix = "A" * 30
    text = f"VERCEL_TOKEN={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Vercel Access Token" for m in matches)


def test_square_token():
    prefix = "sq0atp-"
    suffix = "A" * 22
    text = f"SQUARE_TOKEN={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Square Access Token" for m in matches)


def test_sendgrid_key():
    prefix = "SG."
    mid = "A" * 22
    suffix = "." + "B" * 43
    text = f"SENDGRID_KEY={prefix}{mid}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "SendGrid API Key" for m in matches)


def test_openai_key():
    prefix = "sk-proj-"
    suffix = "A" * 30
    text = f"OPENAI_KEY={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "OpenAI API Key" for m in matches)


def test_anthropic_key():
    prefix = "sk-ant-"
    suffix = "A" * 30
    text = f"ANTHROPIC_KEY={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Anthropic API Key" for m in matches)


def test_huggingface_token():
    prefix = "hf_"
    suffix = "A" * 36
    text = f"HF_TOKEN={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Hugging Face Token" for m in matches)


def test_linear_api_key():
    prefix = "lin_api_"
    suffix = "A" * 40
    text = f"LINEAR_KEY={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Linear API Key" for m in matches)


def test_databricks_token():
    prefix = "dapi"
    suffix = "a" * 32
    text = f"DB_TOKEN={prefix}{suffix}"
    matches = scan_text(text, PATTERNS)
    assert any(m["pattern_name"] == "Databricks API Token" for m in matches)


def test_no_false_positive_on_normal_text():
    text = "this is a normal comment about api design"
    matches = scan_text(text, PATTERNS)
    assert len(matches) == 0


def test_no_false_positive_on_short_strings():
    text = 'token = "abc"'
    matches = scan_text(text, PATTERNS)
    assert len(matches) == 0
