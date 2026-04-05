# git-clean-history

Scan your git repos for accidentally committed secrets and remove them from history. No more leaked API keys haunting old commits.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/RedBeret/git-clean-history/actions/workflows/ci.yml/badge.svg)](https://github.com/RedBeret/git-clean-history/actions/workflows/ci.yml)

## What it does

1. **Scan** - checks every commit in your repo for secrets (API keys, tokens, passwords, SSH keys)
2. **Report** - shows you exactly which commits contain what secrets
3. **Clean** - helps remove secrets from git history using filter-branch or BFG

## Install

Works on macOS, Linux and Windows.

```bash
# from PyPI (when published)
pip install git-clean-history

# from source
git clone https://github.com/RedBeret/git-clean-history.git
cd git-clean-history
pip install -e .
```

## Quick start

```bash
# scan current repo
git-clean-history scan

# scan a specific repo
git-clean-history scan /path/to/repo

# JSON output for CI pipelines
git-clean-history scan --format json

# generate a report
git-clean-history report

# clean secrets from history (careful - rewrites history)
git-clean-history clean
```

## Detected patterns

### Cloud providers
- **AWS** - access keys (`AKIA...`), MWS auth tokens
- **Azure** - storage account keys, AD client secrets, SAS tokens, DevOps PATs, Teams webhooks
- **Google/GCP** - API keys (`AIza...`), OAuth client IDs, service account keys
- **DigitalOcean** - personal access tokens, OAuth tokens, Spaces keys
- **Firebase** - cloud messaging keys, database URLs

### Code platforms
- **GitHub** - personal access tokens (`ghp_`), OAuth, user-to-server, server-to-server, refresh tokens, fine-grained PATs
- **GitLab** - personal access tokens (`glpat-`), pipeline tokens, runner tokens

### AI/ML services
- **OpenAI** - API keys (`sk-proj-`)
- **Anthropic** - API keys (`sk-ant-`)
- **Groq** - API keys (`gsk_`)
- **Cohere** - API keys (`co-`)
- **Hugging Face** - tokens (`hf_`)
- **Replicate** - API tokens (`r8_`)

### Payment providers
- **Stripe** - secret keys, publishable keys, restricted keys, test keys
- **Square** - access tokens, OAuth secrets
- **PayPal/Braintree** - access tokens

### Messaging
- **Slack** - bot tokens, user tokens, webhooks, app tokens
- **Twilio** - API keys
- **SendGrid** - API keys
- **Mailgun** - API keys
- **Telegram** - bot tokens
- **Discord** - bot tokens

### Infrastructure
- **HashiCorp** - Vault tokens (`hvs.`, `hvb.`), Terraform Cloud tokens
- **Vercel** - access tokens
- **Netlify** - access tokens
- **Fly.io** - access tokens
- **Databricks** - API tokens
- **Linear** - API keys

### Package registries
- **npm** - access tokens, legacy tokens
- **PyPI** - API tokens
- **Docker Hub** - access tokens
- **NuGet** - API keys
- **RubyGems** - API keys

### SaaS platforms
- **Shopify** - access tokens, custom app tokens, private app passwords, shared secrets
- **Supabase** - service role keys, anon keys
- **PlanetScale** - database tokens, OAuth tokens

### Cryptographic material
- RSA, DSA, EC, OpenSSH, PGP private keys
- PKCS8 encrypted private keys

### Generic patterns
- Password/secret/token assignments in code
- Database connection strings with credentials
- Bearer tokens and Basic auth headers
- JWT tokens (`eyJ...`)

## How is this different from truffleHog/gitleaks?

Those tools are great at finding secrets. This tool focuses on **cleanup**:

- Generates actionable reports showing exactly what to remove
- Wraps BFG repo cleaner for easy history rewriting
- Includes a pre-commit hook to prevent future leaks
- Simple CLI focused on the scan-report-clean workflow
- Modular pattern library - easy to add your own provider patterns

## Commands

```bash
# scan for secrets
git-clean-history scan [path] [--format text|json]

# generate grouped report
git-clean-history report [path] [--format text|json]

# clean history (interactive)
git-clean-history clean [path] [--dry-run]

# install pre-commit hook
git-clean-history hook install
```

## Configuration

Create a `.git-clean-history.yaml` in your repo:

```yaml
# extra patterns to scan for
custom_patterns:
  - name: internal_api
    pattern: "mycompany-api-[a-z0-9]{32}"
    severity: high

# paths to ignore
ignore_paths:
  - "test/fixtures/"
  - "docs/examples/"

# patterns to ignore (false positives)
ignore_patterns:
  - "EXAMPLE_KEY"
  - "test_token_123"
```

## Adding your own patterns

Drop a Python file in `git_clean_history/patterns/` with a `PATTERNS` list:

```python
"""My custom secret patterns."""

PATTERNS = [
    {
        "name": "My Internal Token",
        "pattern": r"myco_[A-Za-z0-9]{32}",
        "severity": "high",
        "provider": "internal",
    },
]
```

Patterns are auto-discovered at runtime. No registration needed.

## CI/CD integration

### GitHub Actions

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0  # need full history
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: pip install git-clean-history
- run: git-clean-history scan --format json > scan-results.json
```

## License

[MIT](LICENSE)
