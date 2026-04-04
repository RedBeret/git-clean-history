# git-clean-history

Scan your git repos for accidentally committed secrets and remove them from history. No more leaked API keys haunting old commits.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## What it does

1. **Scan** - checks every commit in your repo for secrets (API keys, tokens, passwords, SSH keys)
2. **Report** - shows you exactly which commits contain what secrets
3. **Clean** - helps remove secrets from git history using filter-branch or BFG

## Quick start

```bash
pip install -r requirements.txt

# scan current repo
python -m git_clean_history scan

# scan a specific repo
python -m git_clean_history scan /path/to/repo

# generate a report
python -m git_clean_history report

# clean secrets from history (careful - rewrites history)
python -m git_clean_history clean
```

## Detected patterns

- AWS access keys (`AKIA...`)
- GitHub tokens (`ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`)
- GitLab tokens (`glpat-`)
- Slack tokens and webhooks
- Stripe keys (`sk_live_`, `pk_live_`)
- Google API keys (`AIza...`)
- SSH private keys
- Generic patterns (`password=`, `secret=`, `api_key=`)
- And more - see [patterns.py](git_clean_history/patterns.py)

## How is this different from truffleHog/gitleaks?

Those tools are great at finding secrets. This tool focuses on **cleanup**:

- Generates actionable reports showing exactly what to remove
- Wraps BFG repo cleaner for easy history rewriting
- Includes a pre-commit hook to prevent future leaks
- Simple CLI focused on the scan-report-clean workflow

## Commands

```bash
# scan for secrets
python -m git_clean_history scan [path] [--pattern custom_regex]

# generate report
python -m git_clean_history report [--format text|json]

# clean history
python -m git_clean_history clean [--dry-run]

# install pre-commit hook
python -m git_clean_history hook install
```

## Configuration

Create a `.git-clean-history.yaml` in your repo:

```yaml
# extra patterns to scan for
custom_patterns:
  - name: internal_api
    pattern: "mycompany-api-[a-z0-9]{32}"

# paths to ignore
ignore_paths:
  - "test/fixtures/"
  - "docs/examples/"

# patterns to ignore (false positives)
ignore_patterns:
  - "EXAMPLE_KEY"
  - "test_token_123"
```

## License

[MIT](LICENSE)
