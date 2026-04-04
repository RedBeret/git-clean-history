# Contributing

Thanks for helping improve git-clean-history.

## Adding new secret patterns

1. Add the pattern to `git_clean_history/patterns.py`
2. Include: name, regex pattern and severity (critical/high/medium)
3. Add a test in `tests/test_patterns.py`
4. Open a PR with an example of what the pattern catches

## Reporting false positives

If the scanner flags something that isn't a real secret, open an issue with:
- The pattern name that matched
- A sanitized example of the false positive
- Suggested fix (more specific regex, context check, etc.)

## Running tests

```bash
pip install -r requirements.txt
pip install pytest
pytest tests/
```

## Code style

- Keep it simple and readable
- Functions should do one thing
- Tests for every new pattern
- No unnecessary dependencies
