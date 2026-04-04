"""CLI entry point."""

import json
import sys
import click
from .scanner import GitScanner


@click.group()
def cli():
    """Scan git repos for secrets and clean them from history."""
    pass


@cli.command()
@click.argument("path", default=".")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def scan(path, output_format):
    """Scan a repo for secrets in git history."""
    scanner = GitScanner(path)

    def progress(current, total):
        click.echo(f"\rscanning commit {current}/{total}", nl=False, err=True)

    findings = scanner.scan_all(progress_callback=progress)
    click.echo("", err=True)

    if not findings:
        click.echo("no secrets found")
        return

    if output_format == "json":
        # redact actual secret values in output
        safe_findings = []
        for f in findings:
            safe = dict(f)
            val = safe.get("match", "")
            if len(val) > 8:
                safe["match"] = val[:4] + "..." + val[-4:]
            safe_findings.append(safe)
        click.echo(json.dumps(safe_findings, indent=2))
    else:
        click.echo(f"found {len(findings)} potential secret(s):\n")
        for f in findings:
            val = f.get("match", "")
            redacted = val[:4] + "..." + val[-4:] if len(val) > 8 else "***"
            click.echo(f"  [{f['severity']}] {f['pattern_name']}")
            click.echo(f"    commit: {f.get('commit', 'unknown')[:8]}")
            click.echo(f"    value:  {redacted}")
            click.echo(f"    date:   {f.get('date', 'unknown')}")
            click.echo()


@cli.command()
@click.argument("path", default=".")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def report(path, output_format):
    """Generate a detailed scan report."""
    scanner = GitScanner(path)
    findings = scanner.scan_all()

    if output_format == "json":
        report_data = {
            "total_findings": len(findings),
            "by_severity": {},
            "by_type": {},
        }
        for f in findings:
            sev = f["severity"]
            report_data["by_severity"][sev] = report_data["by_severity"].get(sev, 0) + 1
            name = f["pattern_name"]
            report_data["by_type"][name] = report_data["by_type"].get(name, 0) + 1
        click.echo(json.dumps(report_data, indent=2))
    else:
        if not findings:
            click.echo("clean - no secrets found in history")
            return
        click.echo(f"scan report: {len(findings)} finding(s)\n")
        by_sev = {}
        for f in findings:
            by_sev.setdefault(f["severity"], []).append(f)
        for sev in ["critical", "high", "medium"]:
            items = by_sev.get(sev, [])
            if items:
                click.echo(f"  {sev}: {len(items)} finding(s)")


@cli.command()
@click.argument("path", default=".")
@click.option("--dry-run", is_flag=True, help="show what would be cleaned without doing it")
def clean(path, dry_run):
    """Remove secrets from git history."""
    scanner = GitScanner(path)
    findings = scanner.scan_all()

    if not findings:
        click.echo("nothing to clean")
        return

    click.echo(f"found {len(findings)} secret(s) to clean")

    if dry_run:
        click.echo("dry run - no changes made")
        return

    click.echo("to clean secrets from history, use BFG repo cleaner:")
    click.echo("  1. install: brew install bfg")
    click.echo("  2. create a file with secrets to remove (one per line)")
    click.echo("  3. run: bfg --replace-text secrets.txt")
    click.echo("  4. run: git reflog expire --expire=now --all && git gc --prune=now")
    click.echo("  5. force push: git push --force")
    click.echo("\nwarning: this rewrites history. coordinate with your team first.")


if __name__ == "__main__":
    cli()
