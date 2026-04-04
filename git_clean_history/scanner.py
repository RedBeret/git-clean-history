"""Scan git history for secrets."""

import subprocess
from .patterns import compile_patterns, scan_text


class GitScanner:
    def __init__(self, repo_path="."):
        self.repo_path = repo_path
        self.patterns = compile_patterns()

    def get_commits(self) -> list:
        """Get all commit hashes in the repo."""
        result = subprocess.run(
            ["git", "log", "--all", "--format=%H"],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return []
        return [h.strip() for h in result.stdout.strip().split("\n") if h.strip()]

    def get_diff(self, commit_hash: str) -> str:
        """Get the diff for a specific commit."""
        result = subprocess.run(
            ["git", "show", "--format=", "--diff-filter=ACMR", commit_hash],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
        )
        return result.stdout if result.returncode == 0 else ""

    def get_commit_info(self, commit_hash: str) -> dict:
        """Get commit metadata."""
        result = subprocess.run(
            ["git", "log", "-1", "--format=%an|%ae|%ai|%s", commit_hash],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return {}
        parts = result.stdout.strip().split("|", 3)
        if len(parts) < 4:
            return {}
        return {
            "author": parts[0],
            "email": parts[1],
            "date": parts[2],
            "message": parts[3],
        }

    def scan_commit(self, commit_hash: str) -> list:
        """Scan a single commit for secrets."""
        diff = self.get_diff(commit_hash)
        if not diff:
            return []

        matches = scan_text(diff, self.patterns)
        for m in matches:
            m["commit"] = commit_hash

        return matches

    def scan_all(self, progress_callback=None) -> list:
        """Scan all commits in the repo. Returns list of findings."""
        commits = self.get_commits()
        all_findings = []

        for i, commit_hash in enumerate(commits):
            findings = self.scan_commit(commit_hash)
            if findings:
                info = self.get_commit_info(commit_hash)
                for f in findings:
                    f.update(info)
                all_findings.extend(findings)

            if progress_callback:
                progress_callback(i + 1, len(commits))

        return all_findings
