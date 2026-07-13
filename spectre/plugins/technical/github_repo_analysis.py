"""GitHub repository analysis plugin."""

from __future__ import annotations

from typing import Any

from spectre.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from spectre.core.plugin import BasePlugin
from spectre.core.registry import registry
from spectre.sources.github.adapter import GitHubAdapter, parse_repo_slug


@registry.register
class GitHubRepoAnalysisPlugin(BasePlugin):
    name = "github_repo_analysis"
    category = Category.TECHNICAL
    description = "Analyze public GitHub repository metadata, technologies, timeline, and redacted secret indicators via the GitHub source adapter."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        slug = parse_repo_slug(target.value)
        return Detection(slug is not None, 0.96 if slug else 0.0, "GitHub repository target" if slug else "not a GitHub repository")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        slug = parse_repo_slug(target.value)
        if not slug:
            raise ValueError("target is not a GitHub repository URL or owner/repo slug")
        owner, repo = slug
        adapter = GitHubAdapter(
            timeout=float(target.options.get("timeout", 10.0)),
            use_cache=bool(target.options.get("cache", False)),
            cache_ttl=int(target.options.get("cache_ttl", 3600)),
            cache_path=str(target.options.get("cache_path", "investigations/source_cache.db")),
        )
        return adapter.repository(
            owner,
            repo,
            max_secret_files=int(target.options.get("github_secret_files", 25)),
            max_blob_size=int(target.options.get("github_secret_max_blob_size", 180_000)),
        )

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        if raw.get("exists") is False:
            return [
                Finding(
                    title="GitHub repository not found",
                    description="GitHub returned 404 for this repository candidate.",
                    category=self.category,
                    plugin=self.name,
                    confidence=0.75,
                    severity=Severity.INFO,
                    evidence=[Evidence(source="github.repo", value=f"{raw.get('owner')}/{raw.get('repo')}"), Evidence(source="github.message", value=raw.get("message"))],
                    metadata={"rate": raw.get("rate", {}), "adapter": raw.get("metadata", {})},
                )
            ]
        repo = raw.get("repository", {})
        evidence = [
            Evidence(source="github.repo.full_name", value=repo.get("full_name")),
            Evidence(source="github.repo.html_url", value=repo.get("html_url")),
            Evidence(source="github.repo.description", value=repo.get("description")),
            Evidence(source="github.repo.created_at", value=repo.get("created_at")),
            Evidence(source="github.repo.updated_at", value=repo.get("updated_at")),
            Evidence(source="github.repo.pushed_at", value=repo.get("pushed_at")),
            Evidence(source="github.repo.default_branch", value=repo.get("default_branch")),
            Evidence(source="github.repo.visibility", value=repo.get("visibility")),
            Evidence(source="github.repo.archived", value=repo.get("archived")),
            Evidence(source="github.repo.fork", value=repo.get("fork")),
            Evidence(source="github.repo.stars", value=repo.get("stargazers_count")),
            Evidence(source="github.repo.forks", value=repo.get("forks_count")),
            Evidence(source="github.languages", value=raw.get("languages")),
            Evidence(source="github.topics", value=raw.get("topics")),
            Evidence(source="github.technology_hints", value=raw.get("technology_hints")),
            Evidence(source="github.releases", value=raw.get("releases", [])),
            Evidence(source="github.activity_summary", value=raw.get("activity_summary", {})),
            Evidence(source="github.repository_health", value=raw.get("repository_health", {})),
            Evidence(source="github.dependency_files", value=raw.get("dependency_files", [])),
            Evidence(source="github.tree_sample_count", value=raw.get("tree_sample_count")),
        ]
        for contributor in raw.get("contributors_sample", [])[:10]:
            evidence.append(Evidence(source="github.contributor", value=contributor))
        commits = raw.get("recent_commits", [])
        for commit in commits[:5]:
            evidence.append(
                Evidence(
                    source="github.recent_commit",
                    value={
                        "sha": commit.get("sha", "")[:12],
                        "html_url": commit.get("html_url"),
                        "author_date": (commit.get("commit") or {}).get("author", {}).get("date"),
                        "message": ((commit.get("commit") or {}).get("message") or "").splitlines()[0][:140],
                    },
                )
            )

        potential_secrets = raw.get("potential_secret_findings", [])
        for secret in potential_secrets:
            evidence.append(Evidence(source="github.secret_indicator.redacted", value=secret))
        if raw.get("tree_error"):
            evidence.append(Evidence(source="github.tree_error", value=raw["tree_error"]))
        evidence.append(Evidence(source="github.secret_scan_note", value=raw.get("secret_scan_note")))

        severity = Severity.MEDIUM if potential_secrets else Severity.INFO
        return [
            Finding(
                title="GitHub repository intelligence",
                description=(
                    f"Collected repository metadata, languages, recent timeline, technology hints, "
                    f"and {len(potential_secrets)} redacted potential secret indicator(s)."
                ),
                category=self.category,
                plugin=self.name,
                confidence=0.88,
                severity=severity,
                evidence=evidence,
                metadata={"rate": raw.get("rate", {}), "secret_indicators": len(potential_secrets), "adapter": raw.get("metadata", {})},
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
