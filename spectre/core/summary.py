"""Concise investigation summaries.

The terminal report should show what matters before raw evidence or plugin names.
This module extracts simple, deterministic summary fields from plugin results.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from spectre.core.models import Category, InvestigationReport
from spectre.sources.common import normalize_domain


def build_summary(report: InvestigationReport) -> dict[str, Any]:
    """Build a concise summary for human-readable reports."""

    summary: dict[str, Any] = {
        "target": report.target,
        "target_type": report.category.value,
        "fields": [],
        "interesting": [],
    }

    raws = {result.plugin: result.raw for result in report.results}
    findings = [finding for result in report.results for finding in result.findings]

    def add(label: str, value: Any) -> None:
        if value is None or value == "" or value == [] or value == {}:
            return
        item = {"label": label, "value": value}
        if item not in summary["fields"]:
            summary["fields"].append(item)

    def interesting(text: str) -> None:
        if text and text not in summary["interesting"]:
            summary["interesting"].append(text)

    plan = report.metadata.get("analysis_plan") if isinstance(report.metadata, dict) else None
    if isinstance(plan, dict):
        summary["target_type"] = plan.get("target_type", summary["target_type"])

    target = report.target
    if report.category == Category.TECHNICAL:
        host = normalize_domain(target) if "://" in target or "." in target else target
        add("Target", host)

        dns = raws.get("dns_lookup") or (raws.get("technical_intelligence", {}).get("sources", {}) or {}).get("dns", {})
        if dns:
            a_count = len(dns.get("a_records", []) or dns.get("addresses", []))
            aaaa_count = len(dns.get("aaaa_records", []))
            mx_count = len(dns.get("mx_records", []))
            ns_count = len(dns.get("ns_records", []))
            parts = []
            if a_count:
                parts.append(f"{a_count} A")
            if aaaa_count:
                parts.append(f"{aaaa_count} AAAA")
            if mx_count:
                parts.append(f"{mx_count} MX")
            if ns_count:
                parts.append(f"{ns_count} NS")
            add("DNS", ", ".join(parts) if parts else "No common records found")
            if mx_count:
                interesting("Mail records are present")

        rdap = raws.get("rdap_lookup") or (raws.get("technical_intelligence", {}).get("sources", {}) or {}).get("rdap", {})
        owner = _owner_from_rdap(rdap)
        add("Owner", owner)

        ip_raw = raws.get("ip_lookup")
        if ip_raw:
            add("IP", ip_raw.get("ip"))
            if ip_raw.get("reverse_dns"):
                add("Reverse DNS", ip_raw.get("reverse_dns"))
            rdap_ip = ip_raw.get("rdap", {})
            add("Network", rdap_ip.get("name") or rdap_ip.get("handle"))
            add("Country", rdap_ip.get("country"))

        asn = raws.get("asn_lookup")
        if asn:
            names = []
            for record in asn.get("records", []):
                name = record.get("as_name") or record.get("name")
                asn_id = record.get("as") or record.get("asn")
                if name and asn_id:
                    names.append(f"AS{asn_id} {name}")
                elif name:
                    names.append(name)
            if names:
                add("ASN", "; ".join(dict.fromkeys(names)))

        reverse = raws.get("reverse_dns_lookup")
        if reverse and reverse.get("hostname"):
            add("Reverse DNS", reverse.get("hostname"))

        ssl = raws.get("ssl_lookup") or (raws.get("technical_intelligence", {}).get("sources", {}) or {}).get("ssl", {})
        if ssl:
            issuer = ssl.get("issuer", {})
            issuer_name = issuer.get("organizationName") or issuer.get("commonName")
            add("Certificate", issuer_name)
            if ssl.get("days_until_expiry") is not None:
                add("TLS expiry", f"{ssl.get('days_until_expiry')} days")
            if ssl.get("not_after"):
                interesting("Valid TLS certificate data was collected")

        tech = raws.get("technology_fingerprint")
        if tech:
            metadata_tech = _technologies_from_findings(findings)
            add("Technology", ", ".join(metadata_tech[:8]) if metadata_tech else None)
            headers = tech.get("headers", {})
            server = _safe_server_header(headers.get("server", ""))
            add("Server", server or "Unknown/hidden")
            if tech.get("status"):
                add("HTTP", tech.get("status"))
            details = _web_details_from_findings(findings)
            if details:
                sec = details.get("security_headers", {})
                if sec:
                    present = sum(1 for value in sec.values() if value)
                    add("Security headers", f"{present}/{len(sec)} present")
                if details.get("js_endpoints"):
                    add("JavaScript endpoints", len(details.get("js_endpoints", [])))
                    interesting("JavaScript endpoints were found")
                if details.get("authentication_clues"):
                    add("Auth clues", ", ".join(details.get("authentication_clues", [])[:8]))
                if details.get("comments"):
                    interesting("HTML comments were found")

        crtsh = raws.get("crtsh_lookup") or (raws.get("technical_intelligence", {}).get("sources", {}) or {}).get("crtsh", {})
        if crtsh:
            sub_count = len(crtsh.get("subdomains", []))
            cert_count = len(crtsh.get("certificates", []))
            add("Certificate Transparency", f"{sub_count} names, {cert_count} certificates")
            if sub_count:
                interesting("Certificate Transparency returned subdomain leads")

        repo_raw = raws.get("github_repo_analysis")
        if repo_raw:
            repo_data = repo_raw.get("repository", {})
            add("Repository", repo_data.get("full_name"))
            add("Default branch", repo_data.get("default_branch"))
            add("Stars", repo_data.get("stargazers_count"))
            add("Last push", repo_data.get("pushed_at"))
            if repo_raw.get("technology_hints"):
                add("Project hints", ", ".join(repo_raw.get("technology_hints", [])[:8]))
            if repo_raw.get("dependency_files"):
                add("Interesting files", len(repo_raw.get("dependency_files", [])))
            if repo_raw.get("potential_secret_findings"):
                interesting("Possible secret indicators found in repository")
            if repo_raw.get("releases"):
                interesting("Repository publishes releases")

        if target.startswith("https://"):
            interesting("Public HTTPS endpoint")

    elif report.category == Category.FILE:
        raw = raws.get("file_analysis", {})
        add("File", raw.get("name") or raw.get("path"))
        add("Size", _format_size(raw.get("size")))
        signatures = raw.get("signatures", [])
        if signatures:
            add("Type", signatures[0].get("name"))
        add("Entropy", raw.get("entropy"))
        if raw.get("hashes", {}).get("sha256"):
            add("SHA256", raw["hashes"]["sha256"])
        add("Strings", len(raw.get("strings", [])))
        iocs = raw.get("iocs", {})
        if iocs:
            counts = ", ".join(f"{key}: {len(value)}" for key, value in sorted(iocs.items()) if value)
            add("Extracted indicators", counts)
        if raw.get("language_hints"):
            add("Language/type hints", ", ".join(raw.get("language_hints", [])))
        binary_info = raw.get("binary_info", {})
        if binary_info:
            add("Binary", f"{binary_info.get('format')} {binary_info.get('architecture', '')}".strip())
            if binary_info.get("protections"):
                protections = ", ".join(f"{k}: {v}" for k, v in binary_info["protections"].items() if v is not None)
                add("Protections", protections)
        if raw.get("extension_matches_signature") is False:
            interesting("File extension does not match detected signature")
        if signatures and signatures[0].get("artifact_type") == "binary":
            interesting("Executable/binary file detected")
        if raw.get("embedded_archives"):
            interesting("Embedded archive signature found")
        if raw.get("embedded_executables"):
            interesting("Embedded executable signature found")
        if raw.get("potential_secrets"):
            interesting("Possible secret or token found")
        if raw.get("suspicious_patterns"):
            interesting("Suspicious string patterns found")

    elif report.category == Category.CRYPTO:
        best = None
        for raw in raws.values():
            if isinstance(raw, dict) and raw.get("best"):
                best = raw["best"]
        if best:
            add("Best result", best.get("value"))
            add("Decode path", " -> ".join(best.get("path", [])) or "none")
            interesting("Decoded candidate found")
        for result in report.results:
            if result.plugin == "hash_identifier":
                raw = result.raw
                candidates = [c.get("name") for c in raw.get("candidates", [])]
                add("Hash length", raw.get("length"))
                add("Possible types", ", ".join(candidates[:6]))

    elif report.category == Category.PERSONAL:
        add("Target", report.target)
        for result in report.results:
            if result.plugin == "email_lookup":
                add("Email domain", result.raw.get("domain"))
                if result.raw.get("domain_addresses"):
                    interesting("Email domain resolves")
            if result.plugin == "github_user_lookup" and result.raw.get("exists"):
                profile = result.raw.get("profile", {})
                add("GitHub", profile.get("html_url"))
                add("Public repos", profile.get("public_repos"))

    elif report.category == Category.HISTORICAL:
        raw = raws.get("wayback_lookup", {})
        add("Target", raw.get("domain") or report.target)
        add("Snapshots", len(raw.get("snapshots", [])))
        add("Years", ", ".join(raw.get("timeline", {}).keys()))
        if raw.get("closest"):
            interesting("Closest archived snapshot found")

    # Generic interesting findings from severities/errors.
    for result in report.results:
        if result.errors:
            interesting(f"{result.plugin} reported an error")
        for finding in result.findings:
            if finding.severity.value in {"medium", "high"} and finding.title not in {"Native file triage"}:
                interesting(finding.title)

    return summary


def _owner_from_rdap(rdap: dict[str, Any]) -> str | None:
    summary = rdap.get("summary", {}) if isinstance(rdap, dict) else {}
    entities = summary.get("entities", []) if isinstance(summary, dict) else []
    for preferred_role in ("registrant", "administrative", "technical", "registrar"):
        for entity in entities:
            roles = [str(role).lower() for role in entity.get("roles", [])]
            name = entity.get("name") or entity.get("handle")
            if preferred_role in roles and name:
                return name
    return None


def _technologies_from_findings(findings) -> list[str]:
    techs: list[str] = []
    for finding in findings:
        values = finding.metadata.get("technologies") if isinstance(finding.metadata, dict) else None
        if values:
            techs.extend(str(value) for value in values)
    return sorted(dict.fromkeys(techs))


def _web_details_from_findings(findings) -> dict[str, Any]:
    for finding in findings:
        if isinstance(finding.metadata, dict) and finding.metadata.get("web_details"):
            return finding.metadata["web_details"]
    return {}


def _safe_server_header(value: str) -> str | None:
    if not value:
        return None
    lowered = value.lower().strip()
    known_tokens = ["nginx", "apache", "cloudflare", "openresty", "iis", "microsoft-iis", "envoy", "caddy", "gunicorn", "uvicorn"]
    if any(token in lowered for token in known_tokens) and not any(bad in value for bad in [";", "--", "'", '"', "<", ">"]):
        return value.strip()
    return None


def _format_size(value: Any) -> str | None:
    if not isinstance(value, int):
        return None
    if value < 1024:
        return f"{value} bytes"
    if value < 1024 * 1024:
        return f"{round(value / 1024, 1)} KB"
    return f"{round(value / (1024 * 1024), 1)} MB"
