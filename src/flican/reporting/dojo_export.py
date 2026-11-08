"""Map Flican findings to the pinned Generic Findings Import contract."""

from flican.core.models import Finding, Severity
from flican.core.paths import normalize_source_path
from flican.core.provenance import canonical_digest

SCANNERS = ("gitleaks", "semgrep", "trivy", "checkov")


def test_type_name(scanner: str) -> str:
    if scanner not in SCANNERS:
        raise ValueError("Unsupported scanner for DefectDojo export.")
    return f"Flican {scanner.title()} (Generic Findings Import)"


def validate_finding(raw: dict) -> Finding:
    if not isinstance(raw, dict) or set(raw) - set(Finding.__dataclass_fields__):
        raise ValueError("Invalid normalized finding fields.")
    try:
        finding = Finding(**raw)
    except TypeError as error:
        raise ValueError("Incomplete normalized finding.") from error
    if finding.scanner not in SCANNERS:
        raise ValueError("Unknown scanner in the normalized report.")
    for field in ("rule_id", "description"):
        value = getattr(finding, field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Finding identity and description must be non-empty strings.")
    Severity(finding.severity)
    if finding.file_path is not None:
        if not isinstance(finding.file_path, str) or finding.file_path.startswith("/") or normalize_source_path(finding.file_path) != finding.file_path:
            raise ValueError("Finding file paths must be normalized relative paths.")
    if finding.line is not None and (type(finding.line) is not int or finding.line < 1):
        raise ValueError("Finding lines must be positive integers.")
    if finding.column is not None and (type(finding.column) is not int or finding.column < 1):
        raise ValueError("Finding columns must be positive integers.")
    for field in ("package_name", "package_version", "fixed_version", "resource_id", "severity_source", "framework"):
        value = getattr(finding, field)
        if value is not None and not isinstance(value, str):
            raise ValueError("Invalid optional finding metadata.")
    return finding


def finding_identity(finding: Finding, context_key: str, profile_hash: str) -> str:
    # Code occurrences and Dockerfile instructions need their line to distinguish
    # repeated calls. Terraform resources have a stable resource identity instead.
    line = finding.line if finding.scanner in ("gitleaks", "semgrep") or finding.framework == "dockerfile" else None
    return canonical_digest({
        "version": 1, "context": context_key, "profile": profile_hash,
        "scanner": finding.scanner, "framework": finding.framework,
        "rule": finding.rule_id, "path": finding.file_path, "line": line,
        "column": finding.column if line is not None else None,
        "resource": finding.resource_id, "package": finding.package_name,
        "package_version": finding.package_version,
    })


def export_scanner(findings: list[dict], scanner: str, context_key: str,
                   profile_hash: str, completed_at: str) -> dict:
    exported = []
    identities = set()
    for raw in findings:
        finding = validate_finding(raw)
        if finding.scanner != scanner:
            continue
        identity = finding_identity(finding, context_key, profile_hash)
        if identity in identities:
            raise ValueError("The scan contains ambiguous repeated finding identities.")
        identities.add(identity)
        metadata = [f"Flican scanner: {scanner}", f"Rule: {finding.rule_id}"]
        if finding.column is not None:
            metadata.append(f"Column: {finding.column}")
        for label, value in (("Framework", finding.framework), ("Resource", finding.resource_id),
                             ("Package", finding.package_name), ("Declared version", finding.package_version),
                             ("Fixed version", finding.fixed_version), ("Severity source", finding.severity_source)):
            if value:
                metadata.append(f"{label}: {value}")
        item = {
            "title": f"{finding.rule_id}: {finding.description}"[:250],
            "description": finding.description + "\n\n" + "\n".join(metadata),
            "severity": Severity(finding.severity).value.title(),
            "date": completed_at[:10], "unique_id_from_tool": identity,
            "vuln_id_from_tool": finding.rule_id,
            "tags": ["flican", scanner] + ([finding.framework] if finding.framework else []),
            "active": True, "verified": False,
        }
        if finding.file_path is not None:
            item["file_path"] = finding.file_path
        if finding.line is not None:
            item["line"] = finding.line
        if finding.package_name:
            item["component_name"] = finding.package_name
        if finding.package_version:
            item["component_version"] = finding.package_version
        if scanner == "trivy":
            if finding.rule_id.startswith(("CVE-", "GHSA-")):
                item["vulnerability_ids"] = [finding.rule_id]
            if finding.fixed_version:
                item.update(fix_available=True, fix_version=finding.fixed_version,
                            mitigation=f"Upgrade {finding.package_name} to {finding.fixed_version}.")
        exported.append(item)
    return {"type": test_type_name(scanner), "static_tool": True,
            "dynamic_tool": False, "findings": exported}
