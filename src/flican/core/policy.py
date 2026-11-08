from flican.core.models import Finding, Severity


SEVERITY_RANK = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


def should_fail(findings: list[Finding], fail_on: Severity) -> bool:
    """Check whether any finding reaches the failure threshold."""
    threshold = SEVERITY_RANK[fail_on]

    return any(
        SEVERITY_RANK[finding.severity] >= threshold
        for finding in findings
    )