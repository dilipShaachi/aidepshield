"""
AIDepShield V2 — Risk engine.
Combines dependency and workflow scan results into a unified verdict.
"""

from typing import List, Optional
from datetime import datetime, timezone

from app.data.models import (
    ScanRequest, ScanResponse, ScanOptions,
    DependencyResult, WorkflowFinding,
    Verdict, Severity, PackageInput
)
from app.services.requirements_parser import parse_requirements
from app.services.package_scanner import scan_packages
from app.services.workflow_scanner import scan_workflows


# Severity ordering for comparison
SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.NONE: 0,
}


def should_fail(severity: Severity, fail_threshold: str = "high") -> bool:
    """Check if a severity level meets or exceeds the fail threshold."""
    threshold_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    threshold = threshold_map.get(fail_threshold, Severity.HIGH)
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)


def run_scan(request: ScanRequest) -> ScanResponse:
    """Run unified scan across dependencies and workflows."""
    options = request.options or ScanOptions()

    # --- Parse packages ---
    packages: List[PackageInput] = []
    if request.requirements:
        packages = parse_requirements(request.requirements)
    if request.packages:
        packages.extend(request.packages)

    # --- Scan dependencies ---
    dep_results: List[DependencyResult] = []
    if packages:
        dep_results = scan_packages(packages, strict_unknowns=options.strict_unknowns)

    # --- Scan workflows ---
    wf_results: List[WorkflowFinding] = []
    if request.workflows:
        wf_results = scan_workflows(request.workflows)

    # --- Compute overall verdict ---
    verdict = Verdict.SAFE
    confidence = 1.0
    recommendations = []

    # Check dependency results
    for r in dep_results:
        if r.verdict == Verdict.FAIL:
            verdict = Verdict.FAIL
            if r.recommendation:
                recommendations.append(r.recommendation)
        elif r.verdict == Verdict.REVIEW and verdict != Verdict.FAIL:
            verdict = Verdict.REVIEW
            confidence = min(confidence, 0.7)

    # Check workflow findings
    for f in wf_results:
        if should_fail(f.severity, "high"):
            if verdict != Verdict.FAIL:
                # Workflow issues alone produce FAIL if critical
                if f.severity == Severity.CRITICAL:
                    verdict = Verdict.FAIL
                elif verdict != Verdict.FAIL:
                    verdict = Verdict.REVIEW
            recommendations.append(f.recommended_fix)

    # Generate summary
    compromised_count = sum(1 for r in dep_results if r.verdict == Verdict.FAIL)
    review_count = sum(1 for r in dep_results if r.verdict == Verdict.REVIEW)
    wf_critical = sum(1 for f in wf_results if f.severity in (Severity.CRITICAL, Severity.HIGH))

    parts = []
    if compromised_count:
        parts.append(f"{compromised_count} compromised dependency(s)")
    if review_count:
        parts.append(f"{review_count} unverified dependency(s)")
    if wf_critical:
        parts.append(f"{wf_critical} CI/CD workflow risk(s)")

    if verdict == Verdict.FAIL:
        summary = f"FAIL — {' and '.join(parts)} detected"
        confidence = 0.97 if compromised_count else 0.85
    elif verdict == Verdict.REVIEW:
        summary = f"REVIEW — {' and '.join(parts)} need attention"
        confidence = 0.7
    else:
        summary = f"SAFE — {len(dep_results)} package(s) and {len(wf_results)} finding(s) checked"
        confidence = 0.95

    recommendation = " ".join(recommendations[:3]) if recommendations else None

    return ScanResponse(
        verdict=verdict,
        confidence=confidence,
        summary=summary,
        recommendation=recommendation,
        scanned_at=datetime.now(timezone.utc).isoformat() + "Z",
        dependency_results=dep_results,
        workflow_results=wf_results,
        packages_scanned=len(dep_results),
        workflows_scanned=len(request.workflows) if request.workflows else 0,
    )
