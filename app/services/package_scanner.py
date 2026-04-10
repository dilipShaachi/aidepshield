"""
AIDepShield V2 — Package scanner.
Checks packages against the IOC database and version registry.

V2 change: unknown versions default to REVIEW, not SAFE.
"""

from typing import List
from app.data.models import (
    PackageInput, DependencyResult, Verdict, Severity, VersionStatus
)
from app.data.repository import repo


def scan_package(pkg: PackageInput, strict_unknowns: bool = True) -> DependencyResult:
    """Scan a single package against the IOC database."""
    name = pkg.name
    version = pkg.version
    name_lower = name.lower()

    # 1. Explicit compromised version match => FAIL
    if version and version in repo.get_compromised_versions(name_lower):
        incident = repo.get_incident_for_package(name_lower, version)
        indicators = []
        if incident:
            for affected in incident.get("affected_packages", []):
                if affected["name"].lower() == name_lower:
                    indicators = affected.get("indicators", [])
                    break

        nearest_safe = repo.get_nearest_safe_version(name_lower)
        recommendation = f"Pin to {nearest_safe} immediately." if nearest_safe else "Remove this package."

        return DependencyResult(
            package=name,
            version=version,
            status=VersionStatus.COMPROMISED,
            verdict=Verdict.FAIL,
            severity=Severity.CRITICAL,
            ioc=", ".join(indicators) if indicators else None,
            recommendation=recommendation,
            nearest_safe_version=nearest_safe,
            incident_id=incident["id"] if incident else None,
            report_url=f"https://aidepshield.dev/report/{incident['id']}" if incident else None,
        )

    # 2. Explicit verified safe version match => SAFE
    if version and version in repo.get_safe_versions(name_lower):
        return DependencyResult(
            package=name,
            version=version,
            status=VersionStatus.VERIFIED_SAFE,
            verdict=Verdict.SAFE,
            severity=Severity.NONE,
        )

    # 3. Tracked package, unknown version => REVIEW
    if repo.is_tracked_package(name_lower):
        nearest_safe = repo.get_nearest_safe_version(name_lower)
        return DependencyResult(
            package=name,
            version=version,
            status=VersionStatus.UNKNOWN,
            verdict=Verdict.REVIEW,
            severity=Severity.MEDIUM,
            recommendation=f"Version not in verified registry. Nearest verified safe: {nearest_safe}" if nearest_safe else "Version not in verified registry. Verify manually.",
            nearest_safe_version=nearest_safe,
        )

    # 4. Untracked package
    if strict_unknowns:
        # V2: unknown defaults to REVIEW
        return DependencyResult(
            package=name,
            version=version,
            status=VersionStatus.UNKNOWN,
            verdict=Verdict.REVIEW,
            severity=Severity.LOW,
            recommendation="Package not tracked by AIDepShield. Review manually or add to watchlist.",
        )
    else:
        return DependencyResult(
            package=name,
            version=version,
            status=VersionStatus.UNKNOWN,
            verdict=Verdict.SAFE,
            severity=Severity.NONE,
        )


def scan_packages(
    packages: List[PackageInput],
    strict_unknowns: bool = True,
) -> List[DependencyResult]:
    """Scan a list of packages."""
    return [scan_package(pkg, strict_unknowns) for pkg in packages]
