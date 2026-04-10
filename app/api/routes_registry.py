"""
AIDepShield V2 — Registry & IOC feed API routes.
"""

from fastapi import APIRouter, HTTPException

from app.data.repository import repo
from app.data.models import PackageRegistry, RegistryEntry

router = APIRouter()


@router.get("/iocs")
def get_iocs():
    """Public IOC feed — free forever. Enriched with monitored releases in V2."""
    return repo.get_enriched_ioc_feed()


@router.get("/registry/{package}", response_model=PackageRegistry)
def get_package_registry(package: str):
    """Return all tracked versions for a package with trust status and evidence."""
    registry = repo.get_package_registry(package)
    if not registry.versions:
        raise HTTPException(
            status_code=404,
            detail=f"Package '{package}' not found in registry. Submit a scan to check it.",
        )
    return registry


@router.get("/registry/{package}/{version}", response_model=RegistryEntry)
def get_version_status(package: str, version: str):
    """Return trust status + evidence for a specific package version."""
    registry = repo.get_package_registry(package)
    for entry in registry.versions:
        if entry.version == version:
            return entry
    raise HTTPException(
        status_code=404,
        detail=f"Version '{version}' of '{package}' not found in registry.",
    )


@router.get("/monitored/releases")
def get_monitored_releases(limit: int = 50):
    """List recent monitored package releases and their verdicts."""
    releases = repo.monitored_releases
    # Most recent first
    sorted_releases = sorted(
        releases,
        key=lambda r: r.checked_at or "",
        reverse=True,
    )
    return {
        "count": len(sorted_releases[:limit]),
        "total": len(releases),
        "releases": [r.model_dump() for r in sorted_releases[:limit]],
    }


@router.get("/health")
def health():
    """Service health check."""
    return {
        "status": "ok",
        "version": "2.0.0",
        "ioc_count": repo.ioc_count(),
        "monitored_packages": len(repo.monitored_releases),
        "db_updated": repo.ioc_db.get("updated"),
    }
