"""
AIDepShield V2 — Data repository.
Loads and manages the IOC database, registry, and monitored releases.
Uses JSON files for V2 MVP (migration path to SQLite/Postgres later).
"""

import json
import threading
from pathlib import Path
from typing import Optional, List, Dict
from datetime import datetime

from app.data.models import (
    VersionStatus, MonitoredRelease, RegistryEntry, PackageRegistry
)

BASE_DIR = Path(__file__).parent.parent.parent
IOC_DB_PATH = BASE_DIR / "iocs.json"
RELEASES_PATH = BASE_DIR / "data" / "monitored_releases.json"


class Repository:
    """Thread-safe data repository for IOC database, registry, and releases."""

    def __init__(self):
        self._lock = threading.Lock()
        self._ioc_db: dict = {}
        self._compromised: Dict[str, List[str]] = {}
        self._safe: Dict[str, List[str]] = {}
        self._monitored_releases: List[MonitoredRelease] = []
        self.load()

    def load(self):
        """Load IOC database from disk."""
        with self._lock:
            with open(IOC_DB_PATH) as f:
                self._ioc_db = json.load(f)

            self._compromised = {}
            self._safe = {}
            for pkg, data in self._ioc_db.get("safe_version_registry", {}).items():
                self._compromised[pkg.lower()] = data.get("compromised", [])
                self._safe[pkg.lower()] = data.get("verified_safe", [])

            # Load monitored releases if they exist
            if RELEASES_PATH.exists():
                with open(RELEASES_PATH) as f:
                    raw = json.load(f)
                self._monitored_releases = [
                    MonitoredRelease(**r) for r in raw
                ]

    # --- IOC Database ---

    @property
    def ioc_db(self) -> dict:
        return self._ioc_db

    @property
    def incidents(self) -> list:
        return self._ioc_db.get("incidents", [])

    @property
    def ioc_signatures(self) -> list:
        return self._ioc_db.get("ioc_signatures", [])

    def ioc_count(self) -> int:
        return sum(
            len(inc.get("affected_packages", []))
            for inc in self.incidents
        )

    # --- Version Registry ---

    def get_compromised_versions(self, package: str) -> List[str]:
        return self._compromised.get(package.lower(), [])

    def get_safe_versions(self, package: str) -> List[str]:
        return self._safe.get(package.lower(), [])

    def is_tracked_package(self, package: str) -> bool:
        lower = package.lower()
        return lower in self._compromised or lower in self._safe

    def get_version_status(self, package: str, version: str) -> VersionStatus:
        lower = package.lower()
        if version in self._compromised.get(lower, []):
            return VersionStatus.COMPROMISED
        if version in self._safe.get(lower, []):
            return VersionStatus.VERIFIED_SAFE
        if self.is_tracked_package(lower):
            return VersionStatus.UNKNOWN
        return VersionStatus.UNKNOWN

    def get_nearest_safe_version(self, package: str) -> Optional[str]:
        safe = self.get_safe_versions(package)
        return safe[-1] if safe else None

    def get_incident_for_package(self, package: str, version: str) -> Optional[dict]:
        lower = package.lower()
        for incident in self.incidents:
            for affected in incident.get("affected_packages", []):
                if affected["name"].lower() == lower:
                    compromised_versions = affected.get("compromised_versions", [])
                    if version in compromised_versions:
                        return incident
        return None

    def get_package_registry(self, package: str) -> PackageRegistry:
        lower = package.lower()
        entries = []

        # Add compromised versions
        for v in self.get_compromised_versions(lower):
            incident = self.get_incident_for_package(lower, v)
            entries.append(RegistryEntry(
                package=lower,
                version=v,
                status=VersionStatus.COMPROMISED,
                risk_score=100,
                incident_id=incident["id"] if incident else None,
                nearest_safe_version=self.get_nearest_safe_version(lower),
                evidence_links=[
                    ref for inc in self.incidents
                    for aff in inc.get("affected_packages", [])
                    if aff["name"].lower() == lower
                    for ref in aff.get("references", [])
                ],
            ))

        # Add safe versions
        for v in self.get_safe_versions(lower):
            reg = self._ioc_db.get("safe_version_registry", {}).get(lower, {})
            entries.append(RegistryEntry(
                package=lower,
                version=v,
                status=VersionStatus.VERIFIED_SAFE,
                risk_score=0,
                last_verified_at=reg.get("last_verified"),
                verification_methods=["analyst-reviewed"],
            ))

        return PackageRegistry(package=lower, versions=entries)

    # --- Monitored Releases ---

    @property
    def monitored_releases(self) -> List[MonitoredRelease]:
        return self._monitored_releases

    def add_monitored_release(self, release: MonitoredRelease):
        with self._lock:
            self._monitored_releases.append(release)
            self._save_releases()

    def _save_releases(self):
        RELEASES_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(RELEASES_PATH, "w") as f:
            json.dump(
                [r.model_dump() for r in self._monitored_releases],
                f, indent=2
            )

    # --- IOC Feed ---

    def get_enriched_ioc_feed(self) -> dict:
        feed = dict(self._ioc_db)
        feed["version"] = "2.0.0"
        feed["monitored_releases"] = [
            r.model_dump() for r in self._monitored_releases[-50:]
        ]
        return feed


# Singleton
repo = Repository()
