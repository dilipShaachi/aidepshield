"""
AIDepShield V2 — PyPI Monitor.
Watches a curated set of AI-critical packages for suspicious new releases.
Computes risk signals and stores verdicts for the public feed.
"""

import re
import httpx
from typing import List, Optional
from datetime import datetime, timezone
from pathlib import Path

import yaml

from app.data.models import (
    MonitoredRelease, RiskSignal, Verdict, Severity
)
from app.data.repository import repo

WATCHLIST_PATH = Path(__file__).parent.parent.parent / "data" / "watchlist.yaml"
PYPI_BASE = "https://pypi.org/pypi"

# Suspicious file patterns in package archives
SUSPICIOUS_FILES = {
    ".pth": ("Persistent code execution hook", Severity.CRITICAL),
    "setup.cfg.bak": ("Backup config — may indicate tampering", Severity.MEDIUM),
    "__pycache__": ("Pre-compiled bytecode in source dist", Severity.LOW),
}

SUSPICIOUS_PATTERNS = [
    (r"curl\s+.*\|\s*(ba)?sh", "Remote script execution at install time", Severity.CRITICAL),
    (r"wget\s+.*\|\s*(ba)?sh", "Remote script execution at install time", Severity.CRITICAL),
    (r"subprocess\.(call|run|Popen)\s*\(", "Subprocess execution", Severity.MEDIUM),
    (r"os\.system\s*\(", "Shell command execution", Severity.MEDIUM),
    (r"exec\s*\(", "Dynamic code execution", Severity.MEDIUM),
    (r"eval\s*\(", "Dynamic code evaluation", Severity.MEDIUM),
    (r"base64\.(b64)?decode", "Base64 decoding (possible obfuscation)", Severity.LOW),
    (r"import\s+ctypes", "Native code loading", Severity.LOW),
]


def load_watchlist() -> List[str]:
    """Load package watchlist from YAML config."""
    if not WATCHLIST_PATH.exists():
        return []
    with open(WATCHLIST_PATH) as f:
        config = yaml.safe_load(f)
    return config.get("packages", [])


async def check_package_release(package: str) -> Optional[MonitoredRelease]:
    """
    Check the latest release of a package on PyPI and compute risk signals.
    Returns a MonitoredRelease if a new release is found, None otherwise.
    """
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{PYPI_BASE}/{package}/json")
            if resp.status_code != 200:
                return None
            data = resp.json()
    except Exception:
        return None

    info = data.get("info", {})
    version = info.get("version", "")
    releases = data.get("releases", {})

    if not version or version not in releases:
        return None

    # Check if we already have this release
    existing = [r for r in repo.monitored_releases
                if r.package == package and r.version == version]
    if existing:
        return None

    # Get release metadata
    release_files = releases.get(version, [])
    published_at = None
    source_url = None
    if release_files:
        published_at = release_files[0].get("upload_time_iso_8601")
        for rf in release_files:
            if rf.get("packagetype") == "sdist":
                source_url = rf.get("url")
                break
        if not source_url:
            source_url = release_files[0].get("url")

    # Compute risk signals
    signals = _compute_risk_signals(info, version, releases, release_files)
    risk_score = _compute_risk_score(signals)

    # Determine verdict
    if risk_score >= 70:
        verdict = Verdict.REVIEW
    elif risk_score >= 40:
        verdict = Verdict.REVIEW
    else:
        verdict = Verdict.SAFE

    # Override if the version is in our compromised list
    if version in repo.get_compromised_versions(package):
        verdict = Verdict.FAIL
        risk_score = 100

    release = MonitoredRelease(
        package=package,
        version=version,
        published_at=published_at,
        source_url=source_url,
        risk_score=risk_score,
        verdict=verdict,
        signals=signals,
        checked_at=datetime.now(timezone.utc).isoformat(),
    )

    return release


def _compute_risk_signals(
    info: dict, version: str, releases: dict, release_files: list
) -> List[RiskSignal]:
    """Compute heuristic risk signals for a package release."""
    signals: List[RiskSignal] = []

    # Signal: post-release suffix
    if re.search(r'-post\d+$', version):
        signals.append(RiskSignal(
            type="version_pattern",
            severity=Severity.HIGH,
            title="Post-release version suffix detected",
            evidence=f"Version {version} uses -post suffix, commonly seen in supply chain attacks to shadow legitimate versions.",
        ))

    # Signal: release cadence spike
    version_list = sorted(releases.keys())
    if len(version_list) >= 3:
        recent = version_list[-3:]
        dates = []
        for v in recent:
            files = releases.get(v, [])
            if files and files[0].get("upload_time_iso_8601"):
                dates.append(files[0]["upload_time_iso_8601"])
        if len(dates) >= 2:
            try:
                d1 = datetime.fromisoformat(dates[-1].replace("Z", "+00:00"))
                d2 = datetime.fromisoformat(dates[-2].replace("Z", "+00:00"))
                gap_hours = abs((d1 - d2).total_seconds()) / 3600
                if gap_hours < 1:
                    signals.append(RiskSignal(
                        type="release_cadence",
                        severity=Severity.HIGH,
                        title="Rapid release cadence",
                        evidence=f"Two releases within {gap_hours:.1f} hours. Rapid releases can indicate account compromise.",
                    ))
            except (ValueError, TypeError):
                pass

    # Signal: suspicious filenames in release
    for rf in release_files:
        filename = rf.get("filename", "")
        for pattern, desc, sev in SUSPICIOUS_FILES.items():
            if pattern in filename.lower():
                signals.append(RiskSignal(
                    type="suspicious_file",
                    severity=sev,
                    title=desc,
                    evidence=f"File: {filename}",
                ))

    # Signal: homepage/repo mismatch or suspicious URLs
    homepage = info.get("home_page", "") or ""
    project_url = info.get("project_url", "") or ""
    pkg_name = info.get("name", "").lower()
    if homepage and pkg_name and pkg_name not in homepage.lower():
        signals.append(RiskSignal(
            type="metadata_mismatch",
            severity=Severity.LOW,
            title="Package name not found in homepage URL",
            evidence=f"Package: {pkg_name}, Homepage: {homepage}",
        ))

    # Signal: description is very short or empty
    description = info.get("description", "") or ""
    if len(description.strip()) < 20:
        signals.append(RiskSignal(
            type="sparse_metadata",
            severity=Severity.LOW,
            title="Very short or empty description",
            evidence=f"Description length: {len(description.strip())} chars",
        ))

    return signals


def _compute_risk_score(signals: List[RiskSignal]) -> int:
    """Compute an overall risk score (0-100) from signals."""
    score = 0
    for s in signals:
        if s.severity == Severity.CRITICAL:
            score += 40
        elif s.severity == Severity.HIGH:
            score += 25
        elif s.severity == Severity.MEDIUM:
            score += 15
        elif s.severity == Severity.LOW:
            score += 5
    return min(score, 100)


async def run_monitor() -> List[MonitoredRelease]:
    """Run a full monitoring cycle over the watchlist. Returns new releases found."""
    watchlist = load_watchlist()
    new_releases = []

    for package in watchlist:
        release = await check_package_release(package)
        if release:
            repo.add_monitored_release(release)
            new_releases.append(release)

    return new_releases
