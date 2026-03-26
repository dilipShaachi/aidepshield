"""
AIDepShield v1 — Ship code, not malware.
Real-time IOC API for AI Python library supply chain security.
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(
    title="AIDepShield",
    description="Ship code, not malware. Real-time IOC scanning for AI Python libraries.",
    version="1.0.0",
)

# Load IOC database
IOC_DB_PATH = Path(__file__).parent / "iocs.json"
with open(IOC_DB_PATH) as f:
    IOC_DB = json.load(f)

# Build fast lookup indexes
COMPROMISED_VERSIONS: dict = {}
SAFE_VERSIONS: dict = {}
for pkg, data in IOC_DB.get("safe_version_registry", {}).items():
    COMPROMISED_VERSIONS[pkg.lower()] = data.get("compromised", [])
    SAFE_VERSIONS[pkg.lower()] = data.get("verified_safe", [])


# --- Models ---

class PackageInput(BaseModel):
    name: str
    version: Optional[str] = None


class ScanRequest(BaseModel):
    packages: Optional[List[PackageInput]] = None
    requirements: Optional[str] = None  # raw requirements.txt contents


class ScanResult(BaseModel):
    package: str
    version: Optional[str]
    status: str  # SAFE | COMPROMISED | UNKNOWN
    severity: Optional[str]  # critical | high | medium | low | none
    ioc: Optional[str]
    report_url: Optional[str]


class ScanResponse(BaseModel):
    status: str  # SAFE | FAIL
    safe: bool
    scanned_at: str
    results: List[ScanResult]
    summary: str


# --- Helpers ---

def parse_requirements(req_text: str) -> List[PackageInput]:
    packages = []
    for line in req_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Handle ==, >=, <=, ~=
        for sep in ["==", ">=", "<=", "~=", "!="]:
            if sep in line:
                name, version = line.split(sep, 1)
                packages.append(PackageInput(name=name.strip(), version=version.strip()))
                break
        else:
            packages.append(PackageInput(name=line.strip(), version=None))
    return packages


def check_package(pkg: PackageInput) -> ScanResult:
    name_lower = pkg.name.lower()
    version = pkg.version

    # Check against compromised versions
    if name_lower in COMPROMISED_VERSIONS:
        if version and version in COMPROMISED_VERSIONS[name_lower]:
            # Find the incident for details
            for incident in IOC_DB.get("incidents", []):
                for affected in incident.get("affected_packages", []):
                    if affected["name"].lower() == name_lower:
                        return ScanResult(
                            package=pkg.name,
                            version=version,
                            status="COMPROMISED",
                            severity="critical",
                            ioc=", ".join(affected.get("indicators", [])),
                            report_url=f"https://aidepshield.dev/report/{incident['id']}",
                        )

        # Known safe version
        if version and version in SAFE_VERSIONS.get(name_lower, []):
            return ScanResult(
                package=pkg.name,
                version=version,
                status="SAFE",
                severity="none",
                ioc=None,
                report_url=None,
            )

        # Version not in either list — warn
        if version:
            return ScanResult(
                package=pkg.name,
                version=version,
                status="UNKNOWN",
                severity="low",
                ioc="Version not in verified safe registry — verify manually",
                report_url="https://aidepshield.dev/verify",
            )

    # Not in our database — assume safe but unverified
    return ScanResult(
        package=pkg.name,
        version=version,
        status="SAFE",
        severity="none",
        ioc=None,
        report_url=None,
    )


# --- Routes ---

@app.get("/health")
def health():
    ioc_count = sum(
        len(inc.get("affected_packages", []))
        for inc in IOC_DB.get("incidents", [])
    )
    return {
        "status": "ok",
        "version": "1.0.0",
        "ioc_count": ioc_count,
        "db_updated": IOC_DB.get("updated"),
    }


@app.get("/iocs")
def get_iocs():
    """Public IOC feed — free forever. Use this to protect your stack."""
    return IOC_DB


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    packages: List[PackageInput] = []

    if request.requirements:
        packages = parse_requirements(request.requirements)
    elif request.packages:
        packages = request.packages
    else:
        raise HTTPException(status_code=400, detail="Provide 'packages' or 'requirements'")

    if not packages:
        raise HTTPException(status_code=400, detail="No packages found to scan")

    results = [check_package(p) for p in packages]
    compromised = [r for r in results if r.status == "COMPROMISED"]
    safe = len(compromised) == 0

    if compromised:
        summary = f"🚨 FAIL — {len(compromised)} COMPROMISED package(s) detected"
    else:
        summary = f"✅ ALL CLEAR — {len(results)} package(s) scanned, stack is safe"

    return ScanResponse(
        status="SAFE" if safe else "FAIL",
        safe=safe,
        scanned_at=datetime.utcnow().isoformat() + "Z",
        results=results,
        summary=summary,
    )
