"""
AIDepShield V2 — Data models for scan requests, responses, and internal state.
"""

from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum
from datetime import datetime


# --- Enums ---

class Verdict(str, Enum):
    SAFE = "SAFE"
    FAIL = "FAIL"
    REVIEW = "REVIEW"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


class VersionStatus(str, Enum):
    VERIFIED_SAFE = "verified_safe"
    COMPROMISED = "compromised"
    UNDER_REVIEW = "under_review"
    UNKNOWN = "unknown"
    DEPRECATED_RISKY = "deprecated_risky"


# --- Scan Request Models ---

class PackageInput(BaseModel):
    name: str
    version: Optional[str] = None


class WorkflowInput(BaseModel):
    path: str
    content: str


class ScanOptions(BaseModel):
    include_recommendations: bool = True
    strict_unknowns: bool = True


class ScanRequest(BaseModel):
    packages: Optional[List[PackageInput]] = None
    requirements: Optional[str] = None
    workflows: Optional[List[WorkflowInput]] = None
    options: Optional[ScanOptions] = None


# --- Scan Result Models ---

class DependencyResult(BaseModel):
    package: str
    version: Optional[str]
    status: VersionStatus
    verdict: Verdict
    severity: Severity
    ioc: Optional[str] = None
    recommendation: Optional[str] = None
    nearest_safe_version: Optional[str] = None
    incident_id: Optional[str] = None
    report_url: Optional[str] = None


class WorkflowFinding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    file: str
    job: Optional[str] = None
    line: Optional[int] = None
    evidence: str
    why_it_matters: str
    recommended_fix: str


class ScanResponse(BaseModel):
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    summary: str
    recommendation: Optional[str] = None
    scanned_at: str
    dependency_results: List[DependencyResult] = []
    workflow_results: List[WorkflowFinding] = []
    packages_scanned: int = 0
    workflows_scanned: int = 0


# --- Registry Models ---

class RegistryEntry(BaseModel):
    package: str
    version: str
    status: VersionStatus
    risk_score: Optional[int] = None  # 0-100
    first_seen_at: Optional[str] = None
    last_verified_at: Optional[str] = None
    verification_methods: List[str] = []
    evidence_links: List[str] = []
    notes: Optional[str] = None
    incident_id: Optional[str] = None
    nearest_safe_version: Optional[str] = None


class PackageRegistry(BaseModel):
    package: str
    versions: List[RegistryEntry] = []


# --- PyPI Monitor Models ---

class RiskSignal(BaseModel):
    type: str
    severity: Severity
    title: str
    evidence: str


class MonitoredRelease(BaseModel):
    package: str
    version: str
    published_at: Optional[str] = None
    source_url: Optional[str] = None
    risk_score: int = 0  # 0-100
    verdict: Verdict = Verdict.UNKNOWN
    signals: List[RiskSignal] = []
    notes: Optional[str] = None
    checked_at: str = ""


# --- IOC Models ---

class Incident(BaseModel):
    id: str
    name: str
    date: str
    severity: str
    attack_vector: str
    c2_domains: List[str] = []
    kill_switch_domains: List[str] = []
    malicious_files: List[str] = []
    affected_packages: List[dict] = []
    summary: Optional[str] = None
    report_url: Optional[str] = None


class IOCFeed(BaseModel):
    version: str
    updated: str
    source: str
    incidents: List[dict]
    safe_version_registry: dict
    ioc_signatures: List[dict]
    monitored_releases: List[MonitoredRelease] = []
