"""
AIDepShield V2 — Scan API routes.
"""

from fastapi import APIRouter, HTTPException

from app.data.models import ScanRequest, ScanResponse
from app.services.risk_engine import run_scan

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest):
    """
    Unified scan endpoint.
    Accepts packages, requirements text, and/or workflow YAML files.
    Returns SAFE / FAIL / REVIEW with per-item results and recommendations.
    """
    has_input = (
        request.packages
        or request.requirements
        or request.workflows
    )
    if not has_input:
        raise HTTPException(
            status_code=400,
            detail="Provide at least one of: 'packages', 'requirements', or 'workflows'",
        )

    return run_scan(request)
