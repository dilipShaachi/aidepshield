"""
AIDepShield V2 — Ship code, not malware.
Real-time supply chain security for AI Python dependencies.

V2 adds:
- CI/CD Sentinel (workflow scanning)
- PyPI monitoring for suspicious releases
- Verified Safe Version Registry
- Unified SAFE / FAIL / REVIEW verdicts
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.api.routes_scan import router as scan_router
from app.api.routes_registry import router as registry_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    # Startup: repository is loaded on import
    yield
    # Shutdown: nothing to clean up for now


app = FastAPI(
    title="AIDepShield",
    description="Ship code, not malware. Supply chain security for AI dependencies — IOC scanning, CI/CD sentinel, and PyPI monitoring.",
    version="2.0.0",
    lifespan=lifespan,
)

app.include_router(scan_router)
app.include_router(registry_router)
