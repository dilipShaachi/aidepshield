"""
Tests for AIDepShield V2 — Risk Engine (unified scan).
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.data.models import (
    ScanRequest, ScanOptions, PackageInput, WorkflowInput, Verdict
)
from app.services.risk_engine import run_scan


class TestRiskEngine:
    """Test unified scan verdict computation."""

    def test_compromised_dep_returns_fail(self):
        request = ScanRequest(
            packages=[PackageInput(name="litellm", version="1.65.3-post1")]
        )
        result = run_scan(request)
        assert result.verdict == Verdict.FAIL
        assert result.packages_scanned == 1
        assert "compromised" in result.summary.lower()

    def test_safe_dep_returns_safe(self):
        request = ScanRequest(
            packages=[PackageInput(name="litellm", version="1.65.5")],
            options=ScanOptions(strict_unknowns=False),
        )
        result = run_scan(request)
        assert result.verdict == Verdict.SAFE

    def test_dangerous_workflow_returns_review_or_fail(self):
        request = ScanRequest(
            workflows=[WorkflowInput(
                path=".github/workflows/release.yml",
                content="""
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://example.com/install.sh | bash
"""
            )]
        )
        result = run_scan(request)
        # write-all is CRITICAL => should FAIL
        assert result.verdict in (Verdict.FAIL, Verdict.REVIEW)
        assert result.workflows_scanned == 1
        assert len(result.workflow_results) >= 2

    def test_combined_scan(self):
        request = ScanRequest(
            packages=[
                PackageInput(name="litellm", version="1.65.3-post1"),
                PackageInput(name="litellm", version="1.65.5"),
            ],
            workflows=[WorkflowInput(
                path=".github/workflows/build.yml",
                content="""
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
            )],
        )
        result = run_scan(request)
        assert result.verdict == Verdict.FAIL  # compromised dep
        assert result.packages_scanned == 2
        assert result.workflows_scanned == 1

    def test_requirements_text_parsed(self):
        request = ScanRequest(
            requirements="litellm==1.65.5\nfastapi==0.115.0",
            options=ScanOptions(strict_unknowns=False),
        )
        result = run_scan(request)
        assert result.packages_scanned == 2

    def test_strict_unknowns_triggers_review(self):
        request = ScanRequest(
            packages=[PackageInput(name="random-pkg", version="1.0.0")],
            options=ScanOptions(strict_unknowns=True),
        )
        result = run_scan(request)
        assert result.verdict == Verdict.REVIEW

    def test_recommendation_present_on_fail(self):
        request = ScanRequest(
            packages=[PackageInput(name="litellm", version="1.65.3-post1")]
        )
        result = run_scan(request)
        assert result.recommendation is not None
