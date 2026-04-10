"""
Tests for AIDepShield V2 — Package Scanner.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.data.models import PackageInput, Verdict, VersionStatus, Severity
from app.services.package_scanner import scan_package, scan_packages
from app.services.requirements_parser import parse_requirements


class TestPackageScanner:
    """Test dependency trust verdicts."""

    def test_compromised_version_returns_fail(self):
        """Known compromised version must return FAIL."""
        result = scan_package(PackageInput(name="litellm", version="1.65.3-post1"))
        assert result.verdict == Verdict.FAIL
        assert result.status == VersionStatus.COMPROMISED
        assert result.severity == Severity.CRITICAL
        assert result.incident_id == "AIDS-2026-001"
        assert result.nearest_safe_version is not None

    def test_compromised_version_2_returns_fail(self):
        """Second compromised version also returns FAIL."""
        result = scan_package(PackageInput(name="litellm", version="1.65.4-post1"))
        assert result.verdict == Verdict.FAIL
        assert result.status == VersionStatus.COMPROMISED

    def test_safe_version_returns_safe(self):
        """Known safe version must return SAFE."""
        result = scan_package(PackageInput(name="litellm", version="1.65.5"))
        assert result.verdict == Verdict.SAFE
        assert result.status == VersionStatus.VERIFIED_SAFE
        assert result.severity == Severity.NONE

    def test_unknown_tracked_version_returns_review(self):
        """Unclassified version of a tracked package must return REVIEW, not SAFE."""
        result = scan_package(PackageInput(name="litellm", version="1.65.4-post2"))
        assert result.verdict == Verdict.REVIEW
        assert result.status == VersionStatus.UNKNOWN
        assert result.severity == Severity.MEDIUM

    def test_unknown_package_strict_returns_review(self):
        """Unknown package in strict mode must return REVIEW."""
        result = scan_package(
            PackageInput(name="some-random-package", version="1.0.0"),
            strict_unknowns=True,
        )
        assert result.verdict == Verdict.REVIEW
        assert result.severity == Severity.LOW

    def test_unknown_package_non_strict_returns_safe(self):
        """Unknown package in non-strict mode returns SAFE."""
        result = scan_package(
            PackageInput(name="some-random-package", version="1.0.0"),
            strict_unknowns=False,
        )
        assert result.verdict == Verdict.SAFE

    def test_compromised_has_recommendation(self):
        """Compromised result must include a recommendation."""
        result = scan_package(PackageInput(name="litellm", version="1.65.3-post1"))
        assert result.recommendation is not None
        assert "Pin to" in result.recommendation  # should recommend a safe version

    def test_case_insensitive_package_name(self):
        """Package name lookup should be case insensitive."""
        result = scan_package(PackageInput(name="LiteLLM", version="1.65.3-post1"))
        assert result.verdict == Verdict.FAIL

    def test_scan_multiple_packages(self):
        """Batch scan returns correct results for each package."""
        packages = [
            PackageInput(name="litellm", version="1.65.3-post1"),
            PackageInput(name="litellm", version="1.65.5"),
            PackageInput(name="fastapi", version="0.115.0"),
        ]
        results = scan_packages(packages, strict_unknowns=True)
        assert len(results) == 3
        assert results[0].verdict == Verdict.FAIL
        assert results[1].verdict == Verdict.SAFE
        assert results[2].verdict == Verdict.REVIEW  # untracked, strict mode


class TestRequirementsParser:
    """Test requirements.txt parsing."""

    def test_basic_pinned(self):
        packages = parse_requirements("litellm==1.65.5\nfastapi==0.115.0")
        assert len(packages) == 2
        assert packages[0].name == "litellm"
        assert packages[0].version == "1.65.5"

    def test_various_specifiers(self):
        packages = parse_requirements("foo>=1.0\nbar<=2.0\nbaz~=3.0\nqux!=4.0")
        assert len(packages) == 4
        assert packages[0].version == "1.0"

    def test_extras_stripped(self):
        packages = parse_requirements("uvicorn[standard]==0.30.6")
        assert packages[0].name == "uvicorn"
        assert packages[0].version == "0.30.6"

    def test_comments_and_blanks_ignored(self):
        text = "# comment\n\nlitellm==1.0\n  # another\n"
        packages = parse_requirements(text)
        assert len(packages) == 1

    def test_no_version(self):
        packages = parse_requirements("requests")
        assert packages[0].name == "requests"
        assert packages[0].version is None

    def test_flags_ignored(self):
        packages = parse_requirements("-r other.txt\nlitellm==1.0")
        assert len(packages) == 1
        assert packages[0].name == "litellm"
