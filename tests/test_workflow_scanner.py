"""
Tests for AIDepShield V2 — CI/CD Workflow Sentinel.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.data.models import WorkflowInput, Severity
from app.services.workflow_scanner import scan_workflow


def _make_workflow(content: str, path: str = ".github/workflows/test.yml") -> WorkflowInput:
    return WorkflowInput(path=path, content=content)


class TestGHA001UnpinnedActions:
    """GHA001: Unpinned action references."""

    def test_floating_tag_flagged(self):
        wf = _make_workflow("""
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some/action@main
""")
        findings = scan_workflow(wf)
        gha001 = [f for f in findings if f.rule_id == "GHA001"]
        assert len(gha001) == 2  # v4 and main are both unpinned
        assert all(f.severity in (Severity.HIGH,) for f in gha001)

    def test_sha_pinned_not_flagged(self):
        wf = _make_workflow("""
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
""")
        findings = scan_workflow(wf)
        gha001 = [f for f in findings if f.rule_id == "GHA001"]
        assert len(gha001) == 0


class TestGHA002DangerousPermissions:
    """GHA002: Dangerous write permissions."""

    def test_write_all_flagged(self):
        wf = _make_workflow("""
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
""")
        findings = scan_workflow(wf)
        gha002 = [f for f in findings if f.rule_id == "GHA002"]
        assert len(gha002) >= 1
        assert any(f.severity == Severity.CRITICAL for f in gha002)

    def test_specific_write_perms_flagged(self):
        wf = _make_workflow("""
on: push
permissions:
  contents: write
  actions: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
""")
        findings = scan_workflow(wf)
        gha002 = [f for f in findings if f.rule_id == "GHA002"]
        assert len(gha002) == 2  # contents: write and actions: write

    def test_read_perms_not_flagged(self):
        wf = _make_workflow("""
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
""")
        findings = scan_workflow(wf)
        gha002 = [f for f in findings if f.rule_id == "GHA002"]
        assert len(gha002) == 0


class TestGHA003RemoteScripts:
    """GHA003: Remote script piping to shell."""

    def test_curl_pipe_bash_flagged(self):
        wf = _make_workflow("""
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://example.com/install.sh | bash
""")
        findings = scan_workflow(wf)
        gha003 = [f for f in findings if f.rule_id == "GHA003"]
        assert len(gha003) == 1
        assert gha003[0].severity == Severity.HIGH

    def test_wget_pipe_sh_flagged(self):
        wf = _make_workflow("""
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: wget https://example.com/install.sh | sh
""")
        findings = scan_workflow(wf)
        gha003 = [f for f in findings if f.rule_id == "GHA003"]
        assert len(gha003) == 1

    def test_safe_curl_not_flagged(self):
        wf = _make_workflow("""
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -o install.sh https://example.com/install.sh
""")
        findings = scan_workflow(wf)
        gha003 = [f for f in findings if f.rule_id == "GHA003"]
        assert len(gha003) == 0


class TestGHA004SecretsExposure:
    """GHA004: Secrets exposed to untrusted triggers."""

    def test_secrets_on_pr_target_flagged(self):
        wf = _make_workflow("""
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.DEPLOY_KEY }}
""")
        findings = scan_workflow(wf)
        gha004 = [f for f in findings if f.rule_id == "GHA004"]
        assert len(gha004) >= 1
        assert gha004[0].severity == Severity.CRITICAL

    def test_secrets_on_push_not_flagged(self):
        wf = _make_workflow("""
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.DEPLOY_KEY }}
""")
        findings = scan_workflow(wf)
        gha004 = [f for f in findings if f.rule_id == "GHA004"]
        assert len(gha004) == 0


class TestGHA005PublishWithoutProvenance:
    """GHA005: Package publish without provenance gate."""

    def test_publish_without_attestation_flagged(self):
        wf = _make_workflow("""
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: pip install twine
      - run: twine upload dist/*
""")
        findings = scan_workflow(wf)
        gha005 = [f for f in findings if f.rule_id == "GHA005"]
        assert len(gha005) == 1

    def test_publish_with_provenance_not_flagged(self):
        wf = _make_workflow("""
on: push
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: sigstore/cosign-installer@v3
      - run: cosign sign-blob dist/*.tar.gz
      - run: twine upload dist/*
""")
        findings = scan_workflow(wf)
        gha005 = [f for f in findings if f.rule_id == "GHA005"]
        assert len(gha005) == 0


class TestGHA006SelfHostedRunner:
    """GHA006: Self-hosted runner on untrusted trigger."""

    def test_self_hosted_on_pr_target_flagged(self):
        wf = _make_workflow("""
on: pull_request_target
jobs:
  build:
    runs-on: self-hosted
    steps:
      - run: echo hello
""")
        findings = scan_workflow(wf)
        gha006 = [f for f in findings if f.rule_id == "GHA006"]
        assert len(gha006) == 1


class TestComplexWorkflow:
    """Test from the V2 build brief — should trigger multiple rules."""

    def test_multi_rule_workflow(self):
        wf = _make_workflow("""
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://example.com/install.sh | bash
      - uses: actions/checkout@v4
      - uses: some/action@main
""")
        findings = scan_workflow(wf)
        rule_ids = {f.rule_id for f in findings}
        assert "GHA002" in rule_ids  # write-all
        assert "GHA003" in rule_ids  # curl|bash
        assert "GHA001" in rule_ids  # unpinned actions

    def test_invalid_yaml_handled(self):
        wf = _make_workflow("{{invalid yaml::: [}")
        findings = scan_workflow(wf)
        assert len(findings) == 1
        assert findings[0].rule_id == "GHA000"
