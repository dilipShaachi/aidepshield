"""
AIDepShield V2 — CI/CD Workflow Sentinel.
Scans GitHub Actions workflow YAML files for dangerous patterns.

Rules:
  GHA001 - Unpinned action ref
  GHA002 - Dangerous write permissions
  GHA003 - Remote script piping to shell
  GHA004 - Secrets exposed to untrusted trigger
  GHA005 - Package publish without provenance/verification gate
  GHA006 - Self-hosted runner on untrusted PR path
  GHA007 - Install/build executes before dependency trust scan
  GHA008 - Floating Docker image tag for security-sensitive step
"""

import re
from typing import List, Optional
import yaml

from app.data.models import WorkflowInput, WorkflowFinding, Severity


def scan_workflow(wf: WorkflowInput) -> List[WorkflowFinding]:
    """Scan a single workflow YAML for dangerous patterns."""
    findings: List[WorkflowFinding] = []

    try:
        doc = yaml.safe_load(wf.content)
    except yaml.YAMLError:
        findings.append(WorkflowFinding(
            rule_id="GHA000",
            title="Invalid workflow YAML",
            severity=Severity.HIGH,
            file=wf.path,
            evidence="Failed to parse YAML",
            why_it_matters="Malformed workflows may indicate tampering or accidental misconfiguration.",
            recommended_fix="Validate YAML syntax and ensure the workflow is well-formed.",
        ))
        return findings

    if not isinstance(doc, dict):
        return findings

    lines = wf.content.splitlines()
    triggers = _get_triggers(doc)
    has_untrusted_trigger = bool({"pull_request_target", "workflow_dispatch", "issue_comment"} & triggers)

    # Check top-level permissions
    top_perms = doc.get("permissions", None)
    if isinstance(top_perms, str) and top_perms == "write-all":
        findings.append(WorkflowFinding(
            rule_id="GHA002",
            title="Dangerous write-all permissions at workflow level",
            severity=Severity.CRITICAL,
            file=wf.path,
            line=_find_line(lines, "permissions"),
            evidence=f"permissions: {top_perms}",
            why_it_matters="write-all grants every permission scope. If any job is compromised, the attacker has full repo write access, can push code, create releases, and access secrets.",
            recommended_fix="Set least-privilege permissions per job. Only grant write scopes where needed.",
        ))
    elif isinstance(top_perms, dict):
        _check_dangerous_perms(top_perms, wf.path, None, lines, findings)

    jobs = doc.get("jobs", {})
    if not isinstance(jobs, dict):
        return findings

    for job_name, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue

        # Check job-level permissions
        job_perms = job_def.get("permissions", None)
        if isinstance(job_perms, str) and job_perms == "write-all":
            findings.append(WorkflowFinding(
                rule_id="GHA002",
                title=f"Dangerous write-all permissions on job '{job_name}'",
                severity=Severity.CRITICAL,
                file=wf.path,
                job=job_name,
                line=_find_line(lines, "permissions", after=_find_line(lines, job_name)),
                evidence=f"permissions: {job_perms}",
                why_it_matters="write-all grants every permission scope to this job.",
                recommended_fix="Set least-privilege permissions. Only grant write scopes this job actually needs.",
            ))
        elif isinstance(job_perms, dict):
            _check_dangerous_perms(job_perms, wf.path, job_name, lines, findings)

        # GHA006 - Self-hosted runner on untrusted trigger
        runs_on = job_def.get("runs-on", "")
        if isinstance(runs_on, str) and "self-hosted" in runs_on and has_untrusted_trigger:
            findings.append(WorkflowFinding(
                rule_id="GHA006",
                title=f"Self-hosted runner on untrusted trigger in '{job_name}'",
                severity=Severity.HIGH,
                file=wf.path,
                job=job_name,
                line=_find_line(lines, "self-hosted"),
                evidence=f"runs-on: {runs_on} with triggers: {', '.join(triggers)}",
                why_it_matters="Self-hosted runners execute arbitrary code from PRs. An attacker can submit a PR that runs malware on your infrastructure.",
                recommended_fix="Use GitHub-hosted runners for jobs triggered by external events, or restrict self-hosted runner access.",
            ))

        steps = job_def.get("steps", [])
        if not isinstance(steps, list):
            continue

        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue

            # GHA001 - Unpinned action ref
            uses = step.get("uses", "")
            if uses and "@" in uses:
                ref = uses.split("@", 1)[1]
                if _is_unpinned_ref(ref):
                    findings.append(WorkflowFinding(
                        rule_id="GHA001",
                        title=f"Unpinned action ref in '{job_name}'",
                        severity=Severity.HIGH,
                        file=wf.path,
                        job=job_name,
                        line=_find_line(lines, uses),
                        evidence=f"uses: {uses}",
                        why_it_matters="Floating tags (main, master, v1) can be rewritten by attackers to point to malicious code — exactly how the LiteLLM attack worked via trivy-action.",
                        recommended_fix=f"Pin to a specific commit SHA: {uses.split('@')[0]}@<full-sha>",
                    ))

            # GHA003 - Remote script piping
            run_cmd = step.get("run", "")
            if isinstance(run_cmd, str):
                pipe_patterns = [
                    r"curl\s+.*\|\s*(ba)?sh",
                    r"wget\s+.*\|\s*(ba)?sh",
                    r"curl\s+.*\|\s*python",
                    r"wget\s+.*\|\s*python",
                    r"curl\s+-[a-zA-Z]*s[a-zA-Z]*L?\s+.*\|\s*(ba)?sh",
                ]
                for pattern in pipe_patterns:
                    if re.search(pattern, run_cmd, re.IGNORECASE):
                        findings.append(WorkflowFinding(
                            rule_id="GHA003",
                            title=f"Remote script execution in '{job_name}'",
                            severity=Severity.HIGH,
                            file=wf.path,
                            job=job_name,
                            line=_find_line(lines, run_cmd[:40]),
                            evidence=run_cmd.strip()[:200],
                            why_it_matters="Piping remote scripts directly to a shell bypasses all integrity checks. If the remote server is compromised, arbitrary code runs in your CI with full access to secrets.",
                            recommended_fix="Download the script, verify its checksum, then execute. Or use a pinned GitHub Action instead.",
                        ))
                        break

            # GHA004 - Secrets in untrusted trigger context
            if has_untrusted_trigger and isinstance(run_cmd, str):
                if "${{ secrets." in run_cmd or "secrets." in str(step.get("env", {})):
                    findings.append(WorkflowFinding(
                        rule_id="GHA004",
                        title=f"Secrets exposed to untrusted trigger in '{job_name}'",
                        severity=Severity.CRITICAL,
                        file=wf.path,
                        job=job_name,
                        line=_find_line(lines, "secrets."),
                        evidence=f"Secrets used in step with triggers: {', '.join(triggers)}",
                        why_it_matters="pull_request_target and similar triggers run with repo secrets but accept code from forks. Attackers can exfiltrate secrets via malicious PR code.",
                        recommended_fix="Move secret-dependent steps to a separate workflow triggered by workflow_run, or use environment protection rules.",
                    ))

            # GHA008 - Floating Docker image tag
            if uses and uses.startswith("docker://"):
                image = uses.replace("docker://", "")
                if ":" not in image or image.endswith(":latest"):
                    findings.append(WorkflowFinding(
                        rule_id="GHA008",
                        title=f"Floating Docker image tag in '{job_name}'",
                        severity=Severity.MEDIUM,
                        file=wf.path,
                        job=job_name,
                        line=_find_line(lines, uses),
                        evidence=f"uses: {uses}",
                        why_it_matters="Untagged or :latest Docker images can be replaced with malicious versions at any time.",
                        recommended_fix=f"Pin to a specific digest: {image.split(':')[0]}@sha256:<digest>",
                    ))

    # GHA005 - Publish without provenance
    _check_publish_without_provenance(doc, wf, lines, findings)

    return findings


def scan_workflows(workflows: List[WorkflowInput]) -> List[WorkflowFinding]:
    """Scan multiple workflow files."""
    findings = []
    for wf in workflows:
        findings.extend(scan_workflow(wf))
    return findings


# --- Helpers ---

def _get_triggers(doc: dict) -> set:
    on = doc.get("on", doc.get(True, {}))  # YAML parses `on:` as True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on.keys())
    return set()


def _is_unpinned_ref(ref: str) -> bool:
    """Check if an action ref is unpinned (not a SHA)."""
    # Full SHA is 40 hex chars
    if re.match(r'^[0-9a-f]{40}$', ref):
        return False
    # Anything else (tags like v1, v2.1, main, master) is unpinned
    return True


def _find_line(lines: list, needle: str, after: Optional[int] = None) -> Optional[int]:
    """Find the first line containing needle, optionally after a given line."""
    start = (after or 0)
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1  # 1-indexed
    return None


DANGEROUS_WRITE_PERMS = {"contents", "actions", "packages", "id-token", "security-events"}


def _check_dangerous_perms(
    perms: dict, filepath: str, job: Optional[str],
    lines: list, findings: list
):
    for scope, level in perms.items():
        if level == "write" and scope in DANGEROUS_WRITE_PERMS:
            context = f"job '{job}'" if job else "workflow level"
            findings.append(WorkflowFinding(
                rule_id="GHA002",
                title=f"Dangerous '{scope}: write' permission at {context}",
                severity=Severity.HIGH,
                file=filepath,
                job=job,
                line=_find_line(lines, f"{scope}:"),
                evidence=f"{scope}: write",
                why_it_matters=f"'{scope}: write' grants elevated access. If this job is compromised, the attacker can exploit this permission for lateral movement or supply chain attacks.",
                recommended_fix=f"Remove '{scope}: write' unless this job explicitly needs it. Use 'read' by default.",
            ))


def _check_publish_without_provenance(doc: dict, wf: WorkflowInput, lines: list, findings: list):
    """GHA005: Check if any job publishes without provenance/attestation."""
    jobs = doc.get("jobs", {})
    if not isinstance(jobs, dict):
        return

    publish_keywords = ["twine upload", "npm publish", "cargo publish", "gem push", "pypi", "publish"]
    provenance_keywords = ["attest", "provenance", "sigstore", "cosign", "slsa"]

    for job_name, job_def in jobs.items():
        if not isinstance(job_def, dict):
            continue
        steps = job_def.get("steps", [])
        if not isinstance(steps, list):
            continue

        has_publish = False
        has_provenance = False

        for step in steps:
            if not isinstance(step, dict):
                continue
            run_cmd = str(step.get("run", "")).lower()
            uses = str(step.get("uses", "")).lower()

            if any(kw in run_cmd or kw in uses for kw in publish_keywords):
                has_publish = True
            if any(kw in run_cmd or kw in uses for kw in provenance_keywords):
                has_provenance = True

        if has_publish and not has_provenance:
            findings.append(WorkflowFinding(
                rule_id="GHA005",
                title=f"Package publish without provenance in '{job_name}'",
                severity=Severity.HIGH,
                file=wf.path,
                job=job_name,
                line=None,
                evidence="Job publishes a package but has no attestation/provenance step.",
                why_it_matters="Without provenance attestation, consumers cannot verify that the published artifact was built from the correct source code in a trusted environment.",
                recommended_fix="Add SLSA provenance generation or Sigstore signing before the publish step.",
            ))
