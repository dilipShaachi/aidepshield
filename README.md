# AIDepShield V2

**Ship code, not malware.**

In March 2026, LiteLLM (95M monthly downloads) was compromised through a poisoned GitHub Action. Attackers exfiltrated PyPI credentials, published backdoored packages, and deployed a three-stage payload — credential harvesting, Kubernetes lateral movement, and a persistent systemd backdoor. Socket.dev and Snyk missed it.

AIDepShield catches it. And in V2, it catches the workflow patterns that made the attack possible in the first place.

---

## What V2 does

**1. Dependency Scanner** — checks your packages against a verified trust registry. Known compromised versions return `FAIL`. Unknown versions return `REVIEW`, not `SAFE`. When something is compromised, it tells you the nearest safe version to pin to.

**2. CI/CD Sentinel** — scans your GitHub Actions workflow files for the exact patterns that enabled the LiteLLM attack: unpinned action refs, write-all permissions, `curl | bash`, secrets on untrusted triggers, publish without provenance.

**3. PyPI Monitor** — watches 20+ AI-critical packages for suspicious new releases. Computes risk signals: post-release suffixes, rapid release cadence, suspicious files, metadata mismatches.

**4. Verified Safe Version Registry** — evidence-backed trust status per package version with API access.

---

## Quick start

### GitHub Action — scan deps AND workflows

```yaml
- name: AIDepShield V2
  uses: dilipShaachi/aidepshield-action@v2
  with:
    requirements_file: requirements.txt
    workflow_glob: .github/workflows/*.yml
    fail_on: high
    strict_unknowns: "true"
```

### curl — check a package right now

```bash
curl -X POST https://api.aidepshield.dev/scan \
  -H "Content-Type: application/json" \
  -d '{"packages": [{"name": "litellm", "version": "1.65.3-post1"}]}'
```

### Docker — code never leaves your machine

```bash
docker run -p 8080:8080 aidepshield/aidepshield:v2
```

---

## CI output

```
AIDepShield v2 — release safety sweep
-------------------------------------
Dependencies scanned: 14
Workflow files scanned: 3

  [FAIL]   litellm                   1.65.3-post1    critical
           IOC: litellm_init.pth, checkmarx.zone C2 beacon
           Fix: Pin to 1.66.0 immediately.
  [GHA002] .github/workflows/release.yml    Dangerous write-all permissions (critical)
           Fix: Set least-privilege permissions per job.
  [GHA003] .github/workflows/build.yml      Remote script execution (high)
           Fix: Download the script, verify checksum, then execute.

-------------------------------------
Verdict: FAIL
FAIL — 1 compromised dependency(s) and 2 CI/CD workflow risk(s) detected

Recommended action: Pin litellm to 1.66.0 immediately.

Build blocked. Fix the issues above before releasing.
```

---

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan` | POST | Unified scan — packages, requirements, and/or workflows |
| `/iocs` | GET | Public IOC feed — free forever |
| `/registry/{package}` | GET | All tracked versions with trust status |
| `/registry/{package}/{version}` | GET | Trust status for a specific version |
| `/monitored/releases` | GET | Recent PyPI releases with risk scores |
| `/health` | GET | Service status |

### POST /scan — request

```json
{
  "packages": [{"name": "litellm", "version": "1.65.3-post1"}],
  "requirements": "litellm==1.65.3-post1\nfastapi==0.115.0",
  "workflows": [
    {"path": ".github/workflows/release.yml", "content": "..."}
  ],
  "options": {
    "strict_unknowns": true,
    "include_recommendations": true
  }
}
```

### POST /scan — response

```json
{
  "verdict": "FAIL",
  "confidence": 0.97,
  "summary": "FAIL — 1 compromised dependency(s) detected",
  "recommendation": "Pin to 1.66.0 immediately.",
  "scanned_at": "2026-04-09T00:00:00Z",
  "dependency_results": [...],
  "workflow_results": [...],
  "packages_scanned": 2,
  "workflows_scanned": 1
}
```

---

## CI/CD Sentinel rules

| Rule | What it catches | Severity |
|------|----------------|----------|
| GHA001 | Unpinned action refs (`@main`, `@v4`) | High |
| GHA002 | `write-all` or dangerous write permissions | Critical/High |
| GHA003 | `curl \| bash` / `wget \| sh` remote script execution | High |
| GHA004 | Secrets exposed on `pull_request_target` / untrusted triggers | Critical |
| GHA005 | Package publish without provenance/attestation | High |
| GHA006 | Self-hosted runner on untrusted trigger | High |
| GHA008 | Floating Docker image tag (`:latest` or untagged) | Medium |

---

## The attack this catches

**TeamPCP / LiteLLM — March 2026**

1. Attackers rewrote git tags in `trivy-action` to point to a malicious release
2. LiteLLM's CI/CD pulled Trivy without a pinned version
3. The compromised action exfiltrated LiteLLM's `PYPI_PUBLISH` token
4. Backdoored `litellm==1.65.3-post1` and `1.65.4-post1` were published to PyPI
5. Payload: credential harvesting, K8s lateral movement, persistent systemd backdoor
6. Live for 40 minutes. 95M monthly downloads exposed.

IOCs in database: `litellm_init.pth` (malicious file), `checkmarx.zone` (C2 domain), `youtube.com` (kill switch).

**AIDepShield V2 catches this at two layers:**
- Dependency scanner flags the compromised versions
- CI/CD Sentinel flags the unpinned action ref that made the attack possible

---

## Monitored packages

AIDepShield watches these AI-critical packages for suspicious new releases:

`litellm` · `openai` · `anthropic` · `langchain` · `transformers` · `torch` · `diffusers` · `sentence-transformers` · `llama-index` · `crewai` · `autogen` · `vllm` · `fastapi` · `pydantic` · `uvicorn` · `httpx` · `tiktoken` · `tokenizers`

Add your own packages in `data/watchlist.yaml`.

---

## How it's different

| Tool | Scans | AIDepShield V2 gap it fills |
|------|-------|---------------------------|
| Snyk | Known CVEs in dependencies | Misses novel attacks, doesn't scan workflows |
| Socket.dev | Package behavior | Missed LiteLLM, no CI/CD scanning |
| MCPShield | MCP server configs | MCP-only |
| **AIDepShield V2** | Dependencies + CI/CD workflows + PyPI releases | Scans your pipeline, not just your packages |

---

## Development

```bash
# Install
pip install -r requirements.txt

# Run locally
uvicorn app.main:app --reload --port 8080

# Run tests
pytest tests/ -v
```

---

## License

MIT — use it, fork it, integrate it.
