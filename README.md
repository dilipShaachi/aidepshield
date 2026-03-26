Ship zero-day free releases — add this Action, push, and forget.

---

# AIDepShield

**Ship code, not malware.**

Real-time supply chain IOC scanning for AI Python libraries. LiteLLM (97M downloads) was compromised via GitHub Actions. Socket.dev and Snyk missed it. AIDepShield didn't.

---

## 30-second setup

**GitHub Action** — drop into any repo:

```yaml
- name: Scan AI dependencies
  uses: aidepshield/aidepshield@v1
  with:
    requirements_file: requirements.txt
```

**curl** — check any package right now:

```bash
curl -X POST https://api.aidepshield.dev/scan \
  -H "Content-Type: application/json" \
  -d '{"packages": [{"name": "litellm", "version": "1.65.3-post1"}]}'
```

**Docker** — run locally, code never leaves your machine:

```bash
docker run -p 8080:8080 aidepshield/aidepshield:v1
curl -X POST http://localhost:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"requirements": "litellm==1.65.3-post1\ntorch==2.2.0"}'
```

---

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan`  | POST   | Scan packages or requirements.txt |
| `/iocs`  | GET    | Full public IOC feed (free forever) |
| `/health`| GET    | Service status + IOC count |

### /scan request
```json
{"packages": [{"name": "litellm", "version": "1.65.3-post1"}]}
```

### /scan response
```json
{
  "safe": false,
  "summary": "🚨 FAIL — 1 COMPROMISED package(s) detected",
  "results": [{
    "package": "litellm",
    "version": "1.65.3-post1",
    "status": "COMPROMISED",
    "severity": "critical",
    "ioc": "litellm_init.pth, checkmarx.zone C2 beacon",
    "report_url": "https://aidepshield.dev/report/AIDS-2026-001"
  }]
}
```

---

## Free IOC Feed

```bash
curl https://api.aidepshield.dev/iocs
```

Community-sourced. Updated as new attacks are confirmed. Free forever.

---

## The attack this catches

**TeamPCP / LiteLLM — March 2026**
- 97M downloads affected
- Attack vector: GitHub Actions CI/CD compromise (NOT a PyPI account hack)
- Malicious file: `litellm_init.pth`
- C2: `checkmarx.zone`
- Credential theft from developer machines
- Missed by: Socket.dev, Snyk

---

## License

MIT — use it, fork it, integrate it.
