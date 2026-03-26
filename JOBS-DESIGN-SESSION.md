# AIDepShield — Jobs vs Jobs Design Session
**Date:** March 25, 2026
**Participants:** Vekata (Jobs) + o3 (Jobs)
**Topic:** V1 product definition

---

## Round 1 — What must v1 nail?

**Vekata (Jobs):** We have 48 hours. LiteLLM attack is today's news. Socket.dev and Snyk both missed it. What's the ONE thing v1 must nail so developers never leave?

**o3 (Jobs):** Trust. A binary answer at the speed of thought. SAFE or COMPROMISED. If we're ever wrong — even once — we're just another noisy security toy ripped out on Monday morning. Every response must be authoritative, real-time, cryptographically attestable. One-liner integration. The simpler the call, the more ubiquitous the habit.

---

## Round 2 — The feeling

**Vekata (Jobs):** You're thinking like an engineer. 50ms SLA, cryptographic attestation — that's infrastructure porn. What does the developer FEEL the first time they use it?

**o3 (Jobs):** They hit enter. Half-a-breath later the terminal flashes: SAFE. Their shoulders drop. Heartbeat steadies.

- **Relief** — the wolf is off their porch.
- **Power** — one line of YAML just out-gunned an entire threat feed.
- **Control** — the breach headline will happen to someone else.
- **Quiet pride** — they'll brag in Slack, but right now it's a private grin.

Same jolt as watching your code compile clean after an all-night sprint. Visceral, addictive, unforgettable.

---

## Round 3 — Terminal output & landing page copy

**Vekata (Jobs):** Design the actual terminal output. And the ONE landing page line.

**o3 (Jobs):**

```
AIDepShield v1  – instant IOC sweep
──────────────────────────────────────────────────────────────────
Scanning 17 Python packages …

  ✓  torch               2.2.0     SAFE
  ✗  pillow              10.0.1    COMPROMISED   CVE-2025-16342
  ✓  numpy               1.26.2    SAFE

──────────────────────────────────────────────────────────────────
FAIL — MALICIOUS CODE DETECTED            ⏱ 1.6 s
Auto-quarantined pillow 10.0.1.  Read more → https://aidepshield.dev/report/ABC123
```

**Landing page:** "Ship code, not malware."

---

## Round 4 — CLI or API first?

**Vekata (Jobs):** 48 hours, one engineer. CLI or API — pick one. The other waits.

**o3 (Jobs):** API. Full stop.

1. Core value over cosmetics — the magic is the intelligence, not the black screen.
2. Zero-friction adoption — `curl | jq` is universal. Every CI system on earth hits it in 5 minutes.
3. 48-hour reality check — a rushed CLI is an apology. A pristine API can be perfect in 2 days.
4. Let the community hack wrappers. Steal the best ideas. Ship the official CLI with taste for v2.
5. The CLI becomes v2's headline instead of v1's apology.

---

## Round 5 — Final v1 Spec (NON-NEGOTIABLE)

**Vekata (Jobs):** 48 hours, one engineer. ONLY three things. What ships?

**o3 (Jobs):**

### 1. `/scan` API
- One POST endpoint
- Input: package name + version (or requirements.txt / Git diff)
- Output: deterministic JSON `{file, line, issue, severity}`
- Nothing else — no dashboards, no auth complexity, no patch suggestions

### 2. GitHub Action drop-in
- 10-line YAML snippet that calls `/scan`
- Fails build if severity ≥ "high"
- Prints red ✖ next to offending packages in the PR

### 3. Self-contained Docker image
- `pull → run → delete`
- All analysis inside container — customer code never leaves their metal
- Size target: <500 MB so CI caches it

**If it's not one of those three bullets, it does not exist.**

---

## Key Copy

- **README line:** "Ship zero-day free releases — add this Action, push, and forget."
- **Landing page:** "Ship code, not malware."

---

## IOC Seed Data (LiteLLM Attack)
- Malicious file: `litellm_init.pth`
- C2 domain: `checkmarx.zone`
- Kill switch: `youtube.com`
- Attack vector: GitHub Actions CI/CD pipeline compromise (NOT PyPI account hack)
- Source: Microsoft Security Blog + Kaspersky, March 24-25, 2026
- Missed by: Socket.dev, Snyk

---

## Build Sequence
- **48h:** Free IOC API + GitHub Action + Docker image
- **Week 1:** PyPI monitoring (watch for new malicious packages)
- **Week 4:** CI/CD pipeline integrity sentinel
- **Week 6-8:** Enterprise SBOM + attestation ($299/mo)
