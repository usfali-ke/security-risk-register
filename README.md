# Security risk register

Every accepted security risk (an exception to a pipeline's Critical/High gates) for every product, in one place, reviewed by security, always expiring.

- **`products/<product-key>.json`**: one product's accepted risks.
- **`org.json`**: accepted for every product (use sparingly).
- **`scripts/validate.py`**: the policy, required on every change.

## How it is used

**Product pipelines read this repository at the start of each run** with a read-only deploy key: `org.json` plus their own product file, from `main`. They never read a pull request's copy, so a change can't accept its own findings.
- A finding is accepted only by an entry for the same `control` and `id` (plus `match`, if given) that hasn't expired.
- The pipeline records the register commit it used in the verdict.
- If the register can't be read, nothing is accepted and the gate blocks (fail-closed).

**The security dashboard's exception requests are the front door.** Approving a request opens a pull request here, and merging it is what makes the exception live. Once merged, the dashboard records the same decision as a DefectDojo Risk Acceptance.

## Entry

```json
{
  "control": "sca-trivy",
  "id": "CVE-2026-12345",
  "match": "pillow",
  "severity": "high",
  "reason": "Why the risk is accepted (who is exposed, why not fixed now)",
  "compensating_control": "What limits the risk meanwhile (required for critical/high)",
  "expires": "2027-01-15",
  "requested_by": "github-login-or-email",
  "approved_by": "a different person",
  "approved_at": "2026-11-11",
  "ticket": "https://...",
  "exception_id": 42,
  "defectdojo_risk_acceptance": 17
}
```

| Field | Meaning |
|---|---|
| `control` | The pipeline control: `sast-semgrep`, `secrets-gitleaks`, `secrets-trufflehog`, `sca-trivy`, `iac-checkov`, `image-scan`, `image-compliance`, `dast-nuclei`, `dast-tls`, `ai-review`, `config` (the release stage's manifest check) |
| `id` | The finding's identity in that control: rule id, CVE or check id. For `ai-review`, `CWE-<n>`. |
| `match` | Optional substring that narrows the entry (a file, package or title) |
| `unfixed_only` | Optional. `true` accepts the finding only while it has no fix available. |

**Maximum lifetime from `approved_at`:** critical 30 days, high 90, medium 180, low and info 365. An expired entry accepts nothing. The daily `expiry` workflow lists entries expiring within 14 days in an issue.
