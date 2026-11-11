# Accepted risks expiring within 90 days (as of 2026-11-11)

| Expires | File | Control | Id | Severity | Approved by |
|---|---|---|---|---|---|
| 2027-01-25 | frappe-gates-demo.json | dast-tls | cert_revocation | high | usfadan |
| 2027-01-25 | frappe-gates-demo.json | dast-tls | intermediate_cert_expiration | high | usfadan |
| 2027-01-25 | frappe-gates-demo.json | dast-tls | intermediate_cert_notAfter | high | usfadan |

An expired entry accepts nothing: the finding blocks again. Renew it through a new exception request (new approval, new expiry) or fix the finding.
