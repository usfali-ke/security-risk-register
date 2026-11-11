#!/usr/bin/env python3
"""Validate the accepted-risks register (stdlib only, no dependencies).

    validate.py                 every file: exit 1 on any error
    validate.py --expiring N    list entries expiring within N days (or
                                already expired), for the expiry workflow;
                                writes expiring.md, exits 0

Policy, enforced on every change:
  - org.json and products/<product-key>.json, each {"product", "accepted": [...]};
    a product file's "product" equals its file name.
  - Every entry has control (a control that consults the register), id,
    severity, reason, expires, requested_by, approved_by, approved_at.
  - approved_by differs from requested_by (separation of duties).
  - Critical and High need a compensating_control.
  - expires is after approved_at and at most MAX_DAYS[severity] after it
    (critical 30, high 90, medium 180, low and info 365). A change may not
    add or extend an entry that is already past its expiry.
  - No two entries with the same control + id + match in one file.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Controls whose verdict consults the register (frappe-gates-demo's
# .github/scripts/verdict.py accepted(), and hermes_review.py for ai-review).
CONTROLS = {
    "sast-semgrep", "secrets-gitleaks", "secrets-trufflehog", "sca-trivy", "iac-checkov",
    "image-scan", "image-compliance", "dast-nuclei", "dast-tls", "ai-review",
}
SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_DAYS = {"critical": 30, "high": 90, "medium": 180, "low": 365, "info": 365}
REQUIRED = ("control", "id", "severity", "reason", "expires", "requested_by", "approved_by", "approved_at")
KNOWN = set(REQUIRED) | {"match", "unfixed_only", "compensating_control", "ticket", "exception_id",
                         "defectdojo_risk_acceptance", "migrated_from"}
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def files() -> list[Path]:
    return [ROOT / "org.json", *sorted((ROOT / "products").glob("*.json"))]


def load(path: Path) -> tuple[dict | None, list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return None, [f"{path.name}: not valid JSON ({exc})"]
    if not isinstance(data, dict) or not isinstance(data.get("accepted"), list):
        return None, [f"{path.name}: must be an object with an 'accepted' list"]
    return data, []


def date(value: str) -> dt.date | None:
    if not isinstance(value, str) or not DATE.match(value):
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def check_entry(where: str, e: dict, today: dt.date) -> list[str]:
    errs = []
    if not isinstance(e, dict):
        return [f"{where}: entry is not an object"]
    for key in REQUIRED:
        if not str(e.get(key, "")).strip():
            errs.append(f"{where}: missing '{key}'")
    for key in e:
        if key not in KNOWN:
            errs.append(f"{where}: unknown field '{key}' (typo?)")
    if e.get("control") and e["control"] not in CONTROLS:
        errs.append(f"{where}: control '{e['control']}' does not consult the register (one of: {', '.join(sorted(CONTROLS))})")
    sev = e.get("severity")
    if sev and sev not in SEVERITIES:
        errs.append(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
    if len(str(e.get("reason", "")).strip()) < 20:
        errs.append(f"{where}: reason must explain the decision (20+ characters)")
    if sev in ("critical", "high") and len(str(e.get("compensating_control", "")).strip()) < 20:
        errs.append(f"{where}: {sev} needs a compensating_control (20+ characters)")
    req, appr = str(e.get("requested_by", "")).strip().lower(), str(e.get("approved_by", "")).strip().lower()
    if req and appr and req == appr:
        errs.append(f"{where}: approved_by must differ from requested_by (separation of duties)")
    if "unfixed_only" in e and not isinstance(e["unfixed_only"], bool):
        errs.append(f"{where}: unfixed_only must be true or false")
    approved, expires = date(e.get("approved_at")), date(e.get("expires"))
    if e.get("approved_at") and not approved:
        errs.append(f"{where}: approved_at must be YYYY-MM-DD")
    if e.get("expires") and not expires:
        errs.append(f"{where}: expires must be YYYY-MM-DD")
    if approved and approved > today:
        errs.append(f"{where}: approved_at is in the future")
    if approved and expires and sev in MAX_DAYS:
        if expires <= approved:
            errs.append(f"{where}: expires must be after approved_at")
        elif (expires - approved).days > MAX_DAYS[sev]:
            errs.append(f"{where}: {sev} may be accepted for at most {MAX_DAYS[sev]} days "
                        f"(approved {approved}, expires {expires} = {(expires - approved).days} days)")
    return errs


def validate(today: dt.date) -> list[str]:
    errs = []
    for path in files():
        data, problems = load(path)
        errs += problems
        if data is None:
            continue
        expected = "*" if path.name == "org.json" else path.stem
        if data.get("product") != expected:
            errs.append(f"{path.name}: 'product' must be {expected!r}")
        seen = set()
        for i, e in enumerate(data["accepted"]):
            where = f"{path.name}[{i}] {e.get('control', '?')}/{e.get('id', '?')}" if isinstance(e, dict) else f"{path.name}[{i}]"
            errs += check_entry(where, e, today)
            if isinstance(e, dict):
                key = (e.get("control"), e.get("id"), e.get("match", ""))
                if key in seen:
                    errs.append(f"{where}: duplicate of an earlier entry (same control, id and match)")
                seen.add(key)
    return errs


def expiring(today: dt.date, days: int) -> list[tuple[dt.date, str, dict]]:
    out = []
    for path in files():
        data, _ = load(path)
        for e in (data or {}).get("accepted", []):
            exp = date(e.get("expires")) if isinstance(e, dict) else None
            if exp and (exp - today).days <= days:
                out.append((exp, path.name, e))
    return sorted(out, key=lambda t: t[0])


def main() -> int:
    today = dt.date.today()
    if len(sys.argv) == 3 and sys.argv[1] == "--expiring":
        rows = expiring(today, int(sys.argv[2]))
        lines = [f"# Accepted risks expiring within {sys.argv[2]} days (as of {today})", ""]
        if not rows:
            lines.append("None.")
        else:
            lines += ["| Expires | File | Control | Id | Severity | Approved by |", "|---|---|---|---|---|---|"]
            for exp, name, e in rows:
                state = " **(expired: no longer accepted)**" if exp < today else ""
                lines.append(f"| {exp}{state} | {name} | {e.get('control')} | {e.get('id')} | {e.get('severity')} | {e.get('approved_by')} |")
            lines += ["", "An expired entry accepts nothing: the finding blocks again. Renew it through a "
                      "new exception request (new approval, new expiry) or fix the finding."]
        (ROOT / "expiring.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("\n".join(lines))
        return 0
    errs = validate(today)
    total = sum(len((load(p)[0] or {}).get("accepted", [])) for p in files())
    if errs:
        print(f"register INVALID: {len(errs)} problem(s) in {total} entries", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"register valid: {total} entries in {len(files())} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
