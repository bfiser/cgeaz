"""POA&M row logic: pure functions, unit-tested (test_poam.py).

Everything here is computed from evidence documents the collector wrote. The reporter
never calls Azure and never writes to Cosmos (separation of duties); it only reads
lifecycle facts (firstUnhealthyAt, resolvedAt, owner) and turns them into a plan.
"""

import datetime

# Severity-based SLAs: a POA&M is a plan, not a list.
SLA_DAYS = {"High": 30, "Medium": 90, "Low": 180}
SEVERITY_RANK = {"High": 0, "Medium": 1, "Low": 2}
UNASSIGNED = "UNASSIGNED"

COLUMNS = [
    ("poamId", "POA&M ID"),
    ("weakness", "Weakness"),
    ("resourceId", "Affected Resource"),
    ("severity", "Severity"),
    ("owner", "Owner"),
    ("firstDetected", "First Detected"),
    ("detectionSource", "Detection Source"),
    ("daysOpen", "Days Open"),
    ("scheduledCompletion", "Scheduled Completion"),
    ("overdue", "Overdue"),
    ("status", "Status"),
    ("closedAt", "Closed At"),
    ("lastSeenRun", "Last Seen Run"),
]


def poam_id(doc):
    """Stable ID: derived from the evidence document's ID, which is a hash of
    assessment + resource. Same weakness on the same resource = same ID every day."""
    return f"POAM-{doc['id'][:12].upper()}"


def _date(iso):
    return datetime.date.fromisoformat(iso[:10]) if iso else None


def to_row(doc, today):
    """One POA&M row. Deadlines run from FIRST detection, so they stop sliding and can pass."""
    severity = doc.get("severity") or "Medium"
    first = _date(doc.get("firstUnhealthyAt")) or _date(doc.get("collectedAt")) or today
    due = first + datetime.timedelta(days=SLA_DAYS.get(severity, 90))
    closed = _date(doc.get("resolvedAt")) if doc.get("status") != "Unhealthy" else None
    end = closed or today
    return {
        "poamId": poam_id(doc),
        "weakness": doc.get("displayName"),
        "resourceId": doc.get("resourceId"),
        "severity": severity,
        "owner": doc.get("owner") or UNASSIGNED,
        "firstDetected": first.isoformat(),
        "detectionSource": doc.get("firstDetectedSource") or "unknown",
        "daysOpen": (end - first).days,
        "scheduledCompletion": due.isoformat(),
        "overdue": closed is None and today > due,
        "status": "Closed" if closed else "Open",
        "closedAt": closed.isoformat() if closed else None,
        "lastSeenRun": doc.get("runId"),
    }


def build(open_docs, closed_docs, today):
    """Rows for open findings plus recently closed ones, sorted so the riskiest come first:
    open before closed, overdue first, then severity, then longest open."""
    rows = [to_row(d, today) for d in open_docs] + [to_row(d, today) for d in closed_docs]
    rows.sort(key=lambda r: (r["status"] == "Closed", not r["overdue"],
                             SEVERITY_RANK.get(r["severity"], 9), -r["daysOpen"]))
    open_rows = [r for r in rows if r["status"] == "Open"]
    summary = {
        "open": len(open_rows),
        "overdue": sum(r["overdue"] for r in open_rows),
        "unassigned": sum(r["owner"] == UNASSIGNED for r in open_rows),
        "closedRecently": len(rows) - len(open_rows),
        "oldestOpenDays": max((r["daysOpen"] for r in open_rows), default=0),
    }
    return rows, summary


def report_path(prefix, ext, now, exists):
    """Daily path; if today's report already exists (WORM: it can never be replaced), write a
    time-suffixed one instead. Keeps immutability without making same-day re-runs fail."""
    path = f"{prefix}/{now:%Y/%m}/{prefix}-{now:%Y-%m-%d}.{ext}"
    if exists(path):
        path = f"{prefix}/{now:%Y/%m}/{prefix}-{now:%Y-%m-%d}-{now:%H%M%S}.{ext}"
    return path
