"""Unit tests for POA&M row logic. Run: python -m pytest -q"""

import datetime

import poam

TODAY = datetime.date(2026, 10, 30)


def doc(id_, severity="Medium", first="2026-10-22T05:00:00Z", status="Unhealthy",
        resolved=None, owner="grc-team@fafo.example", source="backfill:poam-2026-10-22"):
    return {"id": id_, "displayName": f"weakness {id_}", "resourceId": f"/r/{id_}", "severity": severity,
            "firstUnhealthyAt": first, "firstDetectedSource": source, "status": status,
            "resolvedAt": resolved, "owner": owner, "runId": "run-1", "collectedAt": "2026-10-30T05:00:00Z"}


def test_id_is_stable_and_independent_of_date_and_order():
    a = poam.to_row(doc("abcdef0123456789"), TODAY)["poamId"]
    b = poam.to_row(doc("abcdef0123456789"), TODAY + datetime.timedelta(days=5))["poamId"]
    assert a == b == "POAM-ABCDEF012345"


def test_deadline_from_first_detection_not_today():
    r = poam.to_row(doc("a", first="2026-10-22T05:00:00Z"), TODAY)
    assert r["scheduledCompletion"] == "2027-01-20"  # 10-22 + 90, the same tomorrow and every day after
    assert poam.to_row(doc("a"), TODAY + datetime.timedelta(days=1))["scheduledCompletion"] == "2027-01-20"


def test_days_open():
    assert poam.to_row(doc("a", first="2026-10-21T05:00:00Z"), TODAY)["daysOpen"] == 9


def test_overdue_when_past_sla():
    r = poam.to_row(doc("a", severity="High", first="2026-09-01T00:00:00Z"), TODAY)
    assert r["overdue"] is True and r["scheduledCompletion"] == "2026-10-01"


def test_not_overdue_within_sla():
    assert poam.to_row(doc("a", severity="High", first="2026-10-15T00:00:00Z"), TODAY)["overdue"] is False


def test_owner_fallback_visible():
    assert poam.to_row(doc("a", owner=None), TODAY)["owner"] == "UNASSIGNED"


def test_closed_item():
    r = poam.to_row(doc("a", status="Healthy", first="2026-10-22T00:00:00Z", resolved="2026-10-29T05:00:00Z"), TODAY)
    assert r["status"] == "Closed" and r["closedAt"] == "2026-10-29" and r["daysOpen"] == 7 and r["overdue"] is False


def test_missing_lifecycle_falls_back_and_says_so():
    d = doc("a", first=None, source=None)
    r = poam.to_row(d, TODAY)
    assert r["firstDetected"] == "2026-10-30" and r["detectionSource"] == "unknown"


def test_sort_and_summary():
    rows, summary = poam.build(
        [doc("low", severity="Low"), doc("hi_old", severity="High", first="2026-09-01T00:00:00Z"),
         doc("med_unowned", owner=None)],
        [doc("closed", status="Healthy", resolved="2026-10-29T00:00:00Z")], TODAY)
    assert [r["poamId"][5:] for r in rows][0] == "HI_OLD"      # overdue first
    assert rows[-1]["status"] == "Closed"                       # closed last
    assert summary == {"open": 3, "overdue": 1, "unassigned": 1, "closedRecently": 1, "oldestOpenDays": 59,
                       "openBySource": {"defender": 3}}


def test_report_path_daily_then_suffixed():
    now = datetime.datetime(2026, 10, 30, 16, 45, 7)
    assert poam.report_path("poam", "json", now, lambda p: False) == "poam/2026/10/poam-2026-10-30.json"
    assert poam.report_path("poam", "json", now, lambda p: True) == "poam/2026/10/poam-2026-10-30-164507.json"


def test_policy_finding_shows_source_and_controls():
    d = dict(doc("p"), source="azurePolicy", controls=["SC-7", "AC-17"])
    r = poam.to_row(d, TODAY)
    assert r["source"] == "azurePolicy" and r["controls"] == "SC-7, AC-17"


def test_defender_finding_defaults_source_and_empty_controls():
    r = poam.to_row(doc("d"), TODAY)
    assert r["source"] == "defender" and r["controls"] == ""


def test_summary_counts_open_by_source():
    _, summary = poam.build([doc("a"), dict(doc("b"), source="azurePolicy")], [], TODAY)
    assert summary["openBySource"] == {"azurePolicy": 1, "defender": 1}
