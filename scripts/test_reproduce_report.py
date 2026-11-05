"""The independent recomputation must agree with the reporter on the same data.
Run: python -m pytest scripts -q"""

import datetime
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "functions", "reports"))

import crosswalk  # noqa: E402
import poam  # noqa: E402
import reproduce_report as rr  # noqa: E402

TODAY = datetime.date(2026, 11, 5)
MAPPINGS = [
    {"frameworkId": "nist-800-53-r5", "sourceKey": "cge-a", "controls": ["SC-8", "SC-8(1)", "AC-3"]},
    {"frameworkId": "nist-csf-2.0", "sourceKey": "cge-a", "controls": ["PR.DS-02"]},
]


def doc(i, **kw):
    base = {"id": f"{i:032x}", "displayName": f"w{i}", "resourceId": f"/r/{i}", "severity": "Medium",
            "firstUnhealthyAt": "2026-10-22T05:00:00Z", "status": "Unhealthy", "owner": "grc@x",
            "runId": "run-1", "collectedAt": "2026-11-05T05:00:00Z", "source": "defender"}
    base.update(kw)
    return base


DOCS = [
    doc(1),
    doc(2, severity="High", firstUnhealthyAt="2026-09-01T00:00:00Z"),        # overdue (High = 30 days)
    doc(3, owner="UNASSIGNED"),
    doc(4, owner=None, source=None),                                       # missing source -> defender
    doc(5, source="azurePolicy", assessmentId="cge-a"),                    # mapped via the crosswalk
]


def test_recomputation_matches_the_reporter_exactly():
    _, reporter_summary = poam.build(DOCS, [doc(9, status="Healthy", resolvedAt="2026-11-01T00:00:00Z")],
                                     TODAY, crosswalk.index(MAPPINGS))
    independent = rr.recompute(DOCS, MAPPINGS, closed_count=1, report_date=TODAY)
    assert all(ok for *_, ok in rr.compare(reporter_summary, independent)), rr.compare(reporter_summary, independent)


def test_values():
    s = rr.recompute(DOCS, MAPPINGS, 0, TODAY)
    assert s["open"] == 5 and s["overdue"] == 1 and s["unassigned"] == 2
    assert s["openBySource"] == {"azurePolicy": 1, "defender": 4}
    assert s["byFramework"] == {"mapped": 1, "unmapped": 4, "by80053Family": {"AC": 1, "SC": 1},
                                "byCsfFunction": {"PR": 1}}


def test_compare_flags_a_tampered_number():
    good = rr.recompute(DOCS, MAPPINGS, 0, TODAY)
    tampered = dict(good, overdue=0)
    assert [k for k, _, _, ok in rr.compare(tampered, good) if not ok] == ["overdue"]


def test_queries_are_parameterized_not_string_built():
    assert "@run" in rr.QUERIES["open_findings"] and "@since" in rr.QUERIES["closed_recently"]
