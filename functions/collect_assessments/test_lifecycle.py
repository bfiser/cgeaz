"""Unit tests for finding lifecycle and ownership. Run: python -m pytest -q"""

import lifecycle as lc

RG_ID = "/subscriptions/s/resourceGroups/RG-FAFO-Prod/providers/Microsoft.Web/sites/app"
SUB_ID = "/subscriptions/s"
T1, T2, T3 = "2026-10-21T05:00:00Z", "2026-10-30T05:00:00Z", "2026-11-02T05:00:00Z"


def test_resource_group_parsing_case_insensitive():
    assert lc.resource_group_of(RG_ID) == "rg-fafo-prod"
    assert lc.resource_group_of(SUB_ID) is None
    assert lc.resource_group_of("") is None


def test_owner_from_tag_or_unassigned():
    owners = {"rg-fafo-prod": "grc-team@fafo.example", "rg-fafo-legacy": None}
    assert lc.owner_for(RG_ID, owners) == "grc-team@fafo.example"
    assert lc.owner_for("/subscriptions/s/resourceGroups/rg-fafo-legacy/x", owners) == lc.UNASSIGNED
    assert lc.owner_for("/subscriptions/s/resourceGroups/rg-unknown/x", owners) == lc.UNASSIGNED
    assert lc.owner_for(SUB_ID, owners) == lc.UNASSIGNED


def test_new_finding_starts_clock():
    out = lc.lifecycle(None, "Unhealthy", T2)
    assert out == {"firstUnhealthyAt": T2, "firstDetectedSource": "collector", "resolvedAt": None}


def test_still_unhealthy_keeps_original_clock():
    prev = {"status": "Unhealthy", "firstUnhealthyAt": T1, "firstDetectedSource": "backfill:poam-2026-10-21"}
    out = lc.lifecycle(prev, "Unhealthy", T2)
    assert out["firstUnhealthyAt"] == T1 and out["firstDetectedSource"] == "backfill:poam-2026-10-21"


def test_legacy_doc_without_clock_is_marked_not_overstated():
    out = lc.lifecycle({"status": "Unhealthy"}, "Unhealthy", T2)
    assert out["firstUnhealthyAt"] == T2 and out["firstDetectedSource"] == "collector-first-seen"


def test_resolution_sets_resolved_and_keeps_history():
    prev = {"status": "Unhealthy", "firstUnhealthyAt": T1, "firstDetectedSource": "collector"}
    out = lc.lifecycle(prev, "Healthy", T2)
    assert out["resolvedAt"] == T2 and out["firstUnhealthyAt"] == T1


def test_reopened_finding_starts_new_clock():
    prev = {"status": "Healthy", "firstUnhealthyAt": T1, "resolvedAt": T2, "firstDetectedSource": "collector"}
    out = lc.lifecycle(prev, "Unhealthy", T3)
    assert out == {"firstUnhealthyAt": T3, "firstDetectedSource": "collector", "resolvedAt": None}


def test_healthy_stays_healthy_unchanged():
    prev = {"status": "Healthy", "firstUnhealthyAt": None, "resolvedAt": None}
    assert lc.lifecycle(prev, "Healthy", T2) == {"firstUnhealthyAt": None, "firstDetectedSource": None, "resolvedAt": None}
