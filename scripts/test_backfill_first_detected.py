"""Unit tests for the backfill's streak logic. Run: python -m pytest -q"""

import backfill_first_detected as bf

A = bf.finding_key("FTPS should be required in web apps", "/subscriptions/s/resourceGroups/RG/providers/x/app")
B = bf.finding_key("Key vaults should have deletion protection enabled", "/subscriptions/s/kv")
C = bf.finding_key("Flapping finding", "/subscriptions/s/c")

REPORTS = [
    ("2026-10-21", "t21", {A}),
    ("2026-10-22", "t22", {A, C}),
    ("2026-10-23", "t23", {A}),          # C fixed
    ("2026-10-26", "t26", {A, B, C}),    # B new (seed estate), C back
    ("2026-10-30", "t30", {A, B, C}),
]


def test_key_is_case_insensitive_on_resource():
    assert bf.finding_key("W", "/A/B") == bf.finding_key("W ", "/a/b")


def test_present_since_first_report():
    assert bf.streak_starts(REPORTS)[A] == ("2026-10-21", "t21")


def test_appears_later():
    assert bf.streak_starts(REPORTS)[B] == ("2026-10-26", "t26")


def test_gap_resets_streak_to_newer_date():
    assert bf.streak_starts(REPORTS)[C] == ("2026-10-26", "t26")  # not 10-22: it was fixed in between


def test_only_currently_open_findings():
    old = bf.finding_key("Gone", "/x")
    reports = [("2026-10-21", "t", {old}), ("2026-10-22", "t2", {A})]
    assert old not in bf.streak_starts(reports)


def test_empty_history():
    assert bf.streak_starts([]) == {}


def test_needs_backfill_rules():
    assert bf.needs_backfill({"status": "Unhealthy"})
    assert bf.needs_backfill({"status": "Unhealthy", "firstUnhealthyAt": "t", "firstDetectedSource": "collector-first-seen"})
    assert not bf.needs_backfill({"status": "Unhealthy", "firstUnhealthyAt": "t", "firstDetectedSource": "collector"})
    assert not bf.needs_backfill({"status": "Healthy"})
