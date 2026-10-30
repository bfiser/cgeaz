"""Finding lifecycle and ownership: pure functions, unit-tested (test_lifecycle.py).

The collector owns lifecycle facts because it is the only identity allowed to write
evidence. The reporter stays read-only (separation of duties) and just reads these
fields to compute aging, deadlines, overdue status, and closures.
"""

UNASSIGNED = "UNASSIGNED"


def resource_group_of(resource_id):
    """Lowercased resource group name from an ARM resource ID, or None (subscription-level)."""
    parts = [p for p in (resource_id or "").split("/") if p]
    for i, part in enumerate(parts[:-1]):
        if part.lower() == "resourcegroups":
            return parts[i + 1].lower()
    return None


def owner_for(resource_id, rg_owners):
    """Owner from the resource group's `owner` tag. Missing tag or no resource group -> UNASSIGNED,
    so an ownerless finding is visible in the report instead of hidden behind a placeholder."""
    rg = resource_group_of(resource_id)
    if rg is None:
        return UNASSIGNED
    return rg_owners.get(rg) or UNASSIGNED


def lifecycle(prev, status, now):
    """Carry lifecycle fields forward from yesterday's document.

    prev:   the stored document's lifecycle fields (dict) or None if never seen
    status: today's Defender status code ("Unhealthy", "Healthy", "NotApplicable", ...)
    now:    this run's collectedAt (ISO timestamp)

    Rules:
    - Newly Unhealthy (never seen, or was not Unhealthy): firstUnhealthyAt = now, source "collector".
    - Still Unhealthy: keep the original firstUnhealthyAt and its source (this is the aging clock).
      If an older document lacks it (pre-change data not backfilled), start the clock now but mark
      the source "collector-first-seen" so the report never overstates how long we've known.
    - Unhealthy -> not Unhealthy: resolvedAt = now; keep firstUnhealthyAt (closure keeps its history).
    - Otherwise: carry fields unchanged.
    """
    prev = prev or {}
    was_unhealthy = prev.get("status") == "Unhealthy"
    out = {
        "firstUnhealthyAt": prev.get("firstUnhealthyAt"),
        "firstDetectedSource": prev.get("firstDetectedSource"),
        "resolvedAt": prev.get("resolvedAt"),
    }
    if status == "Unhealthy":
        if not was_unhealthy:
            out.update(firstUnhealthyAt=now, firstDetectedSource="collector", resolvedAt=None)
        elif not out["firstUnhealthyAt"]:
            out.update(firstUnhealthyAt=now, firstDetectedSource="collector-first-seen")
    elif was_unhealthy:
        out["resolvedAt"] = now
    return out
