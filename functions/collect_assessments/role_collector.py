"""Role-assignment snapshot logic (pure functions + one I/O entry point).

Kept separate from the Azure Functions wiring so it can be unit-tested with fake
HTTP responses (see test_role_collector.py).
"""

import datetime
import hashlib
import logging
import uuid

import requests

ARM = "https://management.azure.com"
RBAC_API = "2022-04-01"
MG_API = "2020-05-01"

# Built-in role GUIDs are identical in every tenant. Same list as Custom 3 and the
# broad_roles gate rule, so all three controls agree on what "privileged" means.
PRIVILEGED_ROLE_GUIDS = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  # User Access Administrator
    "f58310d9-a9f6-439a-9e8d-f62e7b41a168",  # Role Based Access Control Administrator
}


def _get_all(session, url):
    """GET a list endpoint and follow nextLink pages until done."""
    items = []
    while url:
        resp = session.get(url, timeout=60)
        resp.raise_for_status()
        payload = resp.json()
        items.extend(payload.get("value", []))
        url = payload.get("nextLink")
    return items


def scope_level(scope):
    """Classify a scope string: managementGroup, subscription, resourceGroup, or resource."""
    s = scope.lower()
    if "/providers/microsoft.management/managementgroups/" in s and not s.startswith("/subscriptions/"):
        return "managementGroup"
    parts = [p for p in s.split("/") if p]
    if len(parts) == 2 and parts[0] == "subscriptions":
        return "subscription"
    if len(parts) == 4 and parts[2] == "resourcegroups":
        return "resourceGroup"
    if s == "/":
        return "root"
    return "resource"


def scope_root(scope):
    """Partition value: the subscription ID for anything at or below a subscription,
    otherwise 'mg:<name>' for management-group (or root) scope grants."""
    parts = [p for p in scope.split("/") if p]
    if len(parts) >= 2 and parts[0].lower() == "subscriptions":
        return parts[1].lower()
    if len(parts) >= 4 and parts[2].lower() == "managementgroups":
        return f"mg:{parts[3]}"
    return "mg:/"


def discover_scopes(session, root_mg_name):
    """Walk the hierarchy under the root management group. Nothing hardcoded:
    a subscription or management group added later is picked up on the next run."""
    mgs = [root_mg_name]
    subs = []
    url = f"{ARM}/providers/Microsoft.Management/managementGroups/{root_mg_name}/descendants?api-version={MG_API}"
    for d in _get_all(session, url):
        dtype = d.get("type", "").lower()
        if dtype.endswith("managementgroups"):
            mgs.append(d["name"])
        elif dtype.endswith("subscriptions"):
            subs.append(d["name"])
    return mgs, subs


def list_assignments(session, mgs, subs):
    """All role assignments visible from these scopes, de-duplicated by assignment ID.
    - Management groups: $filter=atScope() returns grants AT the group (and inherited
      from above), which is exactly what Azure Policy cannot see.
    - Subscriptions: everything at, below, and inherited into the subscription."""
    seen = {}
    for mg in mgs:
        url = (f"{ARM}/providers/Microsoft.Management/managementGroups/{mg}"
               f"/providers/Microsoft.Authorization/roleAssignments?api-version={RBAC_API}&$filter=atScope()")
        for ra in _get_all(session, url):
            seen[ra["id"].lower()] = ra
    for sub in subs:
        url = f"{ARM}/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments?api-version={RBAC_API}"
        for ra in _get_all(session, url):
            seen[ra["id"].lower()] = ra
    return list(seen.values())


def role_name(session, role_definition_id, cache):
    """Resolve a role definition ID to its display name, once per GUID per run."""
    guid = role_definition_id.rstrip("/").split("/")[-1].lower()
    if guid not in cache:
        try:
            resp = session.get(f"{ARM}{role_definition_id}?api-version={RBAC_API}", timeout=30)
            resp.raise_for_status()
            cache[guid] = resp.json().get("properties", {}).get("roleName", "(unknown)")
        except requests.RequestException:
            cache[guid] = "(unresolved)"  # record the gap instead of failing the whole run
    return cache[guid]


def to_document(ra, role, snapshot_date, run_id, collected_at):
    """One snapshot document. IDs only: no names or emails for principals (PII stays out
    of the evidence store; a reviewer resolves names at review time)."""
    props = ra.get("properties", {})
    scope = props.get("scope", "")
    role_def_id = props.get("roleDefinitionId", "")
    role_guid = role_def_id.rstrip("/").split("/")[-1].lower()
    # One document per assignment per DAY: re-runs the same day refresh it,
    # the next day adds a new one. That daily series is the access-review history.
    doc_id = hashlib.sha256(f"{ra['id'].lower()}|{snapshot_date}".encode()).hexdigest()[:32]
    return {
        "id": doc_id,
        "scopeRoot": scope_root(scope),
        "snapshotDate": snapshot_date,
        "runId": run_id,
        "collectedAt": collected_at,
        "assignmentId": ra["id"],
        "scope": scope,
        "scopeLevel": scope_level(scope),
        "principalId": props.get("principalId"),
        "principalType": props.get("principalType"),
        "roleDefinitionGuid": role_guid,
        "roleName": role,
        "privileged": role_guid in PRIVILEGED_ROLE_GUIDS,
        "hasCondition": bool(props.get("condition")),
        "createdOn": props.get("createdOn"),
        "createdBy": props.get("createdBy"),
    }


def snapshot(session, root_mg_name, now=None):
    """Discover scopes, list assignments, and return snapshot documents plus a summary."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    run_id = str(uuid.uuid4())
    collected_at = now.isoformat()
    snapshot_date = now.date().isoformat()

    mgs, subs = discover_scopes(session, root_mg_name)
    assignments = list_assignments(session, mgs, subs)
    cache = {}
    docs = [
        to_document(ra, role_name(session, ra["properties"]["roleDefinitionId"], cache),
                    snapshot_date, run_id, collected_at)
        for ra in assignments
    ]
    summary = {
        "runId": run_id,
        "collectedAt": collected_at,
        "managementGroups": len(mgs),
        "subscriptions": len(subs),
        "assignments": len(docs),
        "privileged": sum(d["privileged"] for d in docs),
        "managementGroupScope": sum(d["scopeLevel"] == "managementGroup" for d in docs),
    }
    logging.info("role snapshot %s: %s", run_id, summary)
    return docs, summary