"""Unit tests with fake HTTP responses: no Azure needed. Run: python -m pytest -q"""

import datetime

import role_collector as rc

MG_ROOT = "mg-grc"
SUB = "74a9c6be-f18a-4f85-90de-cb55aaa149b1"
OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIB = "b24988ac-6180-42a0-ab88-20f7382dd24c"
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"


def ra(name, scope, principal, guid, ptype="User"):
    return {"id": f"{scope}/providers/Microsoft.Authorization/roleAssignments/{name}",
            "properties": {"scope": scope, "principalId": principal, "principalType": ptype,
                           "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{guid}",
                           "createdOn": "2026-10-19T00:00:00Z", "createdBy": "creator"}}


MG_SCOPE = f"/providers/Microsoft.Management/managementGroups/{MG_ROOT}"
SANDBOX_SCOPE = "/providers/Microsoft.Management/managementGroups/mg-grc-sandbox"
SUB_SCOPE = f"/subscriptions/{SUB}"
RG_SCOPE = f"{SUB_SCOPE}/resourceGroups/rg-fafo-prod"

# The real hierarchy's shape, with fake principal IDs.
ci_mg = ra("a1", MG_SCOPE, "ci", CONTRIB, "ServicePrincipal")
me_mg = ra("a2", MG_SCOPE, "me", OWNER)
me_sandbox = ra("a3", SANDBOX_SCOPE, "me", OWNER)
me_sub = ra("a4", SUB_SCOPE, "me", OWNER)
batch_rg = ra("a5", RG_SCOPE, "batch", CONTRIB, "ServicePrincipal")
auditors = ra("a6", f"{SUB_SCOPE}/resourceGroups/rg-grc-sandbox-dev", "grp", READER, "Group")


class FakeResp:
    def __init__(self, payload, status=200):
        self.payload, self.status_code = payload, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise rc.requests.HTTPError(str(self.status_code))

    def json(self):
        return self.payload


class FakeSession:
    """Routes URLs to canned responses; records calls."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, timeout=None):
        self.calls.append(url)
        for key, payload in self.routes.items():
            if key in url:
                return FakeResp(payload) if not isinstance(payload, int) else FakeResp({}, payload)
        raise AssertionError(f"unrouted URL {url}")


def routes(**overrides):
    r = {
        f"managementGroups/{MG_ROOT}/descendants": {"value": [
            {"name": "mg-grc-sandbox", "type": "Microsoft.Management/managementGroups"},
            {"name": SUB, "type": "/subscriptions"},
        ]},
        # Page 1 of the root MG list links to page 2 (pagination test).
        f"managementGroups/{MG_ROOT}/providers/Microsoft.Authorization/roleAssignments": {
            "value": [ci_mg], "nextLink": "https://management.azure.com/PAGE2"},
        "PAGE2": {"value": [me_mg]},
        # The sandbox MG also returns the inherited root grant: must de-duplicate.
        "managementGroups/mg-grc-sandbox/providers/Microsoft.Authorization/roleAssignments": {
            "value": [me_sandbox, me_mg]},
        f"subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments": {
            "value": [me_sub, batch_rg, auditors, ci_mg]},
        f"roleDefinitions/{OWNER}": {"properties": {"roleName": "Owner"}},
        f"roleDefinitions/{CONTRIB}": {"properties": {"roleName": "Contributor"}},
        f"roleDefinitions/{READER}": {"properties": {"roleName": "Reader"}},
    }
    r.update(overrides)
    return r


NOW = datetime.datetime(2026, 10, 28, 5, 15, tzinfo=datetime.timezone.utc)


def test_discovers_hierarchy_without_hardcoding():
    mgs, subs = rc.discover_scopes(FakeSession(routes()), MG_ROOT)
    assert mgs == [MG_ROOT, "mg-grc-sandbox"] and subs == [SUB]


def test_snapshot_dedupes_and_follows_pages():
    docs, summary = rc.snapshot(FakeSession(routes()), MG_ROOT, now=NOW)
    assert summary["assignments"] == 6  # 6 unique grants despite overlapping lists
    assert {d["principalId"] for d in docs} == {"ci", "me", "batch", "grp"}


def test_management_group_grants_are_captured():
    docs, summary = rc.snapshot(FakeSession(routes()), MG_ROOT, now=NOW)
    mg_docs = [d for d in docs if d["scopeLevel"] == "managementGroup"]
    assert summary["managementGroupScope"] == 3  # ci@mg-grc, me@mg-grc, me@sandbox: what policy can't see
    assert {d["scopeRoot"] for d in mg_docs} == {"mg:mg-grc", "mg:mg-grc-sandbox"}


def test_privileged_flag_and_role_names():
    docs, summary = rc.snapshot(FakeSession(routes()), MG_ROOT, now=NOW)
    assert summary["privileged"] == 5  # all but the auditors' Reader
    reader = next(d for d in docs if d["principalId"] == "grp")
    assert reader["roleName"] == "Reader" and reader["privileged"] is False


def test_scope_levels_and_partition():
    assert rc.scope_level(SUB_SCOPE) == "subscription"
    assert rc.scope_level(RG_SCOPE) == "resourceGroup"
    assert rc.scope_level(f"{RG_SCOPE}/providers/Microsoft.Storage/storageAccounts/x") == "resource"
    assert rc.scope_root(RG_SCOPE) == SUB  # partition key = the subscription
    assert rc.scope_root(MG_SCOPE) == "mg:mg-grc"


def test_daily_ids_stable_within_day_new_next_day():
    d1 = rc.to_document(me_sub, "Owner", "2026-10-28", "r1", "t1")
    d2 = rc.to_document(me_sub, "Owner", "2026-10-28", "r2", "t2")
    d3 = rc.to_document(me_sub, "Owner", "2026-10-29", "r3", "t3")
    assert d1["id"] == d2["id"]  # same-day re-run refreshes
    assert d1["id"] != d3["id"]  # next day = new history point


def test_no_pii_fields():
    doc = rc.to_document(me_sub, "Owner", "2026-10-28", "r", "t")
    assert not any(k in doc for k in ("principalName", "displayName", "email", "signInName"))


def test_unresolvable_role_recorded_not_fatal():
    r = routes(**{f"roleDefinitions/{READER}": 403})
    docs, _ = rc.snapshot(FakeSession(r), MG_ROOT, now=NOW)
    assert next(d for d in docs if d["principalId"] == "grp")["roleName"] == "(unresolved)"


def test_role_names_cached_once_per_guid():
    s = FakeSession(routes())
    rc.snapshot(s, MG_ROOT, now=NOW)
    assert sum(f"roleDefinitions/{OWNER}" in c for c in s.calls) == 1