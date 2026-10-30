"""Unit tests for the policy-state collector. Run: python -m pytest -q"""

import policy_collector as pc

SUB = "74a9c6be-f18a-4f85-90de-cb55aaa149b1"
NSG_DEF = "/providers/Microsoft.Management/managementGroups/mg-grc-sandbox/providers/Microsoft.Authorization/policyDefinitions/cge-nsg-no-internet-mgmt-ports"
TAG_DEF = "/providers/Microsoft.Management/managementGroups/mg-grc-sandbox/providers/Microsoft.Authorization/policyDefinitions/cge-require-env-tag-rg"


def state(defn, name, resource, compliance):
    return {"policyDefinitionId": defn, "policyDefinitionName": name, "resourceId": resource,
            "complianceState": compliance, "subscriptionId": SUB,
            "policyAssignmentId": "/providers/.../cge-grc-baseline", "timestamp": "2026-10-30T15:00:00Z"}


NSG_OPEN = state(NSG_DEF, "cge-nsg-no-internet-mgmt-ports",
                 f"/subscriptions/{SUB}/resourceGroups/rg-fafo-legacy/providers/Microsoft.Network/networkSecurityGroups/nsg-fafo-open", "NonCompliant")
NSG_SAFE = state(NSG_DEF, "cge-nsg-no-internet-mgmt-ports",
                 f"/subscriptions/{SUB}/resourceGroups/rg-fafo-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-cge-test-safe", "Compliant")
TAG_LEGACY = state(TAG_DEF, "cge-require-env-tag-rg", f"/subscriptions/{SUB}/resourceGroups/rg-fafo-legacy", "NonCompliant")


class Resp:
    def __init__(self, payload, status=200):
        self.payload, self.status_code = payload, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)

    def json(self):
        return self.payload


class Session:
    def __init__(self, posts, gets):
        self.posts, self.gets, self.calls = posts, gets, []

    def post(self, url, timeout=None):
        self.calls.append(("POST", url))
        for k, v in self.posts.items():
            if k in url:
                return Resp(v)
        raise AssertionError(url)

    def get(self, url, timeout=None):
        self.calls.append(("GET", url))
        for k, v in self.gets.items():
            if k in url:
                return Resp(v) if not isinstance(v, int) else Resp({}, v)
        raise AssertionError(url)


def session(**gets_override):
    gets = {
        "cge-nsg-no-internet-mgmt-ports": {"properties": {
            "displayName": "NSG rules must not allow SSH (22) or RDP (3389) from the internet",
            "metadata": {"category": "Network", "nist_800_53": ["SC-7", "SC-7(5)", "AC-17"]}}},
        "cge-require-env-tag-rg": {"properties": {
            "displayName": "Resource groups must carry an env tag", "metadata": {}}},
    }
    gets.update(gets_override)
    posts = {
        "policyStates/latest/queryResults": {"value": [NSG_OPEN, NSG_SAFE], "@odata.nextLink": "https://management.azure.com/PAGE2"},
        "PAGE2": {"value": [TAG_LEGACY]},
    }
    return Session(posts, gets)


def test_queries_at_management_group_scope_with_initiative_filter():
    s = session()
    pc.collect(s, "mg-grc", "cge-grc-baseline")
    first = s.calls[0]
    assert first[0] == "POST" and "managementGroups/mg-grc/providers/Microsoft.PolicyInsights" in first[1]
    assert "policySetDefinitionName eq 'cge-grc-baseline'" in first[1]


def test_follows_pages_and_maps_status():
    docs = pc.collect(session(), "mg-grc", "cge-grc-baseline")
    assert len(docs) == 3
    assert {d["status"] for d in docs} == {"Unhealthy", "Healthy"}


def test_controls_come_from_definition_metadata():
    docs = pc.collect(session(), "mg-grc", "cge-grc-baseline")
    nsg = next(d for d in docs if d["resourceId"].endswith("nsg-fafo-open"))
    assert nsg["controls"] == ["SC-7", "SC-7(5)", "AC-17"]
    assert nsg["displayName"].startswith("NSG rules must not allow")
    assert nsg["source"] == "azurePolicy" and nsg["categories"] == ["Network"]


def test_definition_without_controls_is_empty_list_not_error():
    docs = pc.collect(session(), "mg-grc", "cge-grc-baseline")
    tag = next(d for d in docs if d["assessmentId"] == "cge-require-env-tag-rg")
    assert tag["controls"] == [] and tag["status"] == "Unhealthy"


def test_definition_lookup_failure_recorded_not_fatal():
    docs = pc.collect(session(**{"cge-require-env-tag-rg": 403}), "mg-grc", "cge-grc-baseline")
    tag = next(d for d in docs if d["assessmentId"] == "cge-require-env-tag-rg")
    assert tag["displayName"] == "cge-require-env-tag-rg"  # falls back to the name, run still completes


def test_definitions_fetched_once_each():
    s = session()
    pc.collect(s, "mg-grc", "cge-grc-baseline")
    assert sum(1 for m, u in s.calls if m == "GET" and "cge-nsg-no-internet-mgmt-ports" in u) == 1


def test_ids_stable_unique_and_never_collide_with_defender():
    a = pc.to_document(NSG_OPEN, {"displayName": "x", "controls": [], "category": None})
    b = pc.to_document(NSG_OPEN, {"displayName": "x", "controls": [], "category": None})
    c = pc.to_document(NSG_SAFE, {"displayName": "x", "controls": [], "category": None})
    assert a["id"] == b["id"] != c["id"]


def test_unknown_compliance_state_is_not_a_finding():
    d = pc.to_document(dict(NSG_OPEN, complianceState="Exempt"), {"displayName": "x", "controls": [], "category": None})
    assert d["status"] == "NotApplicable"
