"""Azure Policy findings for the evidence store: pure functions + one I/O entry point.

Turns policy states from the cge-grc-baseline initiative into documents shaped like the
Defender assessment documents, so the existing lifecycle, owner, and POA&M logic applies
to them unchanged. Unit-tested with fake HTTP responses (test_policy_collector.py).
"""

import hashlib

ARM = "https://management.azure.com"
STATES_API = "2019-10-01"
DEFINITIONS_API = "2023-04-01"

# Map policy compliance onto the Defender status vocabulary the lifecycle logic expects.
STATUS = {"NonCompliant": "Unhealthy", "Compliant": "Healthy"}


def query_states(session, root_mg_name, initiative):
    """All policy states for one initiative across the whole hierarchy (one MG-scope query,
    paged). Covers every subscription under the root: nothing per-subscription is hardcoded."""
    url = (f"{ARM}/providers/Microsoft.Management/managementGroups/{root_mg_name}"
           f"/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
           f"?api-version={STATES_API}&$filter=policySetDefinitionName eq '{initiative}'")
    states = []
    while url:
        resp = session.post(url, timeout=60)  # the query API is a POST, even though it only reads
        resp.raise_for_status()
        payload = resp.json()
        states.extend(payload.get("value", []))
        url = payload.get("@odata.nextLink")
    return states


def definition_info(session, definition_id, cache):
    """Display name, 800-53 controls, and category from the policy definition's own metadata,
    once per definition per run. A lookup failure is recorded, not fatal."""
    key = definition_id.lower()
    if key not in cache:
        try:
            resp = session.get(f"{ARM}{definition_id}?api-version={DEFINITIONS_API}", timeout=30)
            resp.raise_for_status()
            props = resp.json().get("properties", {})
            meta = props.get("metadata") or {}
            cache[key] = {
                "displayName": props.get("displayName") or definition_id.split("/")[-1],
                "controls": meta.get("nist_800_53") or [],
                "category": meta.get("category"),
            }
        except Exception:  # noqa: BLE001 - one bad lookup must not lose the whole run's evidence
            cache[key] = {"displayName": definition_id.split("/")[-1], "controls": [], "category": None}
    return cache[key]


def to_document(state, info):
    """One evidence document per (policy definition, resource). Same core fields as a Defender
    assessment document; `source` says which assessment produced it (CA-7)."""
    definition_name = state.get("policyDefinitionName", "")
    resource_id = state.get("resourceId", "")
    # Deterministic ID with a "policy|" prefix: can never collide with a Defender document's ID.
    doc_id = hashlib.sha256(f"policy|{definition_name}|{resource_id.lower()}".encode()).hexdigest()[:32]
    return {
        "id": doc_id,
        "subscriptionId": state.get("subscriptionId"),
        "source": "azurePolicy",
        "assessmentId": definition_name,
        "displayName": info["displayName"],
        "status": STATUS.get(state.get("complianceState"), "NotApplicable"),
        "statusCause": state.get("complianceState"),
        "severity": "Medium",  # custom policies carry no severity; Medium = 90-day SLA, same as Defender's findings here
        "categories": [info["category"]] if info.get("category") else [],
        "controls": info["controls"],
        "resourceId": resource_id,
        "policyAssignmentId": state.get("policyAssignmentId"),
        "policyEvaluatedAt": state.get("timestamp"),
    }


def collect(session, root_mg_name, initiative):
    """States -> documents (lifecycle/owner/run fields are added by the caller, like Defender docs)."""
    cache = {}
    return [to_document(s, definition_info(session, s["policyDefinitionId"], cache))
            for s in query_states(session, root_mg_name, initiative)]
