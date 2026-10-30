"""CGE-AZ pipeline — Stage 3 collector.

Timer fires nightly -> managed identity -> Defender assessments API -> Cosmos.
One document per assessment per run, upserted on a deterministic ID so re-runs
refresh instead of duplicate. Deliberately boring: if you can read this file,
you can defend this pipeline's data lineage.
"""

import datetime
import hashlib
import json
import logging
import os
import uuid

import azure.functions as func
import requests
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential

import lifecycle  # finding lifecycle + ownership (unit-tested separately)
import role_collector  # role-assignment snapshot logic (unit-tested separately)

app = func.FunctionApp()

ARM = "https://management.azure.com"
API_VERSION = "2021-06-01"


def _collect() -> dict:
    subscription_id = os.environ["SUBSCRIPTION_ID"]
    cosmos_endpoint = os.environ["COSMOS_ENDPOINT"]
    database = os.environ["COSMOS_DATABASE"]

    # DefaultAzureCredential resolves to the Function App's managed identity in Azure
    # (and to your `az login` session when run locally). No keys, anywhere.
    credential = DefaultAzureCredential()
    token = credential.get_token(f"{ARM}/.default").token

    run_id = str(uuid.uuid4())
    collected_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    container = (
        CosmosClient(cosmos_endpoint, credential)
        .get_database_client(database)
        .get_container_client("assessments")
    )

    headers = {"Authorization": f"Bearer {token}"}

    # Owners: one call per run. Each resource group's `owner` tag (Security Reader includes
    # resourceGroups/read). The reporter can't look this up itself: it has no access to Azure.
    rg_resp = requests.get(
        f"{ARM}/subscriptions/{subscription_id}/resourcegroups?api-version=2021-04-01",
        headers=headers, timeout=60,
    )
    rg_resp.raise_for_status()
    rg_owners = {
        rg["name"].lower(): (rg.get("tags") or {}).get("owner")
        for rg in rg_resp.json().get("value", [])
    }

    # Yesterday's lifecycle fields, in one query (not one read per finding).
    previous = {
        d["id"]: d
        for d in container.query_items(
            "SELECT c.id, c.status, c.firstUnhealthyAt, c.firstDetectedSource, c.resolvedAt "
            "FROM c WHERE c.subscriptionId = @sub",
            parameters=[{"name": "@sub", "value": subscription_id}],
            partition_key=subscription_id,
        )
    }

    url = (
        f"{ARM}/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Security/assessments?api-version={API_VERSION}"
    )
    written = 0
    while url:
        resp = requests.get(url, headers=headers, timeout=60)
        resp.raise_for_status()
        payload = resp.json()

        for assessment in payload.get("value", []):
            props = assessment.get("properties", {})
            resource_id = (
                props.get("resourceDetails", {}).get("Id")
                or props.get("resourceDetails", {}).get("id", "")
            )
            # Deterministic ID: same assessment+resource upserts, never duplicates.
            doc_id = hashlib.sha256(
                f"{assessment['name']}|{resource_id}".encode()
            ).hexdigest()[:32]

            status = props.get("status", {}).get("code")

            container.upsert_item(
                {
                    "id": doc_id,
                    "subscriptionId": subscription_id,
                    "assessmentId": assessment["name"],
                    "displayName": props.get("displayName"),
                    "status": status,
                    "statusCause": props.get("status", {}).get("cause"),
                    "severity": props.get("metadata", {}).get("severity"),
                    "categories": props.get("metadata", {}).get("categories"),
                    "resourceId": resource_id,
                    "resourceGroup": lifecycle.resource_group_of(resource_id),
                    "owner": lifecycle.owner_for(resource_id, rg_owners),
                    # firstUnhealthyAt / firstDetectedSource / resolvedAt: carried forward from
                    # the stored document so aging survives the daily overwrite (CA-5).
                    **lifecycle.lifecycle(previous.get(doc_id), status, collected_at),
                    "collectedAt": collected_at,
                    "runId": run_id,
                }
            )
            written += 1

        url = payload.get("nextLink")

    logging.info("collection run %s complete: %d documents", run_id, written)
    return {"runId": run_id, "written": written, "collectedAt": collected_at}


@app.timer_trigger(schedule="0 0 5 * * *", arg_name="timer", run_on_startup=False)
def collect_nightly(timer: func.TimerRequest) -> None:
    """Nightly sweep at 05:00 UTC — midnight-ish US Eastern."""
    _collect()


@app.route(route="collect", auth_level=func.AuthLevel.FUNCTION)
def collect_now(req: func.HttpRequest) -> func.HttpResponse:
    """Manual trigger for labs and demos: hit the endpoint, get the run summary."""
    result = _collect()
    return func.HttpResponse(
        f"run {result['runId']}: {result['written']} documents at {result['collectedAt']}\n",
        status_code=200,
    )


# --- Role-assignment snapshots (federal track: AC-2, AC-2(3), AC-6) ---
# The logic lives in role_collector.py (pure functions, unit-tested with fake HTTP
# responses). This section only wires it to a timer, an HTTP trigger, and Cosmos.


def _collect_role_assignments() -> dict:
    cosmos_endpoint = os.environ["COSMOS_ENDPOINT"]
    database = os.environ["COSMOS_DATABASE"]
    root_mg = os.environ["ROOT_MANAGEMENT_GROUP"]  # from Terraform (stage 01 output), never hardcoded

    # Same managed identity as the assessment collector. No keys anywhere.
    credential = DefaultAzureCredential()
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {credential.get_token(f'{ARM}/.default').token}"

    docs, summary = role_collector.snapshot(session, root_mg)

    container = (
        CosmosClient(cosmos_endpoint, credential)
        .get_database_client(database)
        .get_container_client("roleAssignments")
    )
    for doc in docs:
        container.upsert_item(doc)  # deterministic daily ID: re-runs refresh, never duplicate
    return summary


@app.timer_trigger(schedule="0 15 5 * * *", arg_name="timer", run_on_startup=False)
def collect_role_assignments_nightly(timer: func.TimerRequest) -> None:
    """Daily at 05:15 UTC, after the 05:00 assessment sweep."""
    _collect_role_assignments()


@app.route(route="collect-roles", auth_level=func.AuthLevel.FUNCTION)
def collect_role_assignments_now(req: func.HttpRequest) -> func.HttpResponse:
    """Manual trigger: run a snapshot now and return the summary as JSON."""
    summary = _collect_role_assignments()
    return func.HttpResponse(json.dumps(summary, indent=2) + "\n", status_code=200, mimetype="application/json")
