"""CGE-AZ pipeline — Stage 4 report generators.

Reports read from Cosmos ONLY — never from live services. Every number in every
artifact resolves to a stored, timestamped document. A report that reads live data
is a report whose numbers can't be reproduced tomorrow; a report that reads the
store is a fact with a receipt.

Generators here: POA&M (xlsx + json, daily) and SAR (markdown, weekly), both with
HTTP triggers for labs and demos.

POA&M lifecycle (2026-10-30): rows now come from poam.py, which uses the lifecycle
facts the collector records (firstUnhealthyAt, resolvedAt, owner). Stable IDs,
deadlines from first detection (so they can actually pass), days open, overdue,
owners, and recently closed items. The reporter is still read-only on Cosmos.
"""

import datetime
import io
import json
import logging
import os
from collections import Counter

import azure.functions as func
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from openpyxl import Workbook

import poam  # POA&M row logic (unit-tested separately)

app = func.FunctionApp()

# Closed findings stay on the POA&M for this long, so closures are visible, not silent.
CLOSED_LOOKBACK_DAYS = 30


def _clients():
    credential = DefaultAzureCredential()
    cosmos = (
        CosmosClient(os.environ["COSMOS_ENDPOINT"], credential)
        .get_database_client(os.environ["COSMOS_DATABASE"])
        .get_container_client("assessments")
    )
    blobs = BlobServiceClient(
        account_url=os.environ["REPORTS_ACCOUNT_URL"], credential=credential
    ).get_container_client(os.environ["REPORTS_CONTAINER"])
    return cosmos, blobs


def _latest_run(cosmos):
    """Pin the report to a specific collection sweep — a statement about a known moment."""
    rows = list(
        cosmos.query_items(
            "SELECT TOP 1 c.runId, c.collectedAt FROM c ORDER BY c.collectedAt DESC",
            enable_cross_partition_query=True,
        )
    )
    return (rows[0]["runId"], rows[0]["collectedAt"]) if rows else (None, None)


def _unhealthy(cosmos, run_id):
    return list(
        cosmos.query_items(
            "SELECT * FROM c WHERE c.runId = @run AND c.status = 'Unhealthy'",
            parameters=[{"name": "@run", "value": run_id}],
            enable_cross_partition_query=True,
        )
    )


def _closed_since(cosmos, since_iso):
    """Findings the collector marked resolved within the lookback window."""
    return list(
        cosmos.query_items(
            "SELECT * FROM c WHERE c.status != 'Unhealthy' AND IS_DEFINED(c.resolvedAt) "
            "AND NOT IS_NULL(c.resolvedAt) AND c.resolvedAt >= @since",
            parameters=[{"name": "@since", "value": since_iso}],
            enable_cross_partition_query=True,
        )
    )


def _paths(blobs, prefix, exts, now):
    """One stem for all formats of a report. Daily name, or time-suffixed if today's
    already exists (WORM: never replaced, so a same-day re-run gets its own file)."""
    stem = poam.report_path(prefix, exts[0], now, lambda p: blobs.get_blob_client(p).exists())
    stem = stem.rsplit(".", 1)[0]
    return {ext: f"{stem}.{ext}" for ext in exts}


def generate_poam() -> dict:
    cosmos, blobs = _clients()
    now = datetime.datetime.now(datetime.timezone.utc)
    today = now.date()
    run_id, collected_at = _latest_run(cosmos)
    findings = _unhealthy(cosmos, run_id) if run_id else []
    closed = _closed_since(cosmos, (now - datetime.timedelta(days=CLOSED_LOOKBACK_DAYS)).isoformat())
    rows, summary = poam.build(findings, closed, today)

    wb = Workbook()
    ws = wb.active
    ws.title = "POA&M"
    ws.append([label for _, label in poam.COLUMNS])
    for row in rows:
        ws.append([row[key] for key, _ in poam.COLUMNS])

    xlsx = io.BytesIO()
    wb.save(xlsx)
    paths = _paths(blobs, "poam", ["json", "xlsx"], now)
    blobs.upload_blob(paths["xlsx"], xlsx.getvalue(), overwrite=False)
    blobs.upload_blob(
        paths["json"],
        json.dumps({"runId": run_id, "collectedAt": collected_at, "generatedAt": now.isoformat(),
                    "summary": summary, "items": rows}, indent=2),
        overwrite=False,
    )
    logging.info("POA&M: %s -> %s", summary, paths["json"])
    return {"runId": run_id, "summary": summary, "xlsx": paths["xlsx"], "json": paths["json"]}


def generate_sar() -> dict:
    cosmos, blobs = _clients()
    run_id, collected_at = _latest_run(cosmos)
    findings = _unhealthy(cosmos, run_id) if run_id else []
    by_severity = Counter(f.get("severity") or "Unknown" for f in findings)

    lines = [
        "# Security Assessment Report (SAR)",
        "",
        f"- **Collection run:** `{run_id}`",
        f"- **Collected at:** {collected_at}",
        f"- **Open findings:** {len(findings)}",
        f"- **By severity:** " + (", ".join(f"{k}: {v}" for k, v in sorted(by_severity.items())) or "none"),
        "",
        "## Findings",
        "",
    ]
    for f in sorted(findings, key=lambda x: x.get("severity") or ""):
        lines += [
            f"### {f.get('displayName')}",
            f"- Severity: {f.get('severity')}",
            f"- Resource: `{f.get('resourceId')}`",
            f"- Assessment ID: `{f.get('assessmentId')}` (trace: query the assessments container)",
            "",
        ]

    path = _paths(blobs, "sar", ["md"], datetime.datetime.now(datetime.timezone.utc))["md"]
    blobs.upload_blob(path, "\n".join(lines), overwrite=False)
    logging.info("SAR: %d findings -> %s", len(findings), path)
    return {"findings": len(findings), "runId": run_id, "path": path}


@app.timer_trigger(schedule="0 0 6 * * *", arg_name="timer", run_on_startup=False)
def poam_daily(timer: func.TimerRequest) -> None:
    generate_poam()


@app.timer_trigger(schedule="0 0 7 * * 1", arg_name="timer", run_on_startup=False)
def sar_weekly(timer: func.TimerRequest) -> None:
    generate_sar()


@app.route(route="poam", auth_level=func.AuthLevel.FUNCTION)
def poam_now(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(generate_poam(), indent=2) + "\n", status_code=200)


@app.route(route="sar", auth_level=func.AuthLevel.FUNCTION)
def sar_now(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(generate_sar()) + "\n", status_code=200)
