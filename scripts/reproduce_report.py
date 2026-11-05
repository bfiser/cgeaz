#!/usr/bin/env python3
"""Reproduce every number in a POA&M from the evidence store, independently of the reporter.

Rubric: "reports read from the store ONLY - any report number reproducible by a stored query."
This script takes a POA&M exactly as it was written to the WORM reports container, re-runs the
stored queries below against Cosmos for the SAME collection run (runId), recomputes each summary
number with its own arithmetic (it does not import the reporter's code), and compares. Read-only.

Every query is listed in QUERIES and printed with --show-queries, so anyone can run them by hand
(Cosmos Data Explorer) and get the same numbers. Documented in docs/REPORT-QUERIES.md.

Limit (by design, documented): the assessments container holds the LATEST state per finding
(one document per assessment x resource, overwritten each sweep). A report can be reproduced while
its runId is still the latest collection run, i.e. on the day it was generated. Older reports are
preserved as immutable WORM artifacts (they carry runId + every item), not re-derivable from Cosmos.

Usage (az login; read-only on Cosmos and the reports container):
  export COSMOS_ENDPOINT=$(terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint)
  export REPORTS_ACCOUNT=$(terraform -chdir=stages/03-evidence-store output -raw evidence_storage_account)
  python scripts/reproduce_report.py                 # newest POA&M in the reports container
  python scripts/reproduce_report.py poam/2026/11/poam-2026-11-05.json
  python scripts/reproduce_report.py --show-queries  # print the stored queries and exit
"""

import argparse
import datetime
import json
import os
import sys

# The stored queries. @run = the report's runId; @since = report date - 30 days.
QUERIES = {
    "open_findings": (
        "SELECT c.id, c.source, c.owner, c.severity, c.firstUnhealthyAt, c.collectedAt, c.assessmentId "
        "FROM c WHERE c.runId = @run AND c.status = 'Unhealthy'"),
    "open_count": "SELECT VALUE COUNT(1) FROM c WHERE c.runId = @run AND c.status = 'Unhealthy'",
    "closed_recently": (
        "SELECT VALUE COUNT(1) FROM c WHERE c.status != 'Unhealthy' AND IS_DEFINED(c.resolvedAt) "
        "AND NOT IS_NULL(c.resolvedAt) AND c.resolvedAt >= @since"),
    "mappings": "SELECT c.frameworkId, c.sourceKey, c.controls FROM c WHERE c.type = 'mapping'",
}

# Policy, restated here on purpose (not imported from the reporter): an independent recomputation.
SLA_DAYS = {"High": 30, "Medium": 90, "Low": 180}
CLOSED_LOOKBACK_DAYS = 30


def _d(iso):
    return datetime.date.fromisoformat(iso[:10]) if iso else None


def recompute(open_docs, mapping_docs, closed_count, report_date):
    """Summary numbers from raw query results. Pure: unit-tested against the reporter's output."""
    xw = {}
    for m in mapping_docs:
        xw.setdefault(m["sourceKey"], {})[m["frameworkId"]] = m.get("controls") or []

    by_source, families, functions = {}, {}, {}
    overdue = unassigned = mapped = 0
    oldest = 0
    for d in open_docs:
        src = d.get("source") or "defender"
        by_source[src] = by_source.get(src, 0) + 1
        if not d.get("owner") or d.get("owner") == "UNASSIGNED":
            unassigned += 1
        first = _d(d.get("firstUnhealthyAt")) or _d(d.get("collectedAt")) or report_date
        age = (report_date - first).days
        oldest = max(oldest, age)
        if age > SLA_DAYS.get(d.get("severity") or "Medium", 90):
            overdue += 1
        m = xw.get(d.get("assessmentId") or "", {})
        controls, csf = m.get("nist-800-53-r5", []), m.get("nist-csf-2.0", [])
        if controls or csf:
            mapped += 1
        for fam in {c.split("-")[0] for c in controls}:
            families[fam] = families.get(fam, 0) + 1
        for fn in {c.split(".")[0] for c in csf}:
            functions[fn] = functions.get(fn, 0) + 1

    return {
        "open": len(open_docs),
        "overdue": overdue,
        "unassigned": unassigned,
        "closedRecently": closed_count,
        "oldestOpenDays": oldest,
        "openBySource": dict(sorted(by_source.items())),
        "byFramework": {
            "mapped": mapped,
            "unmapped": len(open_docs) - mapped,
            "by80053Family": dict(sorted(families.items())),
            "byCsfFunction": dict(sorted(functions.items())),
        },
    }


def compare(reported, recomputed):
    """[(metric, reported, recomputed, ok)] for every key in the recomputation."""
    return [(k, reported.get(k), v, reported.get(k) == v) for k, v in recomputed.items()]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report", nargs="?", help="POA&M JSON path in the reports container (default: newest)")
    ap.add_argument("--show-queries", action="store_true")
    args = ap.parse_args()
    if args.show_queries:
        for name, q in QUERIES.items():
            print(f"-- {name}\n{q}\n")
        return 0

    from azure.cosmos import CosmosClient
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient

    cred = DefaultAzureCredential()
    blobs = BlobServiceClient(f"https://{os.environ['REPORTS_ACCOUNT']}.blob.core.windows.net", cred) \
        .get_container_client(os.environ.get("REPORTS_CONTAINER", "reports"))
    path = args.report or max((b for b in blobs.list_blobs(name_starts_with="poam/") if b.name.endswith(".json")),
                              key=lambda b: b.creation_time).name
    report = json.loads(blobs.download_blob(path).readall())
    run_id = report["runId"]
    report_date = _d(report["generatedAt"])
    since = (datetime.datetime.fromisoformat(report["generatedAt"])
             - datetime.timedelta(days=CLOSED_LOOKBACK_DAYS)).isoformat()

    db = CosmosClient(os.environ["COSMOS_ENDPOINT"], cred).get_database_client(os.environ.get("COSMOS_DATABASE", "grc"))
    assessments, mappings = db.get_container_client("assessments"), db.get_container_client("mappings")

    def q(container, name, **params):
        return list(container.query_items(QUERIES[name], enable_cross_partition_query=True,
                                          parameters=[{"name": f"@{k}", "value": v} for k, v in params.items()]))

    open_docs = q(assessments, "open_findings", run=run_id)
    open_count = q(assessments, "open_count", run=run_id)[0]
    closed = q(assessments, "closed_recently", since=since)[0]
    result = recompute(open_docs, q(mappings, "mappings"), closed, report_date)

    print(f"Report:  reports/{path}")
    print(f"runId:   {run_id}   generatedAt: {report['generatedAt']}")
    print(f"Cross-check: COUNT query = {open_count}, rows returned = {len(open_docs)}"
          f" -> {'OK' if open_count == len(open_docs) else 'MISMATCH'}\n")
    rows = compare(report["summary"], result)
    print(f"{'metric':16} {'match':6} reported -> recomputed from the store")
    for k, rep, rec, ok in rows:
        print(f"{k:16} {'PASS' if ok else 'FAIL':6} {json.dumps(rep)} -> {json.dumps(rec)}")
    ok = all(r[3] for r in rows) and open_count == len(open_docs)
    print(f"\n{'ALL NUMBERS REPRODUCED' if ok else 'NOT REPRODUCED (see FAIL rows; is the runId still the latest run?)'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
