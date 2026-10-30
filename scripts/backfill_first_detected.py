"""One-time backfill: set firstUnhealthyAt on open findings from the WORM POA&M history.

Why: before 2026-10-30 the collector overwrote each finding daily, so Cosmos did not
remember when a finding first appeared. The immutable daily POA&Ms (since 2026-10-21) do.
For each finding that is open today, walk back through consecutive POA&Ms while it is
present; the earliest report in that unbroken streak is when we first knew about it.

Provenance is recorded: firstDetectedSource = "backfill:poam-YYYY-MM-DD", so nobody can
mistake a backfilled date for one the collector observed itself.

Read: reports container (WORM) + assessments container. Write: assessments only.
Authenticates as YOU (az login). DRY RUN by default; pass --apply to write.

Usage:
  export COSMOS_ENDPOINT=$(terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint)
  export REPORTS_ACCOUNT=$(terraform -chdir=stages/03-evidence-store output -raw evidence_storage_account)
  python scripts/backfill_first_detected.py            # show the plan
  python scripts/backfill_first_detected.py --apply    # write it
"""

import argparse
import json
import os
import re

POAM_NAME = re.compile(r"poam-(\d{4}-\d{2}-\d{2})\.json$")


def finding_key(weakness, resource_id):
    """How a POA&M item is matched to an evidence document: weakness text + resource (case-insensitive)."""
    return ((weakness or "").strip(), (resource_id or "").lower())


def streak_starts(reports):
    """reports: list of (date, collectedAt, set_of_keys) sorted oldest -> newest.
    Returns {key: (date, collectedAt)} for every key in the NEWEST report, giving the
    earliest report of its current unbroken streak. A gap (finding absent from a report)
    ends the streak, so a finding that was fixed and came back gets its newer date."""
    if not reports:
        return {}
    starts = {}
    newest_keys = reports[-1][2]
    for key in newest_keys:
        start = reports[-1]
        for report in reversed(reports[:-1]):
            if key in report[2]:
                start = report
            else:
                break
        starts[key] = (start[0], start[1])
    return starts


def needs_backfill(doc):
    """Open findings with no clock, or whose clock was only started by the new collector
    because the backfill hadn't run yet."""
    return doc.get("status") == "Unhealthy" and (
        not doc.get("firstUnhealthyAt") or doc.get("firstDetectedSource") == "collector-first-seen"
    )


def main():
    from azure.cosmos import CosmosClient
    from azure.identity import AzureCliCredential
    from azure.storage.blob import BlobServiceClient

    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="write changes (default: dry run)")
    args = parser.parse_args()

    cred = AzureCliCredential()
    reports_container = BlobServiceClient(
        f"https://{os.environ['REPORTS_ACCOUNT']}.blob.core.windows.net", credential=cred
    ).get_container_client("reports")
    assessments = (
        CosmosClient(os.environ["COSMOS_ENDPOINT"], cred)
        .get_database_client("grc")
        .get_container_client("assessments")
    )

    # 1. Read the immutable history, oldest first.
    reports = []
    for blob in reports_container.list_blobs(name_starts_with="poam/"):
        match = POAM_NAME.search(blob.name)
        if not match:
            continue
        data = json.loads(reports_container.download_blob(blob.name).readall())
        keys = {finding_key(i.get("weakness"), i.get("resourceId")) for i in data.get("items", [])}
        reports.append((match.group(1), data.get("collectedAt"), keys))
    reports.sort(key=lambda r: r[0])
    print(f"Read {len(reports)} POA&M reports: {reports[0][0]} .. {reports[-1][0]}")
    starts = streak_starts(reports)

    # 2. Match open findings in the evidence store to their streak start.
    docs = list(assessments.query_items("SELECT * FROM c WHERE c.status = 'Unhealthy'",
                                        enable_cross_partition_query=True))
    planned, unmatched = [], 0
    for doc in docs:
        if not needs_backfill(doc):
            continue
        hit = starts.get(finding_key(doc.get("displayName"), doc.get("resourceId")))
        if not hit:
            unmatched += 1  # newer than the latest report: the collector's own clock is correct
            continue
        planned.append((doc, hit))

    for doc, (date, collected_at) in sorted(planned, key=lambda p: p[1][0]):
        print(f"  {date}  {doc.get('displayName')[:60]:<60}  {(doc.get('resourceId') or '').split('/')[-1]}")
    print(f"\n{len(planned)} to backfill, {unmatched} open finding(s) not in history (left as-is), "
          f"{len(docs)} open in total.")

    if not args.apply:
        print("DRY RUN: nothing written. Re-run with --apply to write.")
        return
    for doc, (date, collected_at) in planned:
        doc.update(firstUnhealthyAt=collected_at, firstDetectedSource=f"backfill:poam-{date}")
        for k in [k for k in doc if k.startswith("_")]:
            doc.pop(k)  # drop Cosmos system fields before writing back
        assessments.upsert_item(doc)
    print(f"Wrote {len(planned)} document(s).")


if __name__ == "__main__":
    main()
