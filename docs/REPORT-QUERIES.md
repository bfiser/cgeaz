# Report numbers → stored queries

Every number in a report is computed from documents in the evidence store (Cosmos DB), never from
live Azure APIs. This page lists, for each number, the stored query that produces it and the
arithmetic applied to the result. `scripts/reproduce_report.py` re-runs these queries for a report's
`runId`, recomputes every number **independently** (it does not import the reporter's code), and
compares them with the report as it was written to the immutable `reports` container.

```bash
export COSMOS_ENDPOINT=$(terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint)
export REPORTS_ACCOUNT=$(terraform -chdir=stages/03-evidence-store output -raw evidence_storage_account)
python scripts/reproduce_report.py                  # newest POA&M; prints PASS/FAIL per number
python scripts/reproduce_report.py --show-queries   # the queries, to run by hand in Data Explorer
```

## Pinning: which data a report describes

| Report field | Query | Container |
|---|---|---|
| `runId`, `collectedAt` | `SELECT TOP 1 c.runId, c.collectedAt FROM c ORDER BY c.collectedAt DESC` | assessments |

A report is a statement about **one collection sweep** (`runId`), recorded in the report itself.

## POA&M summary (`poam/YYYY/MM/poam-*.json` → `summary`)

| Number | Stored query (`@run` = report `runId`) | Arithmetic |
|---|---|---|
| `open` | `SELECT VALUE COUNT(1) FROM c WHERE c.runId = @run AND c.status = 'Unhealthy'` | the count (cross-checked against the rows of the next query) |
| `openBySource` | `SELECT c.id, c.source, c.owner, c.severity, c.firstUnhealthyAt, c.collectedAt, c.assessmentId FROM c WHERE c.runId = @run AND c.status = 'Unhealthy'` | count rows per `source` (missing → `defender`) |
| `unassigned` | same rows | rows where `owner` is missing or `UNASSIGNED` |
| `oldestOpenDays` | same rows | max(report date − `firstUnhealthyAt` date) |
| `overdue` | same rows | rows where (report date − `firstUnhealthyAt`) > SLA for `severity` (High 30, Medium 90, Low 180 days) |
| `closedRecently` | `SELECT VALUE COUNT(1) FROM c WHERE c.status != 'Unhealthy' AND IS_DEFINED(c.resolvedAt) AND NOT IS_NULL(c.resolvedAt) AND c.resolvedAt >= @since` (`@since` = report time − 30 days) | the count |
| `byFramework.*` | open rows above **+** `SELECT c.frameworkId, c.sourceKey, c.controls FROM c WHERE c.type = 'mapping'` (mappings container) | join `assessmentId` = `sourceKey`; a finding with any mapping is `mapped`, else `unmapped`; per 800-53 family (`SC-8(1)` → `SC`) and CSF 2.0 function (`PR.DS-02` → `PR`) a finding counts once |

Each POA&M **row** also carries `lastSeenRun` (the `runId`) and its `poamId` is derived from the
evidence document's `id` (`POAM-` + first 12 characters), so any row traces to exactly one document:
`SELECT * FROM c WHERE STARTSWITH(c.id, '<12 chars, lowercase>')`.

## SAR (`sar/YYYY/MM/sar-*.md`)

| Number | Source |
|---|---|
| Open findings, by severity | the `open_findings` rows; count per `severity` |
| By framework | same as `byFramework` above |
| Each finding's controls | the mapping documents for its `assessmentId` |

## Known limit (by design)

The `assessments` container holds the **latest** state of each finding (one document per
assessment × resource, updated each sweep; lifecycle fields carry history forward). So a report is
re-derivable from Cosmos while its `runId` is still the latest collection run, i.e. on the day it was
generated. Older reports are preserved as **immutable WORM artifacts** that carry their `runId` and
every item; they are the record of what was known at that time. Roadmap: append-only snapshots per
run (or Cosmos continuous backup / point-in-time restore) to re-derive any historical report.
