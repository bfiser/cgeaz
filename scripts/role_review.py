"""Access-review helper: read today's role-assignment snapshot from the evidence store.

Read-only. Authenticates as YOU (az login); Cosmos key auth is disabled on purpose.
Usage:  python scripts/role_review.py [--mg-only] [--date YYYY-MM-DD]
"""

import argparse
import datetime
import os

from azure.cosmos import CosmosClient
from azure.identity import AzureCliCredential

parser = argparse.ArgumentParser()
parser.add_argument("--mg-only", action="store_true", help="only management-group-scope grants")
parser.add_argument("--date", default=datetime.date.today().isoformat())
args = parser.parse_args()

endpoint = os.environ["COSMOS_ENDPOINT"]  # from: terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint
container = (
    CosmosClient(endpoint, AzureCliCredential())
    .get_database_client("grc")
    .get_container_client("roleAssignments")
)

query = "SELECT c.scopeLevel, c.scope, c.principalId, c.principalType, c.roleName, c.privileged FROM c WHERE c.snapshotDate = @d"
if args.mg_only:
    query += " AND c.scopeLevel = 'managementGroup'"

rows = list(container.query_items(query, parameters=[{"name": "@d", "value": args.date}],
                                  enable_cross_partition_query=True))  # MG grants and subscriptions live in different partitions
for r in sorted(rows, key=lambda r: (r["scopeLevel"], r["scope"], r["roleName"])):
    flag = "PRIVILEGED" if r["privileged"] else ""
    print(f"{r['scopeLevel']:<16} {r['roleName']:<35} {r['principalType'] or '?':<17} {r['principalId'][:8]}  "
          f"{r['scope'].split('/')[-1]:<20} {flag}")
print(f"\n{len(rows)} assignment(s) on {args.date}")