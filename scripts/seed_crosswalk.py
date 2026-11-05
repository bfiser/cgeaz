#!/usr/bin/env python3
"""Seed the framework crosswalk (mappings container) from the policy definitions' own metadata.

Collect once: every custom/taught policy (cge-*) already declares its 800-53 controls and CSF 2.0
subcategories in Terraform (metadata.nist_800_53 / metadata.csf_2_0). This script reads those
definitions AS DEPLOYED in Azure and writes them into the evidence store as data:

  mappings   one document per (framework, policy):  800-53 controls, CSF 2.0 subcategories
  frameworks the 800-53 Rev. 5 family catalog (CSF 2.0 is seeded by labs/04-evidence)

Reports then resolve controls through `mappings` (functions/reports/crosswalk.py). Re-running is
safe: deterministic IDs + upsert. Authenticates as YOU (az login; the deployer's Cosmos data role
comes from stage 03). DRY RUN by default; pass --apply to write.

Usage:
  az policy definition list --management-group mg-grc-sandbox -o json > /tmp/defs.json
  export COSMOS_ENDPOINT=$(terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint)
  python scripts/seed_crosswalk.py /tmp/defs.json            # show what would be written
  python scripts/seed_crosswalk.py /tmp/defs.json --apply    # write it
"""

import argparse
import datetime
import json
import os
import sys

NIST_80053 = "nist-800-53-r5"
CSF_2 = "nist-csf-2.0"

# NIST SP 800-53 Rev. 5 control families.
FAMILIES_80053 = {
    "AC": "Access Control", "AT": "Awareness and Training", "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring", "CM": "Configuration Management",
    "CP": "Contingency Planning", "IA": "Identification and Authentication", "IR": "Incident Response",
    "MA": "Maintenance", "MP": "Media Protection", "PE": "Physical and Environmental Protection",
    "PL": "Planning", "PM": "Program Management", "PS": "Personnel Security",
    "PT": "PII Processing and Transparency", "RA": "Risk Assessment", "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection", "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


def _meta(defn):
    props = defn.get("properties", defn)  # az returns properties flattened; ARM nests them
    return props.get("metadata") or defn.get("metadata") or {}


def mapping_docs(definitions, seeded_at):
    """Two mapping documents per cge-* policy that declares controls. Pure: unit-tested."""
    docs = []
    for d in definitions:
        name = d.get("name", "")
        if not name.startswith("cge-"):
            continue
        meta = _meta(d)
        for framework, key in ((NIST_80053, "nist_800_53"), (CSF_2, "csf_2_0")):
            controls = list(meta.get(key) or [])
            if not controls:
                continue
            docs.append({
                "id": f"{framework}|{name}",        # deterministic: re-running upserts, never duplicates
                "frameworkId": framework,           # partition key
                "type": "mapping",
                "source": "azurePolicy",
                "sourceKey": name,                  # = assessmentId on the policy findings
                "controls": controls,
                "derivedFrom": d.get("id"),         # provenance: the definition the mapping came from
                "seededAt": seeded_at,
            })
    return docs


def catalog_doc(seeded_at):
    return {"id": NIST_80053, "frameworkId": NIST_80053, "type": "framework",
            "name": "NIST SP 800-53 Rev. 5", "families": FAMILIES_80053, "seededAt": seeded_at}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("definitions_json", help="output of: az policy definition list --management-group ... -o json")
    ap.add_argument("--apply", action="store_true", help="write to Cosmos (default: dry run)")
    args = ap.parse_args()

    with open(args.definitions_json) as f:
        definitions = json.load(f)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    docs = mapping_docs(definitions, now)
    unmapped = sorted(d["name"] for d in definitions
                      if d.get("name", "").startswith("cge-") and not any(x["sourceKey"] == d["name"] for x in docs))

    for d in docs:
        print(f"{d['frameworkId']:16} {d['sourceKey']:36} {', '.join(d['controls'])}")
    print(f"\n{len(docs)} mapping documents from {len({d['sourceKey'] for d in docs})} policies;"
          f" cge-* policies without control metadata: {unmapped or 'none'}")

    if not args.apply:
        print("DRY RUN: nothing written (pass --apply)")
        return 0

    from azure.cosmos import CosmosClient
    from azure.identity import DefaultAzureCredential

    db = CosmosClient(os.environ["COSMOS_ENDPOINT"], DefaultAzureCredential()).get_database_client(
        os.environ.get("COSMOS_DATABASE", "grc"))
    for d in docs:
        db.get_container_client("mappings").upsert_item(d)
    db.get_container_client("frameworks").upsert_item(catalog_doc(now))
    print(f"written: {len(docs)} mappings + 1 framework catalog ({NIST_80053})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
