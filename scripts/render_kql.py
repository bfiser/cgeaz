"""Render a detection's KQL template for ad-hoc testing, with the same variables Terraform uses.

Terraform's templatefile() and Python's string.Template share the ${name} syntax, so the
query you test by hand is byte-for-byte the query the alert rule runs.
Usage: python scripts/render_kql.py stages/01-foundation/detections/<file>.kql <tenant-id>
"""
import string
import sys

path, tenant_id = sys.argv[1], sys.argv[2]
print(string.Template(open(path).read()).safe_substitute(
    timezone="America/New_York", start_hour="7", end_hour="19",
    home_issuer=f"https://sts.windows.net/{tenant_id}/",
))
