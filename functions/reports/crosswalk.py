"""Framework crosswalk, read from the evidence store: pure functions, unit-tested (test_crosswalk.py).

The `mappings` container holds one document per (framework, assessment): which 800-53 controls
and which CSF 2.0 subcategories a given assessment provides evidence for. It is seeded from the
policy definitions' own metadata (scripts/seed_crosswalk.py), so the mapping is maintained in one
place (code) and collected once. Reports resolve controls through it instead of hardcoding them:
adding a framework is a data change, not a code change.

Findings with no mapping (Defender's built-in assessments today) are counted as "unmapped", never
silently dropped: the gap is visible in every report.
"""

from collections import Counter

NIST_80053 = "nist-800-53-r5"
CSF_2 = "nist-csf-2.0"

# The stored query the reporter runs (documented in docs/REPORT-QUERIES.md).
MAPPINGS_QUERY = "SELECT c.frameworkId, c.sourceKey, c.controls FROM c WHERE c.type = 'mapping'"


def index(mapping_docs):
    """{sourceKey: {frameworkId: [controls]}} from the mapping documents."""
    idx = {}
    for m in mapping_docs:
        idx.setdefault(m["sourceKey"], {})[m["frameworkId"]] = list(m.get("controls") or [])
    return idx


def resolve(doc, idx, framework):
    """Controls a finding maps to in one framework ([] if unmapped). The key is the assessment
    that produced the finding: for Azure Policy findings, the policy definition name."""
    return idx.get(doc.get("assessmentId") or "", {}).get(framework, [])


def family(control):
    """800-53 family: 'SC-8(1)' -> 'SC'."""
    return control.split("-")[0]


def csf_function(subcategory):
    """CSF 2.0 function: 'PR.DS-02' -> 'PR'."""
    return subcategory.split(".")[0]


def summarize(open_docs, idx):
    """Open findings per 800-53 family and per CSF 2.0 function. A finding counts once per family
    or function it maps to (so the per-family numbers can add up to more than the total)."""
    by_family, by_function = Counter(), Counter()
    mapped = 0
    for d in open_docs:
        controls = resolve(d, idx, NIST_80053)
        csf = resolve(d, idx, CSF_2)
        if controls or csf:
            mapped += 1
        by_family.update({family(c) for c in controls})
        by_function.update({csf_function(c) for c in csf})
    return {
        "mapped": mapped,
        "unmapped": len(open_docs) - mapped,
        "by80053Family": dict(sorted(by_family.items())),
        "byCsfFunction": dict(sorted(by_function.items())),
    }
