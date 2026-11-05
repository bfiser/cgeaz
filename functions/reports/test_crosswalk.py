"""Unit tests for the framework crosswalk. Run: python -m pytest -q"""

import crosswalk as cw

MAPPINGS = [
    {"frameworkId": cw.NIST_80053, "sourceKey": "cge-storage-min-tls12", "controls": ["SC-8", "SC-8(1)"]},
    {"frameworkId": cw.CSF_2, "sourceKey": "cge-storage-min-tls12", "controls": ["PR.DS-02"]},
    {"frameworkId": cw.NIST_80053, "sourceKey": "cge-nsg-no-internet-mgmt-ports", "controls": ["SC-7", "AC-17"]},
    {"frameworkId": cw.CSF_2, "sourceKey": "cge-nsg-no-internet-mgmt-ports", "controls": ["PR.IR-01"]},
]
IDX = cw.index(MAPPINGS)


def test_resolve_policy_finding_through_the_store():
    d = {"assessmentId": "cge-storage-min-tls12", "source": "azurePolicy"}
    assert cw.resolve(d, IDX, cw.NIST_80053) == ["SC-8", "SC-8(1)"]
    assert cw.resolve(d, IDX, cw.CSF_2) == ["PR.DS-02"]


def test_unmapped_finding_resolves_to_empty_not_error():
    assert cw.resolve({"assessmentId": "some-defender-guid"}, IDX, cw.NIST_80053) == []
    assert cw.resolve({}, IDX, cw.CSF_2) == []


def test_family_and_function():
    assert cw.family("SC-8(1)") == "SC" and cw.family("AC-17") == "AC"
    assert cw.csf_function("PR.DS-02") == "PR"


def test_summary_counts_once_per_family_and_reports_unmapped():
    docs = [
        {"assessmentId": "cge-storage-min-tls12"},           # SC-8 + SC-8(1): SC counted ONCE
        {"assessmentId": "cge-nsg-no-internet-mgmt-ports"},  # SC + AC
        {"assessmentId": "defender-guid"},                   # unmapped, still counted
    ]
    s = cw.summarize(docs, IDX)
    assert s["mapped"] == 2 and s["unmapped"] == 1
    assert s["by80053Family"] == {"AC": 1, "SC": 2}
    assert s["byCsfFunction"] == {"PR": 2}


def test_empty_store_means_everything_unmapped():
    s = cw.summarize([{"assessmentId": "cge-storage-min-tls12"}], cw.index([]))
    assert s == {"mapped": 0, "unmapped": 1, "by80053Family": {}, "byCsfFunction": {}}
