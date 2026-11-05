"""Unit tests for the crosswalk seed. Run: python -m pytest scripts -q"""

import seed_crosswalk as s

DEFS = [
    {"name": "cge-storage-min-tls12", "id": "/providers/.../cge-storage-min-tls12",
     "metadata": {"nist_800_53": ["SC-8", "SC-8(1)"], "csf_2_0": ["PR.DS-02"]}},
    {"name": "cge-no-metadata", "id": "/x", "metadata": {"category": "Tags"}},
    {"name": "some-builtin", "id": "/y", "metadata": {"nist_800_53": ["AC-1"]}},  # not ours: ignored
]


def test_two_docs_per_mapped_policy_with_provenance():
    docs = s.mapping_docs(DEFS, "2026-11-05T00:00:00Z")
    assert {(d["frameworkId"], d["sourceKey"]) for d in docs} == {
        (s.NIST_80053, "cge-storage-min-tls12"), (s.CSF_2, "cge-storage-min-tls12")}
    d = next(d for d in docs if d["frameworkId"] == s.NIST_80053)
    assert d["id"] == "nist-800-53-r5|cge-storage-min-tls12"   # deterministic -> upsert, no duplicates
    assert d["controls"] == ["SC-8", "SC-8(1)"] and d["type"] == "mapping"
    assert d["derivedFrom"] == "/providers/.../cge-storage-min-tls12"


def test_ids_have_no_characters_cosmos_rejects():
    for d in s.mapping_docs(DEFS, "t"):
        assert not any(ch in d["id"] for ch in "/\\?#")


def test_arm_shape_with_nested_properties_also_works():
    arm = [{"name": "cge-a", "id": "/a", "properties": {"metadata": {"nist_800_53": ["AU-2"]}}}]
    assert s.mapping_docs(arm, "t")[0]["controls"] == ["AU-2"]


def test_catalog_has_all_20_families():
    assert len(s.catalog_doc("t")["families"]) == 20
