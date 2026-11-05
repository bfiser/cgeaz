# Control Mappings

Every policy, gate rule, collector, report and detection in this repo, mapped to **NIST SP 800-53
Rev. 5** and **NIST CSF 2.0**. For the Azure Policy definitions the mapping is not only written here:
it lives in each definition's `metadata` (`nist_800_53`, `csf_2_0`) in Terraform, is seeded into the
evidence store's `mappings` container (`scripts/seed_crosswalk.py`), and the reports resolve controls
from there. This table and the store say the same thing because they come from the same source.

Effects are deliberate and variable-driven: **Audit** for new controls, **Deny** where earned,
**DeployIfNotExists / Modify** where automation is safe. Changing an effect is a reviewed PR to the
variable's default; a local `-var` deviation would surface as drift the next night.

## Stage 01: Foundation (policies assigned via the `cge-grc-baseline` initiative at `mg-grc-sandbox`)

| Component | Effect | What it does | 800-53 | CSF 2.0 |
|---|---|---|---|---|
| Management group hierarchy + initiative at MG scope | n/a | Controls inherit to every current and future subscription | PL-2, CM-2 | GV.PO-01, GV.OC |
| `cge-require-env-tag-rg` | Audit | Inventory hygiene; resource groups must carry `env` | CM-8 | ID.AM-02 |
| `cge-deny-public-blob` | **Deny** (earned) | Public blob access refused at the API | AC-3, SC-7 | PR.DS-01, PR.AA-05 |
| `cge-dine-storage-diagnostics` | DeployIfNotExists | Storage accounts route diagnostics to the GRC workspace (account-level metrics; see finding below) | AU-2, AU-12 | PR.PS-04 |
| **`cge-storage-min-tls12`** (custom 1) | Audit | Declared minimum TLS must be 1.2+ (declared config must be truthful; regression guard after Azure's TLS 1.0/1.1 retirement) | SC-8, SC-8(1) | PR.DS-02 |
| **`cge-appservice-secure-transport`** (custom 2a) | Audit (Deny-capable) | App Service apps HTTPS-only | SC-8, SC-8(1), SC-23 | PR.DS-02 |
| **`cge-appservice-tls-ftps`** (custom 2b) | AuditIfNotExists | TLS 1.2+ on app and SCM sites; FTPS-only or FTP disabled (`sites/config/web`) | SC-8, SC-8(1), IA-5(1) | PR.DS-02 |
| **`cge-audit-privileged-roles`** (custom 3) | Audit | Owner / Contributor / User Access Admin / RBAC Admin assignments flagged for review (mode All) | AC-6, AC-6(5), AC-2(7) | PR.AA-05 |
| **`cge-nsg-no-internet-mgmt-ports`** (custom 4) | Audit (Deny candidate) | NSG rules must not open 22/3389 to the internet; inline and child-rule forms, single and list values (mode All) | SC-7, SC-7(5), AC-17 | PR.IR-01 |
| Remediation identity `id-grc-remediation-dev` (user-assigned) | n/a | One named author for every automated change; Monitoring Contributor at the sandbox MG | AC-6, AU-10 | PR.AA-05, GV.RR |
| Log Analytics workspace | n/a | Central audit trail beyond the 90-day platform default | AU-4, AU-11 | PR.PS-04 |
| Activity-log routing: subscription (Security, Alert) + **MG export at `mg-grc`** (Administrative, Policy; covers child MGs and every subscription) | n/a | Exactly one export per category; MG-scope policy/RBAC changes become visible | AU-2, AU-12 | PR.PS-04, DE.CM-09 |
| **`cge-governance-tamper`** (KQL, Sev 1, 15 min) | alert | Writes/deletes to policy, RBAC, management locks, diagnostic settings, alert rules, WORM immutability policies | AU-6, AU-9, CM-3, SI-4 | DE.CM-09, DE.AE-02 |
| **`cge-offhours-human-changes`** (KQL, Sev 2, hourly) | alert | Human writes, deletes and key listing outside business hours | AU-6, AC-2(12) | DE.CM-03, DE.AE-02 |
| **`cge-external-identity-activity`** (KQL, Sev 3, daily) | alert | Activity by identities from another identity provider (guests, B2B) | AC-2, AC-2(12) | DE.CM-03 |

## Stage 02: Activation

| Component | What it does | 800-53 | CSF 2.0 |
|---|---|---|---|
| Discovery-first Defender plans (`azapi` data sources, converge only the gap) | Vulnerability/configuration assessment across the estate | RA-5, CA-7 | ID.RA-01, DE.CM |
| NIST CSF 2.0 regulatory-compliance assignment | Framework-aligned compliance view | CA-2 | GV.OV |

## Stage 03: Evidence store

| Component | What it does | 800-53 | CSF 2.0 |
|---|---|---|---|
| Cosmos DB `assessments` (`/subscriptionId`), `roleAssignments` (`/scopeRoot`) | Owned evidence schema; deterministic IDs; `runId` + `collectedAt` lineage | AU-3, CA-7 | ID.RA, GV.OV |
| `frameworks` + **`mappings` (crosswalk as data)** | 800-53 family catalog + CSF 2.0 structure; one mapping doc per framework × policy | PM-9, CA-2 | GV.OV |
| WORM time-based immutability on `reports` (90 days; unlocked for teardown) | Reports cannot be deleted or overwritten (proven: `BlobImmutableDueToPolicy`) | AU-9, SI-7 | PR.DS-01 |
| **Evidence access log** (`ds-evidence-blob-access`: StorageRead/Write/Delete) | Who reads, writes or deletes evidence | AU-2, AU-9, AU-12 | PR.PS-04, DE.CM-09 |
| Shared keys disabled (evidence account), Cosmos local auth disabled, key-based metadata writes off | Identity or nothing; no keys to steal | IA-2, AC-3 | PR.AA-01 |
| `prevent_destroy` on 8 evidence resources | Evidence cannot disappear via `terraform destroy` | AU-9, CP-9 | PR.DS-11 |
| Collector: Defender assessments (Security Reader) | Continuous control assessment | CA-7, RA-5 | DE.CM, ID.RA-01 |
| **Collector: Azure Policy states** (custom role *GRC Policy State Reader*) | Custom-policy findings become evidence (`source=azurePolicy`) | CA-7 | DE.CM |
| **Collector: role-assignment snapshots** (custom role *GRC Role Assignment Reader*, 4 actions, `mg-grc`) | Daily access record across the hierarchy, including MG-scope grants Policy cannot see | AC-2, AC-2(3), AC-6 | PR.AA-05, GV.RR |
| **Finding lifecycle** in the collector (`firstUnhealthyAt`, `resolvedAt`, owner from RG tag, UNASSIGNED visible) | Aging and accountability; collector owns facts, reporter stays read-only | CA-5, PM-4 | ID.IM, GV.RR |
| Collector ≠ reporter identities | Recorder of facts cannot author the narrative (SoD by role scope) | AC-5 | PR.AA, GV.RR |

## Stage 04: Reporting

| Component | What it does | 800-53 | CSF 2.0 |
|---|---|---|---|
| **POA&M** (daily, xlsx + json): stable IDs, deadline = first detected + SLA, overdue, owners, closures, 800-53 + CSF 2.0 per row via the crosswalk | Plan of action and milestones from the store only | CA-5, PM-4 | ID.IM-01, GV.RM |
| SAR (weekly, markdown) with by-framework summary | Assessment reporting; every number traceable | CA-2, CA-7 | ID.RA, GV.OV |
| **Report reproducibility** (`scripts/reproduce_report.py`, `docs/REPORT-QUERIES.md`) | Every POA&M number recomputed from stored queries, independently | AU-3, CA-7 | GV.OV-03 |

## Stage 06: Enforcement

| Component | Effect | What it does | 800-53 | CSF 2.0 |
|---|---|---|---|---|
| `cge-fix-public-blob` | Modify (ladder) | Flips `allowBlobPublicAccess` to false through the remediation identity; dry-run keeps a human at the remediation task | AC-3, SC-7, SI-2 | PR.DS-01, RS.MI |
| `remediation_mode` variable (`audit` → `dry-run` → `enforce`) | n/a | Escalation is a reviewed one-line diff | CM-3, CM-5 | GV.PO, GV.RR |

## Repo gates (`policy/`, run by `.github/workflows/gate.yml` on every PR; 43 tests)

| Rule | Mistake it makes unmergeable | 800-53 | CSF 2.0 |
|---|---|---|---|
| `storage.rego` | Public blob or shared keys on pipeline storage | AC-3, IA-2 | PR.DS, PR.AA |
| **`storage_tls.rego`** (6 tests) | Storage below TLS 1.2 | SC-8 | PR.DS-02 |
| **`appservice_transport.rego`** (11 tests) | App Service without HTTPS-only / TLS 1.2 / FTPS | SC-8, SC-23 | PR.DS-02 |
| **`broad_roles.rego`** (12 tests; hardened) | Owner / Contributor / UAA / RBAC Admin in code, by name **or role GUID** | AC-6, AC-6(5) | PR.AA-05 |
| **`nsg_mgmt_ports.rego`** (14 tests) | 22/3389 open to the internet, including port **ranges** policy cannot evaluate | SC-7, AC-17 | PR.IR-01 |
| `policy_identity.rego` | Remediation policy without an identity (silently never runs) | CM-6 | PR.PS |

## Pipeline operations

| Component | What it does | 800-53 | CSF 2.0 |
|---|---|---|---|
| Branch protection (4 required matrix checks, up to date, no bypass) | No ungated change reaches `main`; failed closed during the Actions outage | CM-3, CM-5 | PR.PS-01 |
| **Drift detection** (`drift.yml`, all stages, `-detailed-exitcode`, issue on drift) | Does reality match code? (proven on a controlled and a real drift) | CM-3, CM-6, SI-4 | DE.CM-09 |
| KQL detections (stage 01) | Who is touching reality? | AU-6, SI-4 | DE.AE |
| **Actions pinned to commit SHAs, `ubuntu-24.04`, provider lock files with checksums** | Build inputs change only through a PR | SR-4, SR-11, SI-7, CM-2 | GV.SC, PR.PS-01 |
| **Tier 0: tflint + checkov** (pinned, checksum-verified; 0 failed, exceptions justified inline) | Static analysis of every stage | SA-11, CM-6 | PR.PS-01 |
| OIDC federation, zero stored credentials; `persist-credentials: false` | No secret to leak | IA-5, AC-6 | PR.AA-01 |

## Findings this mapping surfaced (and what changed)

- `cge-dine-storage-diagnostics` is **Compliant but does not meet its objective**: it deploys account-level
  metrics only; storage read/write/delete logs exist only on sub-services. Evidence access is now logged by a
  dedicated blob-service setting; extending the policy to blob services is on the roadmap.
- Defender for Cloud did not flag the NSG management ports, the workload identity holding Contributor, or the
  storage account declaring TLS 1.0: custom policies 4, 3 and 1 exist because of that.
- `cge-fix-public-blob` carries no `nist_800_53` metadata because it is a remediation, not an assessment
  feeding the POA&M; its mapping is this table (AC-3, SC-7, SI-2).
