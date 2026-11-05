# CGE-AZ Pipeline Architecture

How this pipeline is put together: the stage flow, the contracts between stages, where
data goes, and which identity is allowed to touch what. It started as the course starter's
architecture and is extended for this capstone; every departure is described in place and
summarized in [section 5](#5-capstone-departures-what-i-changed-and-why).

## 1. Stage flow

```
            ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐
  Lab 1-3   │ 01 foundation│───▶│ 02 activation│    │ 03 evidence store│
            │ MG hierarchy │    │ discover gap │    │ Cosmos + WORM    │
            │ policies     │    │ enable plans │    │ blob + collector │
            │ remediation  │    │ CSF 2.0 std  │    └────────┬─────────┘
            │ identity     │    └──────────────┘             │
            └──────┬───────┘                                 ▼
                   │                                ┌──────────────────┐
                   │                                │ 04 reporting     │
                   │                                │ POA&M + SAR from │
                   │                                │ the store ONLY   │
                   ▼                                └────────┬─────────┘
            ┌──────────────┐                                 ▼
            │ 06 enforce   │                        ┌──────────────────┐
            │ Modify effect│                        │ 05 narrative     │
            │ audit→dry-run│                        │ (optional) AI    │
            │ →enforce     │                        │ digest of 04     │
            └──────────────┘                        └──────────────────┘
```

Each stage is a Terraform root module with its own state file in the shared
`tfstate` container (bootstrapped once by `labs/03-foundation/bootstrap.sh`, the one
piece that cannot manage itself). Stages are applied in number order and destroyed in
reverse. Stage 05 is a lab, not a stage directory: it reads stage 04's artifacts and
produces prose; it never decides anything.

### The contract between stages

Downstream stages read upstream **outputs** through `terraform_remote_state`. Outputs
are the interface; everything else is private implementation.

| Stage | Reads from | Publishes |
|---|---|---|
| 01 foundation | nothing | `subscription_id`, `management_group_id`, `root_management_group_id` / `_name` (added for the collector's hierarchy-wide reads), `log_analytics_workspace_id`, `evidence_resource_group_name`, `remediation_identity_id`, `remediation_identity_principal_id` |
| 02 activation | nothing (discovers live state with `azapi` data sources) | Defender plan tiers, the NIST CSF 2.0 assignment |
| 03 evidence store | 01 | `cosmos_endpoint`, `cosmos_account_id/name`, `evidence_storage_account`, `reports_container`, `collector_function_app`, `collector_principal_id` |
| 04 reporting | 01, 03 | `reporting_function_app`, `reporter_principal_id` |
| 06 enforcement | 01 | `remediation_mode` |

Stage 01 adopts the Lab 1–2 resources (management groups, sandbox resource group,
Log Analytics workspace) with `terraform import` rather than recreating them. Stage 02
is discovery-first: `azapi` data sources read every Defender plan's current tier and
activation converges only the measured gap; a plan already at Standard stays
untouched and becomes change-managed.

## 2. Data flow

```
 Defender for Cloud ──(assessments API)────┐
 Azure Policy (cge-grc-baseline states, ───┤ collector Function ──▶ Cosmos: assessments  /subscriptionId
   one query at mg-grc)                    │ nightly 05:00 UTC       (source = defender | azurePolicy,
                                           │ runId + collectedAt      lifecycle: firstUnhealthyAt,
 Role assignments (hierarchy, 05:15 UTC) ──┘                          resolvedAt, owner)
                                                                  ▶ Cosmos: roleAssignments /scopeRoot
                 frameworks ◀── seed_frameworks.py (CSF 2.0) + seed_crosswalk.py (800-53 families)
                 mappings   ◀── seed_crosswalk.py: policy definition metadata → one doc per framework × policy
                                                                    │
 Activity log (subscription: Security, Alert; MG export at mg-grc: Administrative, Policy)
   ──▶ Log Analytics ──▶ 3 scheduled query rules (tamper, off-hours, external) ──▶ Azure Monitor alerts
 Evidence blob service ──(StorageRead/Write/Delete)──▶ Log Analytics (who touched the evidence)
                                                                    ▼
                                           reporting Function ◀── reads Cosmos ONLY
                                           POA&M daily (xlsx+json), SAR weekly (md)
                                                                    │
                                                                    ▼
                                           WORM `reports` container (immutable blob)
                                                                    │
                                                                    ▼
                                           Stage 05 narrative (optional) reads reports
```

Three rules make this defensible:

- **Collect once.** One assessment document serves every framework through the
  `mappings` crosswalk. Adding a framework is a data change, not a collector change.
- **Reports read from the store only.** No report touches a live API. Every number is
  reproducible tomorrow with a stored query against a pinned `runId`.
- **Immutability is a platform guarantee, not an access rule.** The `reports`
  container carries a time-based immutability policy. Unlocked for the course so
  teardown works; production locks it.

### Partition keys, justified

| Container | Partition key | Why |
|---|---|---|
| `assessments` | `/subscriptionId` | Every query the reports run is "this subscription, this run". A second and third subscription land as new partitions with no reshaping — the scale-by-scope requirement in the capstone brief. |
| `frameworks` | `/frameworkId` | A catalog is read whole, one framework at a time. |
| `mappings` | `/frameworkId` | The crosswalk is queried per target framework when a report resolves which controls an assessment satisfies. Document IDs `<framework>\|<policy>` make the seed idempotent. |
| `roleAssignments` | `/scopeRoot` | Snapshots are read per root of the hierarchy; a second tenant root or hierarchy becomes a new partition. One document per assignment per day keeps access history. |

Document IDs in `assessments` are a hash of `assessmentId|resourceId`, so a re-run
upserts rather than duplicates; lineage comes from `runId` and `collectedAt` on every
document. If you change a partition key in your capstone, this table is where you
defend it. A schema you cannot justify is a schema you copied.

## 3. Identity boundaries

Zero stored credentials anywhere in the design. Every actor is a managed identity or
an OIDC federation, and every identity's roles are a whitelist of its job.

| Identity | Kind | Roles (scope) | Can | Cannot |
|---|---|---|---|---|
| **Deployer** (you) | `az login` user | Owner on the subscription; Storage Blob Data Contributor on the evidence account; Cosmos Data Contributor (both pinned to `deployer_principal_id`, so CI can never move them to itself) | Apply stages, seed frameworks and crosswalk, prove WORM | Nothing is automated through this identity |
| **Remediation** `id-grc-remediation-<env>` | User-assigned MI | Monitoring Contributor (sandbox MG); Storage Account Contributor (sandbox MG) *only* when `remediation_mode != audit` | Create diagnostic settings; flip `allowBlobPublicAccess` | Create or delete resources. **Known gap:** Storage Account Contributor includes `listKeys`, i.e. data access on shared-key accounts; fix on the roadmap (custom role: `storageAccounts/read` + `write`) |
| **Collector** `func-grc-collectors-*` | System-assigned MI | Security Reader (subscription); **GRC Role Assignment Reader** (custom, `mg-grc`: 4 read actions); **GRC Policy State Reader** (custom, `mg-grc`: `policyStates/queryResults/read` + `/action`, `policyDefinitions/read`); Cosmos Built-in Data Contributor (evidence account) | Read Defender assessments and policy states; read role assignments + definitions across the hierarchy; write evidence (`assessments`, `roleAssignments`) | Change posture; grant or revoke access; read resource contents or secrets; write reports |
| **Reporter** `func-grc-reporting-*` | System-assigned MI | Cosmos Built-in Data Reader (account: `assessments`, `mappings`, `frameworks`); Storage Blob Data Contributor (`reports`) | Read evidence and the crosswalk; write immutable reports (never overwrite: same-day re-runs get a time-suffixed file) | Read live platform data; write evidence |
| **CI** (your fork's gate + drift) | GitHub OIDC federation, fork-scoped | Contributor at `mg-grc`; Storage Blob Data Contributor on the state resource group (hardening to a plan-only custom role is a documented exercise) | `terraform plan`, conftest | Write RBAC; hold a secret — there is none |

The boundaries that matter:

- **Recorder ≠ narrator.** The collector writes evidence and cannot read reports; the
  reporter reads evidence and cannot touch live services. Separation of duties is
  enforced by role scopes, not by policy text.
- **One named author for every automated change.** Filter the Activity Log by the
  remediation identity's principal ID and you have the complete history of what
  automation did. Humans and CI show up as themselves.
- **Control plane ≠ data plane.** Owner on the subscription does not read a blob or a
  Cosmos document; the deployer and both Functions hold explicit data-plane roles.
  The evidence account disables shared keys and Cosmos disables local auth, so there
  is no key-shaped way around this.
- **Upstream is unarmed.** This repo's workflows skip until `AZURE_CLIENT_ID` is set.
  Each learner federates their own fork against their own subscription
  (`labs/06-loop/arm-your-fork.sh`); a public upstream must never hold a path to a
  subscription, because `pull_request` OIDC subjects match PRs from any fork.
- **Why the collector has management-group-level read access (deliberate widening, AC-6).**
  Custom policy 3 (Azure Policy) was shown not to evaluate role assignments made *at* a
  management group, which hid the three most powerful grants in this hierarchy (Owner at
  `mg-grc` and `mg-grc-sandbox`, CI Contributor at `mg-grc`). Seeing them requires read
  access at `mg-grc`. Instead of built-in Reader (`*/read` on every resource), the collector
  gets a custom role limited to four actions: `managementGroups/read`,
  `managementGroups/descendants/read`, `roleAssignments/read`, `roleDefinitions/read`.
  `assignableScopes` restricts the role to this hierarchy. The identity still cannot change
  anything, grant access, or read data inside resources. It stores principal IDs only, never
  names or emails, so the evidence store holds no PII.

## 4. The two loops

**The pipeline on the environment.** Policy assignments at the sandbox management
group inherit to every current and future subscription. Effects are deliberate:
Audit for the tag rule (onboarding), Deny for public blob (earned), DeployIfNotExists
for diagnostics (logging that enforces its own coverage). Stage 06 adds a Modify
effect on an escalation ladder wired to one variable — `audit` → `dry-run` → `enforce`
— where each step up is a reviewed one-line diff and dry-run keeps a human at the
remediation-task approval.

**The pipeline on itself.** The compliance gate (`.github/workflows/gate.yml`) runs
`terraform plan` per stage on every PR and refuses plans that break the repo's own
standard (`policy/*.rego`: no public blob, no shared keys, no broad roles). Drift
detection (`drift.yml`) plans nightly with `-detailed-exitcode` and opens an issue
when reality has moved away from code; three scheduled KQL rules in Log Analytics answer
the other direction: who has been touching reality (stage 01 `detections.tf`).

## 5. Capstone departures: what I changed and why

Each custom control: what it checks, who acts, its effect and blast radius (the full blast-radius
note sits above each definition in `stages/01-foundation/policies*.tf`).

| Control | Checks | Who acts | Effect (why) | Blast radius if escalated to Deny |
|---|---|---|---|---|
| `cge-storage-min-tls12` | Declared minimum TLS ≥ 1.2 | Azure Policy (no identity) | Audit: Azure enforces 1.2 at the service; the declared config must still be truthful | Updates to a non-compliant account blocked until fixed |
| `cge-appservice-secure-transport` | `httpsOnly` | Azure Policy | Audit, Deny-capable | Blocks non-HTTPS apps incl. this pipeline's Functions (already fixed in code) |
| `cge-appservice-tls-ftps` | TLS 1.2+ app + SCM, FTPS/FTP off (`sites/config/web`) | Azure Policy | AuditIfNotExists (cannot Deny; the PR gate is the preventive layer) | None (cannot block) |
| `cge-audit-privileged-roles` | Owner/Contributor/UAA/RBAC Admin grants (mode All) | Azure Policy | Audit: Deny would block break-glass grants; JIT/PIM is the right control | Blocks new privileged grants, incl. emergency ones |
| `cge-nsg-no-internet-mgmt-ports` | 22/3389 from internet, inline + child rules, single + list values (mode All) | Azure Policy | Audit now; strongest Deny candidate once the seed NSG is fixed | Any update to an open NSG blocked; seed re-runs fail |
| Policy-state + role-assignment collection | Evidence beyond Defender | Collector MI (custom read-only roles) | n/a | Read-only; cannot change posture or grant access |
| KQL detections | Governance tamper, off-hours, external identities | Azure Monitor (scheduled query rules) | Alert only | None (alerts, no action group yet) |

Design decisions worth defending:

- **Lifecycle lives in the collector, not the reporter.** The collector is the only identity that may write
  evidence; the reporter stays read-only (SoD), so "first detected" is a recorded fact, not a computed guess.
- **Policy findings use the Defender document shape** (`source` field), so lifecycle, owners, stable IDs and
  deadlines apply unchanged.
- **The collector's hierarchy-wide read is deliberate** (section 3): Azure Policy cannot see MG-scope grants.
- **One export per activity-log category.** The MG export at `mg-grc` carries child MGs *and* every subscription;
  exporting the same categories from the subscription stored every event twice (measured: dup ratio 1.0 → 2.0).
- **Detections select by `ingestion_time()`** with a 5-minute overlap: with window = frequency, 2 of 3 events
  were never evaluated in a live test because ingestion lags 5–10 minutes.
- **Scale by scope, not size:** assignments and queries at management-group scope, partition keys that include
  the subscription or hierarchy root, no hardcoded subscription IDs in code (tests use a fake ID).
