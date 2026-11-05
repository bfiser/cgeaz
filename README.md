# CGE-AZ Capstone: a federal-track GRC pipeline on Azure

**Track:** Federal (NIST SP 800-53 Rev. 5 + NIST CSF 2.0) · **Author:** [@bfiser](https://github.com/bfiser)
· **Built on:** the [GRCEngClub/cgeaz](https://github.com/GRCEngClub/cgeaz) starter (labs 1–6), extended
with my own controls, detections, evidence lifecycle, and pipeline hardening.

This repository is a working, automated GRC engineering pipeline running in my own Azure
subscription. It **prevents** (PR gate), **enforces** (Azure Policy at management-group scope),
**detects** (drift + KQL detections), **records** (immutable evidence store), and **reports**
(POA&M and SAR read only from the store), and every control is mapped to 800-53 and CSF 2.0
as data. Everything is code; nothing is changed in the portal.

| If you want to… | Read |
|---|---|
| Deploy it from an empty subscription | [Deploy order](#deploy-from-an-empty-subscription) below |
| See every control and its mappings | [docs/CONTROLS.md](docs/CONTROLS.md) |
| See stage flow, data flow, identity boundaries | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Reproduce any report number from the store | [docs/REPORT-QUERIES.md](docs/REPORT-QUERIES.md) |
| See the evidence | [`submission/`](submission/) (index [below](#evidence)) |

## Pipeline at a glance

```
 PR ──▶ compliance gate (terraform plan per stage + 43 Conftest tests + OPA rules) ──▶ main
                                                                                       │ apply (from main only)
 01 foundation ── MG hierarchy, 8 custom/taught policies (initiative at MG scope),       ▼
                  remediation identity, activity-log routing (subscription + MG), 3 KQL detections
 02 activation ── discovery-first: Defender plans + CSF 2.0 assignment converge only the measured gap
 03 evidence   ── Cosmos (assessments / roleAssignments / frameworks / mappings) + WORM reports container
                  collector Function: Defender assessments + Azure Policy states + role assignments, nightly
 04 reporting  ── POA&M (daily) + SAR (weekly), read from Cosmos ONLY, written to WORM
 06 enforce    ── Modify policy on an audit → dry-run → enforce ladder, one reviewed variable

 nightly drift (plan -detailed-exitcode, all stages) ──▶ issue on drift
 KQL detections (governance tamper, off-hours human changes, external identities) ──▶ Azure Monitor alerts
```

## What I built beyond the starter

| Area | Addition | Why |
|---|---|---|
| **Own controls** | 4 custom policies (5 definitions): storage TLS 1.2, App Service HTTPS-only + TLS/FTPS, privileged role assignments, NSG mgmt ports from internet; all with 800-53 + CSF 2.0 metadata | Each covers a gap Defender for Cloud did **not** flag on the seeded estate ([coverage gaps](#what-defender-missed-and-what-covers-it)) |
| **Gate** | 4 Conftest rules written or hardened, 43 tests (storage TLS, App Service transport, broad roles hardened against GUID bypass, NSG mgmt ports incl. port ranges), plus the starter's storage and policy-identity rules | The same standard enforced on this repo's own Terraform before merge |
| **Evidence lifecycle** | Stable POA&M IDs, deadlines from first detection, aging, overdue, owners (UNASSIGNED made visible), closures, backfill from WORM history with provenance | A POA&M that restamps dates daily can never be overdue (CA-5, PM-4) |
| **Second evidence source** | Azure Policy states collected at the root MG as evidence documents | Custom-policy findings never reached the POA&M before (CA-7) |
| **Role-assignment collector** | Daily snapshot across the hierarchy via a 4-action custom role | Azure Policy cannot see MG-scope role assignments, where the most powerful grants live (AC-2, AC-6) |
| **Crosswalk as data** | `mappings` seeded from policy metadata; reports resolve 800-53 + CSF 2.0 through it | Collect once; adding a framework is a data change |
| **Reproducibility** | `scripts/reproduce_report.py` recomputes every POA&M number from stored queries (7/7 PASS) | "Every number has a receipt", proven, not claimed |
| **Detections as code** | Imported the hand-made activity-log routing; MG activity export; 3 scheduled query rules (KQL in files, `templatefile`) | The starter documented a KQL tripwire that did not exist |
| **Pipeline hardening** | Drift detector that can fail, actions pinned to SHAs, `ubuntu-24.04`, per-stage concurrency, tflint + checkov (0 failed, every exception justified inline) | Supply chain (SR-4, SR-11), baseline (CM-2), integrity (SI-7) |

## Deploy from an empty subscription

Prerequisites, regional quirks and cost guardrails: **[docs/SETUP.md](docs/SETUP.md)** (follow it first).
Commands below run from the repo root unless noted; `az login` as the deployer.

1. **Management groups + sandbox (labs 1–2).** Create `mg-grc` → `mg-grc-sandbox`, move the
   subscription under it, create `rg-grc-sandbox-dev` and the Log Analytics workspace
   (labs/01-sandbox, labs/02-toolkit). Stage 01 adopts these with `import`, never recreates them.
2. **State backend (once).** `labs/03-foundation/bootstrap.sh`: versioned storage account,
   `tfstate` container, Blob Data Contributor for you, writes `backend.hcl` (names only, committed).
3. **Variables.** `export TF_VAR_state_storage_account=<from bootstrap>`,
   `TF_VAR_owner_email=<a role address>` (never a personal email: it lands in tags and logs),
   `TF_VAR_deployer_principal_id=$(az ad signed-in-user show --query id -o tsv)` (pins stage 03's
   data-plane roles to the deployer, so CI can never move them to itself).
4. **Apply the stages in order**, each with
   `terraform init -backend-config=../../labs/03-foundation/backend.hcl && terraform plan -out=tf.plan`,
   read the plan, then `terraform apply tf.plan`:
   `01-foundation` → `02-activation` → `03-evidence-store` → `04-reporting` → `06-enforcement`.
   Stage 01 must be applied before 03 (03 reads 01's outputs: publish the output first, then consume it).
5. **Deploy the Function code** (collector, then reporter). On the Consumption plan the trigger
   sync is **required**, or timers silently never fire:
   ```bash
   APP=$(terraform -chdir=stages/03-evidence-store output -raw collector_function_app)   # reporter: stages/04-reporting, reporting_function_app
   (cd functions/collect_assessments && zip -qr ~/app.zip . -x "test_*" "__pycache__/*" ".pytest_cache/*")
   az functionapp deployment source config-zip -n "$APP" -g rg-grc-evidence-dev --src ~/app.zip --build-remote true
   az rest --method post --url "https://management.azure.com/subscriptions/$(az account show --query id -o tsv)/resourceGroups/rg-grc-evidence-dev/providers/Microsoft.Web/sites/$APP/syncfunctiontriggers?api-version=2022-03-01"
   az functionapp function list -n "$APP" -g rg-grc-evidence-dev --query "[].name" -o tsv   # verify: all functions listed
   ```
6. **Seed the frameworks and the crosswalk** (as the deployer):
   ```bash
   export COSMOS_ENDPOINT=$(terraform -chdir=stages/03-evidence-store output -raw cosmos_endpoint)
   (cd labs/04-evidence && python3 seed_frameworks.py)                                  # CSF 2.0 catalog
   az policy definition list --management-group mg-grc-sandbox -o json > /tmp/defs.json
   python scripts/seed_crosswalk.py /tmp/defs.json            # dry run; then add --apply
   ```
7. **Arm the fork's CI** (`labs/06-loop/arm-your-fork.sh <github-user>`). Note: GitHub now sends
   OIDC subjects with numeric IDs (`repo:<owner>@<id>/<repo>@<id>:pull_request`); the federated
   credentials must match that format exactly. Add the repository variables `AZURE_CLIENT_ID`,
   `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `STATE_STORAGE_ACCOUNT`, `OWNER_EMAIL`,
   `DEPLOYER_PRINCIPAL_ID`. Without them the gate **skips**, and a skipped required check counts as
   passing. If the Actions tab shows "Workflows on this fork have been disabled", re-enable it there
   (the permissions API still reports "enabled").
8. **Branch protection on `main`:** PR required; required checks = the four matrix jobs
   `gate (01-foundation)`, `gate (03-evidence-store)`, `gate (04-reporting)`, `gate (06-enforcement)`;
   branches must be up to date; **no bypass**, including admins.
9. **Seed estate** (graded material, not part of the pipeline): `./seed-estate.sh`, discovered by tag.

From then on: every change is a PR → gate → merge → apply from `main` → post-apply
`terraform plan -detailed-exitcode` must be `0`.

## Controls (summary)

Full catalog with 800-53 and CSF 2.0 for every policy, gate rule, collector, report and detection:
**[docs/CONTROLS.md](docs/CONTROLS.md)**. Policy effects are deliberate: **Audit** for new controls,
**Deny** where earned (public blob), **DeployIfNotExists/Modify** where automation is safe, each
effect a variable changed only by reviewed PR. Every Deny-capable or remediating policy carries a
**blast radius** note at its definition.

## What Defender missed, and what covers it

| Seeded misconfiguration | Defender for Cloud | Covered by |
|---|---|---|
| NSG allows 22/3389 from the internet | Not flagged (its mgmt-port check is VM-only) | `cge-nsg-no-internet-mgmt-ports` + gate rule `nsg_mgmt_ports.rego` (also port ranges) |
| Workload identity holding Contributor | Not flagged | `cge-audit-privileged-roles` + role-assignment collector (MG scope) |
| Storage account declaring TLS 1.0 | Not flagged | `cge-storage-min-tls12` + gate rule `storage_tls.rego` |
| Custom-policy findings in the POA&M | Never there (Defender-only POA&M) | Policy states collected as `source=azurePolicy` evidence |
| Policy/RBAC changes at management-group scope | Invisible to the subscription activity log | MG activity export + `cge-governance-tamper` |
| App Service HTTPS/TLS/FTPS | Flagged | Also `cge-appservice-*` (policy) + `appservice_transport.rego` (gate, before deploy) |

## Detections

| Rule | Severity / cadence | Detects | Controls |
|---|---|---|---|
| `cge-governance-tamper` | Sev 1, every 15 min | Writes/deletes to policy, RBAC, management locks, diagnostic settings, alert rules, WORM immutability policies (incl. MG scope) | AU-6, AU-9, CM-3, SI-4 |
| `cge-offhours-human-changes` | Sev 2, hourly | Human writes, deletes and key listing outside 07–19 America/New_York | AU-6, AC-2(12) |
| `cge-external-identity-activity` | Sev 3, daily digest | Activity by identities from another identity provider (guests, B2B) | AC-2, AC-2(12) |

Design facts I measured rather than assumed: activity-log ingestion lag is **5–10 min**; a rule whose
window equals its frequency **missed 2 of 3 events** in a live test, so the rules select by
`ingestion_time()` with a 5-minute overlap (duplicates over misses for Sev 1); observed
change→alert ≈ 10 min, worst case ≈ 25 min. The MG export also carries every subscription, so each
log category has exactly **one** export (the double export was found by measurement and fixed).
Alerts land in Azure Monitor; notification routing (action group) is on the roadmap.

## Evidence

Every claim above has a file in [`submission/`](submission/), most of them written as **predictions
before the change** and results after it.

| Topic | Files |
|---|---|
| Custom policies (predicted vs. observed, control groups) | `policy-compliance/*` |
| Role collector | `role-collector-actions-verified-*`, `role-collector-first-run-*` |
| POA&M lifecycle | `poam-lifecycle-backfill-*`, `poam-before-after-*`, `poam-policy-findings-*`, `policy-findings-expected-*`, `policy-collector-local-test-*`, `poam-stability-2026-11-02.txt` |
| Report reproducibility | `report-reproduced-2026-11-05.txt` (7/7 numbers reproduced from stored queries) |
| WORM | `worm-proof-2026-11-04.txt` (delete + overwrite refused: `BlobImmutableDueToPolicy`) |
| Detections | `detections-expected-*`, `detections-live-*`, `detections-verify-*` |
| Drift | `manual-drift-checks.txt`, `drift-restored-*.json`; issues #13 (controlled test) and #19 (real drift, root-caused) |
| Tier 0 | `tier0-2026-11-04.txt` (tflint clean; checkov 0 failed / 0 parse errors) |
| Gate blocks | PR #1 (closed, red) + `labs/06-loop/lab6-gate-evidence.txt`; enforcement loop: `labs/06-loop/lab6-redeny-evidence.txt` |

Self-checks: `./self-check.sh` (18/0), `gitleaks` (clean), unit tests (collector 25, reporter 20,
scripts 15), Conftest (43).

## Findings and lessons (the short list)

- **A skipped gate is a passed gate.** Missing repo variables made the required check skip, which
  GitHub counts as passing. Fixed; the gate now fails loudly.
- **Documented is not deployed.** The starter described a KQL tripwire that did not exist, on
  log routing that was hand-made. Both are now code.
- **Compliant is not the control objective.** `cge-dine-storage-diagnostics` reported Compliant
  while deploying metrics only; nobody logged who read the evidence. Fixed with a blob-service
  diagnostic setting.
- **"Apply complete" is not proof.** A diagnostic-setting change reported success while Azure
  still had the old categories; only the post-apply `plan -detailed-exitcode` and a read-back
  caught it.
- **A detector that cannot fail is not a control.** The drift job masked exit codes for three
  nights; it now fails on drift and opens an issue (proven on a real drift, issue #19).

## Known gaps and roadmap (accepted, with reasons)

| Gap | Why accepted now | Next step |
|---|---|---|
| Remediation identity uses Storage Account Contributor (includes listKeys) for a job that flips one property | Proven Lab 6 loop; not Owner/Contributor; changing the role the policy references needs a live remediation retest | Custom role `storageAccounts/read` + `write` only, referenced in the policy's `roleDefinitionIds` |
| One CI identity (Contributor at `mg-grc`) for plan-only workflows | All applies are local from `main`; plan needs storage key reads | Split: read-only plan identity |
| WORM policy unlocked | Sandbox must be torn down after grading | Lock in production (irreversible) |
| No action group on alerts | Lab scope | Route to an on-call role address |
| Scheduled drift runs stopped after GitHub auto-disabled the fork's workflows; cron moved off the hour | Gap covered by manual dispatch runs | Drift heartbeat: alert if no successful run in 26 h |
| Defender built-in findings have no crosswalk entries (counted as "unmapped") | Visible in every report, never dropped | Map assessment metadata to 800-53 |
| Standing Owner for the deployer (external account) | Free personal tenant | Native account + PIM |
| Report history re-derivable only on the day of generation | Latest-state container; WORM keeps every report | Append-only snapshots or Cosmos point-in-time restore |
| Y1 Consumption: no private endpoints, Microsoft-managed keys | Cost and plan limits; justified inline per resource | Premium plan + private endpoints, CMK |

## Repository layout

```
stages/     one Terraform root module per stage, separate state
functions/  collector (assessments, policy states, role assignments) and reporter (POA&M, SAR, crosswalk)
policy/     Conftest rules + tests gating this repo's own Terraform
scripts/    crosswalk seed, report reproduction, KQL render, backfill, access review
submission/ evidence for the capstone
docs/       CONTROLS, ARCHITECTURE, REPORT-QUERIES, SETUP, RUBRIC, VALIDATION-LOG
labs/       the course labs (starter), including bootstrap and fork-arming scripts
```

---

*Starter by the GRC Engineering Club community (www.grcengclub.com). Capstone extensions by @bfiser.*
