# Calculation Methodology — Derived Fields

Field-by-field explanation of **how every non-trivial value in the inventory is
calculated**: the inputs used, the exact decision logic, every possible output
value, worked examples from real resources, and the blind spots you should be
aware of when consuming the CSV/XLSX.

> Companion docs: [README.md](README.md) for usage,
> [ARCHITECTURE.md](ARCHITECTURE.md) for data flow and system design.
> This document zooms into the *decision logic* only.

---

## Table of contents

1. [How to read this document](#1-how-to-read-this-document)
2. [Encryption Status](#2-encryption-status)
3. [Backup / Recovery Status](#3-backup--recovery-status)
4. [Logging and Monitoring Status](#4-logging-and-monitoring-status)
5. [Tag Compliance Status](#5-tag-compliance-status)
6. [The tag extraction engine (12 governance columns)](#6-the-tag-extraction-engine)
7. [Publicly Accessible](#7-publicly-accessible)
8. [Policy Compliance Status](#8-policy-compliance-status)
9. [Virtual Network / Subnet and NSG / Network Control](#9-virtual-network--subnet-and-nsg--network-control)
10. [Quick reference — remaining semi-derived fields](#10-quick-reference--remaining-semi-derived-fields)
11. [Appendix — output value dictionary](#11-appendix--output-value-dictionary)

---

## 1. How to read this document

**Inputs.** Every calculation runs locally on data already fetched:

| Input | Origin |
|---|---|
| `type`, `id`, `name`, `location`, `zones`, `sku`, `identity`, `tags` | Resource Graph row fields |
| `properties` blob | Resource Graph row field (JSON object) |
| Network maps (`vm_to_nics`, `nic_to_pips`, `subnet_to_nsg`, …) | Built once from all fetched rows |
| `backup_labels` | Restore point collections + per-vault Backup API scan |
| `logging_map`, `agent_monitored` | Monitor API probe + agent scan |
| `policy` states | ARG `policyresources` table |

**`N/A` semantics.** `N/A` is not "failed" — it means *not determinable from
the control plane*, or *not applicable to this resource type*. Example: a VNet
has no meaningful "publicly accessible" verdict, so it reports `N/A`; a NIC
reports a real `No`.

**Snapshot semantics.** All values reflect one moment in time (the
`Inventory Last Refreshed` column). Tag edits made mid-run may or may not be
captured; policy states lag live evaluation by up to ~15 minutes.

**Case handling.** Resource IDs are compared case-insensitively everywhere
(lowercased map keys); tag keys are normalized before matching (§5, §6).

---

## 2. Encryption Status

**Function:** `encryption_status(type, properties, serialized_properties)`
**Column:** `Encryption Status`

### Decision tree (evaluated top to bottom)

```
                 ┌─────────────────────────────┐
                 │ type == storage account?    │
                 └──┬───────────────────────▲──┘
            yes ▼                           no ▼
   any of blob/file/queue/table      type == disk or snapshot?
   services encryption enabled?              │
        │yes            │no          yes ▼          ▼no
        ▼               ▼         encryption.type?   type == keyvault?
 keySource contains           │                │            │
 'keyvault'?                  │     ┌──────────┴────┐       ▼
   │yes        │no            │  CustomerKey?  other?   Platform-managed
   ▼           ▼              ▼     ▼yes    ▼no        (always encrypted)
Enabled    Enabled         N/A      ▼       ▼
(CMK)   (Microsoft-             Enabled Enabled
         managed)               (CMK) (Platform-
                                      managed)

 For everything else (generic scan of lowercased properties JSON):
   ├─ contains 'diskencryptionsetid' / 'keyvaulturi'
   │  or 'customermanagedkey'        → Enabled (CMK referenced)
   ├─ contains '"encryption"'        → Enabled (review properties)
   └─ otherwise                      → N/A
```

### Rules in words

| Step | Condition | Result |
|---|---|---|
| 1a | Storage account, zero encryption services enabled (blob/file/queue/table) | `Disabled` |
| 1b | Storage account, enabled + `keySource == Microsoft.Keyvault` | `Enabled (CMK)` |
| 1c | Storage account, enabled + any other keySource | `Enabled (Microsoft-managed)` |
| 2a | Disk/snapshot, `encryption.type` contains `CustomerKey` | `Enabled (CMK)` |
| 2b | Disk/snapshot, any other `encryption.type` present | `Enabled (Platform-managed)` |
| 2c | Disk/snapshot with no `encryption` block | `N/A` |
| 3 | Key Vault (any sub-resource) | `Enabled (Platform-managed)` — always encrypted by design |
| 4 | Any resource whose properties reference a CMK idiom | `Enabled (CMK referenced)` |
| 5 | Any resource with an `"encryption"` property at all | `Enabled (review properties)` |
| 6 | Nothing matched | `N/A` |

### Worked examples

| Resource | Properties observed | Output |
|---|---|---|
| Storage acct, `encryption.keySource = Microsoft.Storage`, blob+file enabled | step 1c | `Enabled (Microsoft-managed)` |
| Storage acct with CMK via Key Vault | step 1b | `Enabled (CMK)` |
| Managed disk, `encryption.type = EncryptionAtRestWithCustomerKey` | step 2a | `Enabled (CMK)` |
| Managed disk, `EncryptionAtRestWithPlatformKey` | step 2b | `Enabled (Platform-managed)` |
| VM with `diskEncryptionSetId` on OS profile | step 4 | `Enabled (CMK referenced)` |
| SQL server with `"encryption": {...}` somewhere in props | step 5 | `Enabled (review properties)` |
| Basic NIC | nothing matches | `N/A` |

### Blind spots

- Step 4/5 are *heuristics* over property text — a resource that merely
  references someone else's Key Vault URI can light up as `CMK referenced`.
- `Enabled (review properties)` intentionally tells you to look deeper rather
  than guessing TDE state for SQL, which lives in child resources Graph
  doesn't expose uniformly.

---

## 3. Backup / Recovery Status

**Functions:** `fetch_backup_map()` (data), `enrich()` (priority chain)
**Column:** `Backup / Recovery Status`

### Priority chain (first match wins)

```
1. Resource's ID found in vault protected-item scan
   OR in restore-point-collection sources
        → "Azure Backup (<workload>)"        e.g. Azure Backup (AzureIaasVM)
                                             e.g. Azure Backup (AzureDisk)

2. Type ∈ PLATFORM_BACKUP map
        → "Built-in PITR (platform backups)"     SQL DBs (PaaS & MI)
          "Automatic backups (platform)"         Cosmos DB accounts
          "Automated backups (platform)"         PostgreSQL/MySQL Flexible

3. Resource IS a Recovery Services vault
        → "Recovery Services vault"

4. Otherwise → "N/A"
```

### How layer 1 collects sources

| Source | Where the protected workload ID hides |
|---|---|
| Per-vault Backup API (`backup_protected_items.list`) | `sourceResourceId` / `virtualMachineId` inside each item — harvested generically by walking the whole parsed object and collecting every string shaped like an ARM ID |
| Restore point collections (Graph query) | `properties.sourceResourceId` pointing back at the source VM/disk |

Both feed one dictionary keyed by lowercased ARM ID → label.

### Worked examples

| Resource | Signal | Output |
|---|---|---|
| VM `BlrCognosApp02`, protected by vault IaaS policy | vault item workload `AzureIaasVM` | `Azure Backup (AzureIaasVM)` |
| Managed disk under Azure Backup disk protection | vault item workload `AzureDisk` | `Azure Backup (AzureDisk)` |
| SQL-in-VM database protected via MABS | vault item | `Azure Backup (MAB)` or `(SQLDatabase)` depending on reported workload |
| SQL MI database (never in a vault) | platform rule | `Built-in PITR (platform backups)` |
| The vault itself | identity check | `Recovery Services vault` |
| Random NIC | none | `N/A` |

### Blind spots

- Azure SQL DB PITR is *always* on — the platform label doesn't tell you the
  retention window; check the service defaults.
- Snapshots taken manually are **not** backup signals (too ambiguous).
- A vault in a subscription your credential can't read will silently miss its
  protected items even if the workloads are visible.

---

## 4. Logging and Monitoring Status

**Functions:** `fetch_logging_signals()`, `detect_agent_monitored()`
**Column:** `Logging and Monitoring Status`

Three independent signals are collected, then composed.

### Signal 1 — Diagnostic settings (Monitor API probe)

Only types known to support `{resource-uri}/providers/microsoft.insights/
diagnosticSettings` are probed (`DIAG_CAPABLE_PREFIXES`: storage accounts,
Key Vaults, SQL servers/databases, web apps, NSGs, firewalls, gateways, AKS,
ACR, Event Hubs, Service Bus, Cosmos DB, Redis, Log Analytics workspaces,
App Insights, vaults, VMs, …). Each returned setting is classified:

```
any log category (or category group) enabled?
    yes → "Diagnostic settings (logs)"          ← best label, stops search
    no  → any metric category enabled?
              yes → "Diagnostic settings (metrics only)"
              no  → setting ignored (exists but emits nothing)
```

Best label per resource wins across multiple settings (logs beats metrics-only).

### Signal 2 — Data collection rules (AMA era)

If the Monitor client exposes DCR associations, an association on the resource
adds `"Data collection rule (monitor agent)"`. This catches modern
Azure Monitor Agent pipelines that never create classic diagnostic settings.

### Signal 3 — Monitoring agents (free, from inventory itself)

Every extension row already fetched by the main query is scanned for known
agents (name or publisher, case-insensitive):

```
AzureMonitorLinuxAgent · AzureMonitorWindowsAgent · OMSAgentForLinux
MicrosoftMonitoringAgent · DependencyAgent
publisher: Microsoft.EnterpriseCloud.Monitoring
```

Match ⇒ the **parent VM** gets credited (via parent-ID parsing).

### Composition

```
signals = [diag_label?] + ["Monitoring agent extension"?]
none    → "Not detected"
any     → joined with " + "
```

Examples:

```
Diagnostic settings (logs)
Diagnostic settings (metrics only) + Monitoring agent extension
Data collection rule (monitor agent)
Not detected
```

### Blind spots

- "Diagnostic settings (logs)" proves a *pipe* exists, not that the destination
  workspace still receives data.
- Types outside `DIAG_CAPABLE_PREFIXES` are never probed → they can only ever
  reach `Not detected` unless an agent signal exists.
- Classic Log Analytics agent extensions were retired in Aug 2024 but remain a
  positive signal here since AMA-era detection covers both worlds.

---

## 5. Tag Compliance Status

**Functions:** `tag_compliance(tags, required_tags)`
**Column:** `Tag Compliance Status`

### Step 1 — normalize both sides

Tag keys are stripped to `[a-z0-9]`: `Business-Owner`, `business_owner`,
`BUSINESSOWNER` all become `businessowner`.

Required tags are matched **alias-aware**: each required canonical name reuses
the same pattern list the extraction engine uses. So requiring `Environment`
is satisfied by tags `env`, `stage`, `environmenttype`, etc.; requiring
`Business Owner` is satisfied by `owner`, `ownedby`, `requestor`, …

A required name with no pattern list (e.g. custom `CostCenter`) falls back to
exact normalized equality.

### Step 2 — verdict ladder

```
missing count == 0            → Compliant
0 < missing < total           → Partially compliant (missing: X, Y)
missing count == total:
    resource HAS some tags    → Non-compliant (no required tags)
    resource has NO tags at all
                              → Non-compliant (no required tags)
check disabled (-t "")        → N/A
```

Note the two bottom rungs currently share the same message; presence of tags
alone never softens the verdict — only which required ones matched.

### Worked examples

| Tags on resource | Required set | Verdict |
|---|---|---|
| `env=prod`, `business-owner=a@x.com`, `tech-owner=b@x.com` | Environment, Business Owner, Technical Owner | `Compliant` |
| `environment=prod` | same | `Partially compliant (missing: Business Owner, Technical Owner)` |
| `costcenter=123` | same | `Non-compliant (no required tags)` |
| `{}` | same | `Non-compliant (no required tags)` |
| anything | `-t ""` | `N/A` |

### Blind spots

- Values are **not validated** — `env=TODO` counts as compliant.
- Alias breadth cuts both ways: a tag literally named `tier` satisfies
  `Criticality` because tier appears in its pattern list.

---

## 6. The tag extraction engine

**Functions:** `norm_key`, `tag_lookup`, `infer_environment`
**Columns:** Associated Application ID/Name, Business Unit / Function,
Business Owner, Technical Owner, Support Group, Environment, Criticality,
Data Classification, Customer-Facing, Regulatory Relevance, Lifecycle Status

### Matching algorithm

For each governance field, iterate the resource's tags **in sorted-key order**
(deterministic) and return the first tag whose *normalized* key fully matches
any regex in that field's pattern list:

```
value = first match of fullmatch(pattern_i, norm_key(tag_key))
```

- Empty tag values are treated as absent.
- Pattern lists are ordered most-specific-first, so `^technicalowner$` beats
  `^admin$` when both could apply to different tags.
- First-match-wins means one resource tag can satisfy several fields (e.g.
  `owner` feeds Business Owner; `it-owner` would feed Technical Owner).

### Fallbacks after tag lookup fails

| Field | Fallback | Rule |
|---|---|---|
| Environment | Name inference | Word-boundary scan of `"{resourceGroup} {name}"` against hints, **in priority order**: prod/prd → Production; dev/dvl → Development; uat/stg/preprod → Staging/UAT; qa/test/tst → Test/QA; sbx/sandbox → Sandbox; demo/poc → PoC/Demo. First hit wins, so `preprod` correctly lands Staging/UAT before `prod` sees it. |
| Lifecycle Status | State inference | Only when resolved state is `Deleting`/`Deleted` → `Decommissioning`; otherwise stays empty (never guessed). |

### Worked example

Tags `{application-name: Payments, owner: Alice}` on RG `rg-prod-webapp`:

| Field | Match path | Value |
|---|---|---|
| Associated Application Name | `application-name` → `applicationname` hits `^applicationname$` | Payments |
| Business Owner | `owner` hits `^owner$` | Alice |
| Environment | no env-tag → name inference `\bprod\b` | Production |

---

## 7. Publicly Accessible

**Function:** `public_access(row, props, ctx)`
**Column:** `Publicly Accessible`

Type-dispatched decision table; network chains use the relationship maps built
once per run.

| Type | Logic | Outputs |
|---|---|---|
| Public IP | attached iff `ipConfiguration` present | `Yes` / `Yes (unattached)` |
| NIC | has PIP on any IP configuration? | `Yes (public IP)` / `No` |
| Virtual Machine | walk VM→NICs→PIPs | `Yes (public IP)` / `No` |
| Load Balancer / App Gateway | public frontend IPs? | `Yes (public frontend)` / `No` |
| Storage account | ① `publicNetworkAccess == Disabled` → No; ② else `allowBlobPublicAccess == true` → Yes(blob); ③ else firewall `defaultAction`: Allow → Yes, Deny → Restricted | `No (public access disabled)`, `Yes (blob public access)`, `Yes`, `Restricted (firewall/VNet)` |
| Web app / Function app | `publicNetworkAccess` flag (defaults enabled) | `Yes` / `No (public access disabled)` |
| Key Vault | same flag + firewall default-action pair as storage | `Yes` / `Restricted (firewall/VNet)` / `No (…)` |
| Private endpoint, Private DNS zone | inherently private | `No (private)` |
| Everything else | indeterminate from control plane | `N/A` |

**Worked example chain:** VM `vm1` → NIC `nic1` → `ipConfigurations[0].
publicIPAddress.id` exists ⇒ VM row reads `Yes (public IP)` even though the VM
resource's own properties contain no IP information.

**Blind spots:** a `Yes` says the control plane exposes a public endpoint;
actual reachability depends on NSGs, firewalls and WAFs layered on top. An
unattached PIP still reads `Yes (unattached)` — it *is* a publicly routable
object awaiting association.

---

## 8. Policy Compliance Status

**Data:** ARG `policyresources` table, aggregated server-side to
`{resourceId → set(complianceState)}`.
**Logic (worst-state-wins):**

```
states contains NonCompliant  → "Non-Compliant"
else states contains Compliant → "Compliant"
resource absent from table     → "N/A"
```

`N/A` legitimately means *never evaluated* (no assignment targets it), not
unknown-failure. Column degrades entirely to `N/A` if the policy query lacks
permissions (`--skip-policy` skips it deliberately).

---

## 9. Virtual Network / Subnet and NSG / Network Control

**Functions:** `vnet_subnet()`, `nsg_control()`, fed by `build_network_ctx()`

Resolution order per resource:

```
VM:      vm_to_nics → nic_to_subnet            (relationship path)
NIC:     own ipConfigurations                   (self path)
other:   regex harvest of subnet IDs inside the properties JSON
VNet:    harvested children ∪ own ID (pinned first)
```

NSG resolution adds one hop: whenever a subnet reference was resolved, it is
translated through `subnet_to_nsg` (built from VNet definitions), so
subnet-level controls surface even though the resource itself only references
the subnet. An NSG resource reports `"{name} (this NSG)"`.

Results are deduplicated, capped at 3, joined with `"; "`; absence → `N/A`.

Example outputs:

```
/subscriptions/x/.../virtualNetworks/vnet1/subnets/app-subnet
/subscriptions/x/.../networkSecurityGroups/nsg-app; /subscriptions/x/.../subnets/app-subnet
```

---

## 10. Quick reference — remaining semi-derived fields

| Column | Calculation |
|---|---|
| Parent Resource ID | Split ARM ID on `providers` markers: multiple markers → parent is everything before the last marker (extension-style); single marker with exactly `namespace/type/name` after it → top-level (`N/A`); more segments → drop trailing `childType/childName` pair. Works at any depth (`servers/srv/databases/db` → server). |
| Resource Category | Namespace lookup in `CATEGORY_MAP` (Compute, Networking, Databases, Security…); unknown namespaces → prettified namespace (`microsoft.contoso` → `Contoso`). |
| Region | Slug lookup in `REGION_MAP` (`eastus2` → `East US 2`), else title-cased slug. |
| Availability Zone | Join `zones` array with `"; "`; absent → `N/A`. |
| SKU / Service Tier | `sku.tier / sku.name` when both exist and differ (`Standard / Standard_LRS`), either alone otherwise; falls back to `properties.sku`; else `N/A`. |
| Resource State | Probe properties in order `provisioningState → state → status → powerState.code` (last one trimmed past its `/` prefix, e.g. `PowerState/running` → `running`). None present → `N/A`. Note: VM power state isn't in Resource Graph, so stopped VMs still show their provisioning state. |
| Managed Identity | Map `identity.type`: System-assigned / User-assigned / System + User-assigned / `None`. |
| Management Group | Subscription's ancestor chain from `resourcecontainers`, labels deduped, joined `Root > Child > Leaf`; none → `N/A`. |
| Inventory Last Refreshed | Single UTC timestamp shared by every row in the run. |

---

## 11. Appendix — output value dictionary

Exact strings emitted per column (for filtering/pivot tables).

| Column | Possible values |
|---|---|
| Encryption Status | `Enabled (CMK)` · `Enabled (Microsoft-managed)` · `Enabled (Platform-managed)` · `Enabled (CMK referenced)` · `Enabled (review properties)` · `Disabled` · `N/A` |
| Backup / Recovery Status | `Azure Backup (<workload>)` · `Built-in PITR (platform backups)` · `Automatic backups (platform)` · `Automated backups (platform)` · `Recovery Services vault` · `N/A` |
| Logging and Monitoring Status | Combinations of `Diagnostic settings (logs)` · `Diagnostic settings (metrics only)` · `Data collection rule (monitor agent)` · `Monitoring agent extension` joined by ` + ` · `Not detected` |
| Tag Compliance Status | `Compliant` · `Partially compliant (missing: …)` · `Non-compliant (no required tags)` · `N/A` |
| Policy Compliance Status | `Compliant` · `Non-Compliant` · `N/A` |
| Publicly Accessible | `Yes` · `Yes (unattached)` · `Yes (public IP)` · `Yes (public frontend)` · `Yes (blob public access)` · `No` · `No (public access disabled)` · `Restricted (firewall/VNet)` · `No (private)` · `N/A` |
| Managed Identity | `System-assigned` · `User-assigned` · `System + User-assigned` · `None` |
| Environment (fallback) | `Production` · `Development` · `Staging/UAT` · `Test/QA` · `Sandbox` · `PoC/Demo` (or tagged value, verbatim) |
| Lifecycle Status (fallback) | `Decommissioning` (only when state is Deleting/Deleted) |
| Governance columns (tags) | Verbatim tag values, or `N/A` |

Any cell reading `N/A` means "control plane couldn't answer", never
"lookup error" — errors degrade the same way but are logged to stderr during
the run.
