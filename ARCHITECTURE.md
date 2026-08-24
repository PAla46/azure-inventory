# Architecture — Azure Inventory Exporter

Deep-dive into how `azure_inventory.py` works end-to-end: data sources, query
strategy, enrichment algorithms, error handling, and design trade-offs.

> For the exact decision logic inside each derived value (encryption tree,
> backup priority chain, logging signal composition, tag compliance ladder,
> …), see [CALCULATIONS.md](CALCULATIONS.md).

---

## Table of contents

1. [High-level overview](#1-high-level-overview)
2. [Design principles](#2-design-principles)
3. [End-to-end pipeline](#3-end-to-end-pipeline)
4. [Phase 0 — CLI arguments and configuration](#4-phase-0--cli-arguments-and-configuration)
5. [Phase 1 — Authentication and tenant resolution](#5-phase-1--authentication-and-tenant-resolution)
6. [Phase 2 — Primary acquisition: the Resource Graph mega-query](#6-phase-2--primary-acquisition-the-resource-graph-mega-query)
7. [Phase 3 — Auxiliary datasets](#7-phase-3--auxiliary-datasets)
8. [Phase 4 — Network relationship graph](#8-phase-4--network-relationship-graph)
9. [Phase 5 — Row enrichment pipeline](#9-phase-5--row-enrichment-pipeline)
10. [Phase 6 — Sorting and export](#10-phase-6--sorting-and-export)
11. [Error handling and resilience](#11-error-handling-and-resilience)
12. [Column provenance matrix](#12-column-provenance-matrix)
13. [Performance and scale](#13-performance-and-scale)
14. [Security model](#14-security-model)
15. [Known limitations](#15-known-limitations)
16. [Extension guide](#16-extension-guide)

---

## 1. High-level overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          AZURE CONTROL PLANE                            │
│                                                                         │
│   Azure Resource Graph                    ARM APIs                      │
│   ─────────────────────                   ────────                      │
│   ┌──────────────────────────┐                                          │
│   │ resources                │◄─── main inventory (all properties)      │
│   │ resourcecontainers       │◄─── subscription names + MG chains       │
│   │ policyresources          │◄─── per-resource policy states           │
│   └──────────────────────────┘                                          │
└───────────────▲─────────────────────────────────────────────────────────┘
                │  KQL queries (paginated)
                │
┌───────────────┴─────────────────────────────────────────────────────────┐
│                        azure_inventory.py                               │
│                                                                         │
│   Auth ─► Query ─► Build maps ─► Enrich rows ─► Sort ─► CSV / XLSX      │
│                                                                         │
│   • 1 primary query (resources)                                         │
│   • 3 auxiliary queries (containers, diagnostics, backups, policy)      │
│   • all enrichment done LOCALLY (zero per-resource API calls)           │
└──────────────────────────────┬──────────────────────────────────────────┘
                               ▼
              azure_inventory_<timestamp>.csv / .xlsx
```

**Key architectural decision:** everything that can possibly be derived from
the Resource Graph result set *is* derived locally. The script never makes
per-resource REST calls. This means runtime scales with the number of Graph
*pages* (≈ resources ÷ page-size), not with resource count in terms of API
round-trips — a 50,000-resource tenant takes roughly the same number of HTTP
calls as five 10,000-resource subscriptions.

---

## 2. Design principles

| Principle | How it manifests |
|---|---|
| **Read-only safety** | Only `*/read` scopes used; no mutation possible |
| **Single-plane sourcing** | All data via Resource Graph tables → consistent snapshot semantics, no cross-API drift mid-run |
| **Graceful degradation** | Every auxiliary dataset wrapped in try/except; failure downgrades specific columns to `N/A`, never kills the run |
| **Alias-tolerant tagging** | Tag keys normalized (`business-owner` ≡ `Business_Owner` ≡ `businessowner`) before regex matching, so orgs with inconsistent tagging conventions still populate governance fields |
| **Deterministic output** | Tags iterated in sorted key order; rows sorted post-enrichment → byte-stable CSVs between identical runs (modulo timestamp) |

---

## 3. End-to-end pipeline

`main()` orchestrates six sequential phases:

```
parse_args()
    │
    ▼
get_credential() ── DefaultAzureCredential chain
    │
    ▼
get_arg_client() ── ResourceGraphClient(credential)
    │
    ▼
[Phase 2] run_arg_query(main_query)          ──► rows[]            (core inventory)
    │
    ▼
[Phase 3a] fetch_subscription_metadata()     ──► sub_names{}, sub_mg{}
[Phase 3b] fetch_logging_signals()           ──► logging_map{} + agent_monitored{}
[Phase 3c] fetch_backup_map()                ──► backup_labels{}
[Phase 3d] fetch_policy_compliance()         ──► policy{rid → states}
    │
    ▼
resolve_tenant()                             ──► ctx["tenant"]
build_network_ctx(rows)                      ──► ctx network maps
    │
    ▼
[Phase 5] enrich(row, ctx) for every row     ──► records[]
    │
    ▼
[Phase 6] sort ─► write_csv() / write_xlsx() ──► output files
```

---

## 4. Phase 0 — CLI arguments and configuration

Static configuration lives as module-level constants so it is trivially
editable without touching logic code:

| Constant | Purpose |
|---|---|
| `COLUMNS` | Exact 36-column output contract, in user-specified order |
| `TAG_PATTERNS` | Per-field ordered regex lists for tag extraction (see §9.2) |
| `REQUIRED_TAGS_DEFAULT` | Canonical tags checked by the compliance column |
| `CATEGORY_MAP` | Provider namespace → business category |
| `REGION_MAP` | Region slug → display name (`eastus2` → `East US 2`) |
| `ENV_HINTS` | Ordered `(regex, label)` pairs for environment inference |
| `DIAG_CAPABLE_PREFIXES` | Types probed for diagnostic settings (see §7.2) |
| `PLATFORM_BACKUP` | Services with always-on platform backups (see §7.3) |
| `SUBNET_RE` / `NSG_RE` / `ARM_ID_RE` | Compiled extractors over structured properties |

Runtime toggles come from argparse:

```
-o/--output        output base path (default: ./azure_inventory_<ts>)
-f/--format        auto | csv | xlsx | both
-s/--subscriptions comma list scoping every Graph query
-t/--required-tags overrides REQUIRED_TAGS_DEFAULT ("" disables check)
--page-size        initial ARG page size (default 200, adaptive §6.3)
--fast             drop `properties` from projection (smaller payload,
                   networking/encryption columns degrade to N/A)
--skip-policy      skip the policyresources query entirely
```

`--fast` matters at scale: `properties` dominates payload size ~20:1 versus
metadata columns.

---

## 5. Phase 1 — Authentication and tenant resolution

```python
credential = DefaultAzureCredential()
client     = ResourceGraphClient(credential)
```

`DefaultAzureCredential` walks its provider chain (environment variables →
workload identity → managed identity → shared token cache → Azure CLI →
interactive browser). This makes the script portable across:

| Environment | Credential actually used |
|---|---|
| Workstation after `az login` | `AzureCliCredential` |
| GitHub Actions with OIDC | `EnvironmentCredential` / federation |
| Azure VM / Cloud Shell | `ManagedIdentityCredential` / shell session |
| CI with service principal | env-var secret or cert |

**Tenant ID resolution** (`resolve_tenant`) uses a two-tier strategy:

1. **Preferred:** read the `tenantId` column projected out of Resource Graph —
   free, already fetched.
2. **Fallback:** request a token for `https://management.azure.com/.default`,
   split the JWT, base64url-decode the payload, and pull the `tid` claim.

This covers edge cases such as `--fast` mode (which drops `tenantId` from the
projection).

> **Required RBAC:** Reader on target subscriptions (covers all Graph reads).
> Policy states additionally require `Microsoft.PolicyInsights/policyStates/read`,
> which Reader includes but custom roles may strip.

---

## 6. Phase 2 — Primary acquisition: the Resource Graph mega-query

### 6.1 Query shape

```
resources
| project id, name, type, kind, location, subscriptionId, resourceGroup,
          tags, sku, identity, zones, tenantId, properties
```

Notes on the projection choices:

- **`properties` in full** — deliberately greedy. Dozens of downstream fields
  (VNet refs, NSG refs, public-network flags, encryption config, provisioning
  state, zones fallback…) mine this blob. Fetching it once here avoids any
  later fan-out.
- **`identity` / `sku` / `zones`** — top-level ARG columns (not buried inside
  `properties`), extracted because ARG normalizes them across types.
- `resourcecontainers` (subscriptions/RGs) is intentionally **not** part of the
  row set — only true resources belong in an inventory.

### 6.2 Pagination protocol

ARG returns at most one page plus an opaque continuation token:

```python
while True:
    options = QueryRequestOptions(result_format="objectArray", top=page_size)
    if skip_token: options.skip_token = skip_token
    response = client.resources(QueryRequest(subscriptions, query, options))
    rows.extend(response.data)
    skip_token = response.skip_token
    if not skip_token or not data: break
```

`result_format="objectArray"` yields typed JSON objects (dicts/lists), so
`tags`, `sku`, `identity`, `zones`, `properties` arrive structured rather than
stringified — no re-parsing needed for map building.

### 6.3 Adaptive page size (payload throttling defense)

Large `properties` blobs can trip ARG's response-size ceiling or transient 429s.
`run_arg_query` catches `HttpResponseError` and inspects the message:

```
if page_size > 20 and ("payload" or "too large" or "429" in message):
    page_size = max(20, page_size // 2)
    retry immediately
```

Each failure halves the window (200 → 100 → 50 → … → floor 20) and retries
in place. Continuation tokens remain valid because pagination position is
server-side, not offset-based.

### 6.4 Subscription scoping

`QueryRequest.subscriptions` receives either the explicit `-s` list or `None`.
With `None`, Graph fans out across **every subscription the credential can see**
— no pre-listing round-trip needed. The same scope list is reused verbatim by
all four auxiliary queries in Phase 3, keeping the whole run on one consistent
visibility boundary.

---

## 7. Phase 3 — Auxiliary datasets

Four small Graph queries complete the picture. Each is independently skippable
or failure-tolerant.

### 7.1 Subscription metadata + management group chains

```kql
resourcecontainers
| where type == 'microsoft.resources/subscriptions'
| project subscriptionId, name,
          mgChain = tostring(properties.managementGroupAncestorChain)
```

`managementGroupAncestorChain` is an ordered array of `{displayName, name}`
from the subscription upward through every ancestor management group to the
tenant root. The parser dedupes labels while preserving order and joins them
with `" > "`, e.g.:

```
Tenant Root Group > platform-prod > landingzone-corp
```

so the single **Management Group** column carries full lineage without needing
the Management Groups REST API.

### 7.2 Logging signals (three independent sources)

> **Why not Resource Graph?** ARG does **not** index
> `microsoft.insights/diagnosticSettings` (an extension child resource) — a
> Graph query for it returns zero rows on any tenant. The first version of this
> script relied on exactly that and reported "Not detected" everywhere. The
> logging column therefore aggregates three signals that actually work:

**Signal 1 — Diagnostic settings via Azure Monitor API (threaded probe).**
Resources whose type appears in `DIAG_CAPABLE_PREFIXES` (~35 families: storage,
KV, SQL servers + databases, web apps, NSGs, firewalls, gateways, AKS, ACR,
service bus, event hubs, Cosmos, Redis, workspaces, App Insights, vaults, VMs…)
are probed with `MonitorManagementClient.diagnostic_settings.list(resource_uri)`
through a `ThreadPoolExecutor` (`--workers`, default 8). Extension rows and
child noise are excluded by `_diag_eligible`. Each returned setting is
classified by whether any *log* category or *metric* category is enabled:

```
any logs enabled     →  "Diagnostic settings (logs)"
else any metrics     →  "Diagnostic settings (metrics only)"
setting w/o categories → ignored
```

The best label per resource wins (logs beats metrics-only).

**Signal 2 — Data collection rules (AMA era).** For the same resources the
client's `data_collection_rule_associations.list_by_resource()` is consulted
(guarded by `hasattr` so older SDK versions degrade cleanly). Association
presence ⇒ `"Data collection rule (monitor agent)"`.

**Signal 3 — Monitoring agents already in the inventory.** Because the main
Graph query already fetched every VM extension row, `detect_agent_monitored`
scans those rows locally for known agent names/publishers
(`AzureMonitorLinuxAgent`, `AzureMonitorWindowsAgent`, `OMSAgentForLinux`,
`MicrosoftMonitoringAgent`, `DependencyAgent`,
`Microsoft.EnterpriseCloud.Monitoring`) and credits the parent VM via the
parent-ID parser. Zero extra API calls.

`enrich` composes all three, e.g.
`"Diagnostic settings (logs) + Monitoring agent extension"`, or
`Not detected`.

### 7.3 Backup coverage (three-layer resolution)

ARG also fails to expose `vaults/backupProtectedItems` reliably (zero rows on
real tenants), so backup truth is assembled from three layers:

**Layer 1 — Restore point collections (Graph, free).** Azure Backup materializes
a `Microsoft.Compute/restorePointCollections` resource per protected VM/disk,
and its properties embed the *source* resource ID. One extra Graph query over
those rows feeds every property blob through `collect_arm_ids` — a recursive
walker that harvests **all** ARM-ID-shaped strings from parsed JSON (handles
`sourceResourceId`, `virtualMachineId`, nested lists, arbitrary schemas).

**Layer 2 — Vault scan (authoritative).** For each Recovery Services vault
already present in the inventory rows, the Backup Management API
(`RecoveryServicesBackupClient.backup_protected_items.list`) is queried in a
thread pool. This returns every protected item — IaaS VMs, **disks**, **SQL
in-VM databases**, SAP HANA, file shares — with its workload type. Source IDs
are extracted with the same walker and stored as labels like
`"Azure Backup (AzureDisk)"` / `"Azure Backup (MAB)"`. Failures are isolated
per vault.

**Layer 3 — Platform-native backups.** Some services are always backed up by
the platform and never appear in a vault; `PLATFORM_BACKUP` maps them to
explicit labels:

```
SQL databases (PaaS & MI)   → Built-in PITR (platform backups)
Cosmos DB accounts          → Automatic backups (platform)
PostgreSQL/MySQL Flexible   → Automated backups (platform)
```

Enrichment priority: explicit vault protection → platform-native →
`Recovery Services vault` (for vault rows themselves) → `N/A`.

### 7.4 Policy compliance

```kql
policyresources
| where type =~ 'microsoft.policyinsights/policystates'
| extend rid = tostring(properties.resourceId),
         cs  = tostring(properties.complianceState)
| summarize states = make_set(cs) by rid
```

Server-side `make_set` collapses the (potentially huge) state-per-assignment
fan-out to one row per resource carrying the distinct compliance verdicts.
Client-side aggregation applies worst-state-wins:

```
any NonCompliant  →  Non-Compliant
else any Compliant →  Compliant
absent             →  N/A   (never evaluated by any assignment)
```

Wrapped in try/except in `main()` — tenants where the caller lacks policy-read
scope degrade the column to `N/A` with a stderr warning instead of aborting.

---

## 8. Phase 4 — Network relationship graph

`build_network_ctx(rows)` makes **one pass** over the already-fetched rows and
materializes six lookup structures that encode Azure's implicit network
containment graph:

| Structure | Direction | Populated from |
|---|---|---|
| `pip_attached: set` | PIP → is it bound to anything? | PIP `properties.ipConfiguration` presence |
| `nic_to_pips: dict[list]` | NIC → its public IPs | NIC `ipConfigurations[].publicIPAddress.id` |
| `nic_to_subnet: dict` | NIC → subnet | NIC `ipConfigurations[].subnet.id` |
| `nic_to_nsg: dict` | NIC → NSG | NIC `networkSecurityGroup.id` |
| `subnet_to_nsg: dict` | Subnet → NSG | VNet `subnets[].networkSecurityGroup.id` |
| `vm_to_nics: dict[list]` | VM → NICs | VM `networkProfile.networkInterfaces[].id` |
| `lb_to_pips: dict[list]` | LB/AppGW → frontend PIPs | `frontendIPConfigurations[].publicIPAddress.id` |

Because ARG's `resources` table already contains NICs, VNets, and PIPs as
first-class rows, these edges cost **zero additional API calls** — the classic
inventory trick: resolve relationships locally that would otherwise require
thousands of GETs.

All keys/values are raw ARM IDs; comparisons during enrichment use exact-case
IDs as returned by Graph (consistent within one snapshot).

Per-row exceptions during map building are swallowed (`AttributeError`,
`TypeError`) — malformed or exotic schemas simply contribute no edges.

---

## 9. Phase 5 — Row enrichment pipeline

`enrich(row, ctx)` converts one Graph row into one ordered output record.
Conceptually it runs five sub-engines:

```
row ─► [tag engine] ─► [structural parsers] ─► [network resolver]
          │                   │                       │
          ▼                   ▼                       ▼
     governance cols    parent/category/etc      pub-access/vnet/nsg
                              │
                              ▼
                     [security & ops engines]
                      encryption / policy / diag / backup
```

### 9.1 Structural parsers

**Parent Resource ID** (`parent_resource_id`) — pure ARM-ID algebra. Split the
ID on segments, locate `providers` markers:

- **No `providers`** → container-level object → `N/A`.
- **Multiple markers** → extension-style child
  (`.../vm/providers/Microsoft.Insights/extensions/ext`). Parent = everything
  before the final marker → the VM's ID.
- **Single marker** → compare trailing segment count against the canonical
  `{namespace}/{type}/{name}` triple:
  - exactly 3 → top-level resource → `N/A`
  - >3 → nested child (e.g. `servers/srv/databases/db`): drop the last two
    segments → server ID. Works for arbitrary depth (VNets→subnets,
    sites→slots, vaults→secrets).

**Category** (`resource_category`) — namespace lookup in `CATEGORY_MAP`;
unknown namespaces fall back to a prettified namespace
(`microsoft.contoso` → `Contoso`). Network leaf special-cases (DNS zones etc.)
are pinned to `Networking`.

**Region** — `REGION_MAP` slug lookup, else generic title-casing.

**SKU** (`sku_str`) — prefers `sku.name`, prepends `sku.tier` when distinct
(`Standard / Standard_LRS`); falls back to `properties.sku` for types that
embed it there; else `N/A`.

**State** (`resource_state`) — probes properties in priority order
`provisioningState` → `state` → `status` → `powerState.code`; first string hit
wins. (VM power state is *not* exposed by Graph — see §15.)

### 9.2 Tag extraction engine

Azure tag keys arrive as-is; org conventions vary wildly. The engine therefore
normalizes both sides before matching:

```python
norm_key("Business-Owner")  ==  norm_key("business_owner")  ==  "businessowner"
```

Then each output field owns an **ordered pattern list** in `TAG_PATTERNS`.
Matching semantics:

- `re.fullmatch` against the normalized key (anchored by construction).
- Tags iterated in **sorted-key order** → deterministic winner when several
  tags could satisfy one field.
- First matching pattern wins; empty values are treated as absent.

Example — field *"Associated Application Name"*:

| Tag on resource | Normalized | Matches pattern | Result |
|---|---|---|---|
| `application-name: Payments` | `applicationname` | `^applicationname$` | ✅ wins |
| `app: payments-api` | `app` | `^app$` | (would win if #1 absent) |

Pattern ordering encodes specificity: multi-word keys
(`^technicalowner$`) precede loose ones (`^admin$`), so precise matches beat
generic collisions.

**Environment fallback** — when no environment-tagged key matched, the
concatenated `"{resourceGroup} {name}"` string is scanned against `ENV_HINTS`
with word boundaries and priority ordering:

```
prod/prd → Production   (checked first, so "preprod" does NOT false-match)
dev/dvl  → Development
uat/stg/preprod → Staging/UAT
qa/test  → Test/QA
sbx/sandbox → Sandbox
demo/poc → PoC/Demo
```

**Lifecycle fallback** — untagged resources inherit `Decommissioning` iff
their resolved state is `Deleting`/`Deleted`; otherwise `N/A` (never guessed).

**Tag Compliance Status** — alias-aware by reusing the same pattern lists:
required tag `Environment` counts as present if *any* tag satisfies any
`Environment` pattern (`env`, `stage`, `deploymentenvironment`, …). Unknown
required names fall back to exact normalized equality. Verdict ladder:

```
0 missing            → Compliant
some missing         → Partially compliant (missing: X, Y)
all missing          → Non-compliant (no required tags)
check disabled (-t)  → N/A
```

### 9.3 Public accessibility resolver

Type-dispatched decision table, using Phase-4 maps for attached resources:

| Resource type | Logic |
|---|---|
| `publicIPAddresses` | `Yes`; suffix `(unattached)` when no `ipConfiguration` |
| `networkInterfaces` | `Yes (public IP)` iff `nic_to_pips[id]` non-empty |
| `virtualMachines` | walk `vm_to_nics` → any NIC with PIP ⇒ yes |
| `loadBalancers` / `applicationGateways` | `Yes (public frontend)` via `lb_to_pips` |
| `storageAccounts` | three-stage: `publicNetworkAccess==Disabled` ⇒ No; `allowBlobPublicAccess==true` ⇒ `Yes (blob public access)`; else firewall `defaultAction` Allow ⇒ Yes / Deny ⇒ `Restricted (firewall/VNet)` |
| `web/sites`, `web/functions` | `publicNetworkAccess` flag (defaults Yes) |
| `keyVault/vaults` | same flag + firewall default-action pair as storage |
| private endpoints / private DNS | hard `No (private)` |
| everything else | `N/A` (indeterminate from control plane alone) |

### 9.4 VNet/Subnet and NSG resolvers

Resolution strategy differs by topology visibility:

```
VMs:      vm_to_nics ─► nic_to_subnet            (relationship path)
NICs:     direct from own ipConfigurations       (self path)
others:   SUBNET_RE scan over serialized props   (grep path)
VNets:    grep path ∪ self-ID (pinned first)
```

The **grep path** is the universal fallback: any `/subscriptions/…/
virtualNetworks/{vnet}(/subnets/{subnet})?` occurrence inside the resource's
JSON properties is harvested (private endpoints, App Gateway configs, firewall
`subnetRef`s, SQL VNet rules, …). Results dedupe, cap at 3, join with `"; "`.

NSG resolution mirrors this and adds one extra hop — subnet→NSG translation
through `subnet_to_nsg`, so *subnet-level* controls surface even though the
resource itself references only the subnet. An NSG resource reports itself as
`"{name} (this NSG)"`.

### 9.5 Managed Identity

Direct read of top-level `identity.type` mapped to human phrasing
(`SystemAssigned` → `System-assigned`, combo type → `System + User-assigned`,
absent → `None`).

### 9.6 Encryption decision engine

Ordered from most-specific to most-generic signal:

```
storage accounts   keySource == Microsoft.Keyvault → CMK
                   services.*.enabled              → Microsoft-managed
                   none enabled                    → Disabled
disks/snapshots    encryption.type CustomerKey     → CMK
                   any other type                  → Platform-managed
key vaults         always Platform-managed
any resource       diskEncryptionSetId / keyVaultUri /
                   customermanagedkey in props     → CMK referenced
any resource       literal "encryption" key present → Enabled (review properties)
otherwise                                            N/A
```

Generic signals operate on the lowercased serialized properties blob, so newly
introduced services with CMK idioms still light up without script changes.

### 9.7 Logging / Backup columns

Pure set-membership against Phase-3 results:

```
Logging:  logging_map[rid] → "Diagnostic settings (logs)" / "(metrics only)"
                            / "Data collection rule (monitor agent)"
          rid ∈ agent_monitored → append " + Monitoring agent extension"
          none of the above → "Not detected"
Backup:   rid ∈ backup_labels → "Azure Backup (<workload>)"
          type ∈ PLATFORM_BACKUP → "Built-in PITR (platform backups)" etc.
          vault row → "Recovery Services vault"
          otherwise → N/A
```

---

## 10. Phase 6 — Sorting and export

Records sort by `(Subscription Name, Resource Group, Type, Name)` giving
stable, human-navigable grouping in both formats.

**CSV writer** — stdlib `csv`, UTF-8 with BOM (`utf-8-sig`) so Excel opens it
with correct encoding by double-click.

**XLSX writer** — raw openpyxl (no pandas dependency):

- bold header row, freeze panes at `B2` (header + ID column pinned),
- auto-filter across the full range,
- column widths computed from the longest cell up to 60 chars (sampled over
  first 500 rows for speed),
- cells truncated at Excel's 32,767-char hard limit.

Default format (`auto`) picks xlsx when openpyxl imports cleanly, else csv —
Cloud Shell minimal images degrade gracefully.

---

## 11. Error handling and resilience

| Failure | Handling | Blast radius |
|---|---|---|
| ARG payload too large / 429 | halve page size, retry (§6.3) | latency only |
| Aux query throws (policy perms, etc.) | caught in `main()` → warn, continue | single column = N/A |
| Per-vault backup probe fails | isolated per vault in the thread pool | that vault's items missing |
| Diag probe fails on a resource | silently counted as no-signal | resource shows Not detected |
| Monitor SDK lacks DCR API | `hasattr` guard skips signal 2 | fewer logging labels |
| Malformed row during enrichment | per-row try/except → skipped with stderr note | one resource missing |
| Map-building anomaly | swallowed per-row in `build_network_ctx` | missing edges only |
| No credentials available | exception surfaces with SDK message | clean abort pre-query |
| Zero resources returned | explicit early exit, exit code 1 | clean abort |
| Ctrl-C | `KeyboardInterrupt` trap → exit 130 | clean abort |

Design stance: **auxiliary intelligence is optional, core inventory is not.**
Only a total failure of the primary query aborts the run.

---

## 12. Column provenance matrix

| # | Column | Source | Function |
|---|---|---|---|
| 1 | Azure Resource ID | ARG `id` | — |
| 2 | Resource Name | ARG `name` | — |
| 3 | Resource Type | ARG `type` | — |
| 4 | Resource Category | derived | `resource_category` |
| 5 | Parent Resource ID | parsed | `parent_resource_id` |
| 6 | Tenant | ARG / JWT | `resolve_tenant` |
| 7 | Management Group | containers chain | `fetch_subscription_metadata` |
| 8–10 | Sub ID / Sub name / RG | ARG + containers | — |
| 11 | Region | ARG + map | `pretty_region` |
| 12 | Availability Zone | ARG `zones` | join |
| 13 | SKU / Service Tier | ARG `sku` (+props) | `sku_str` |
| 14 | Resource State | props probe | `resource_state` |
| 15–26 | Governance ×12 | tag engine (+fallbacks) | `tag_lookup`, `infer_environment` |
| 27 | Publicly Accessible | computed | `public_access` + net ctx |
| 28 | Virtual Network / Subnet | computed | `vnet_subnet` |
| 29 | NSG / Network Control | computed | `nsg_control` |
| 30 | Managed Identity | ARG `identity` | `managed_identity_str` |
| 31 | Tag Compliance Status | computed | `tag_compliance` |
| 32 | Policy Compliance | policyresources | `fetch_policy_compliance` |
| 33 | Encryption Status | computed | `encryption_status` |
| 34 | Logging & Monitoring | Monitor API + DCR + agent scan | `fetch_logging_signals`, `detect_agent_monitored` |
| 35 | Backup / Recovery | RPCs + vault API + platform map | `fetch_backup_map`, `PLATFORM_BACKUP` |
| 36 | Inventory Last Refreshed | run clock | constant per run |

---

## 13. Performance and scale

API-call count is effectively **constant** (~5 queries × pages) regardless of
estate size; memory grows linearly with resource count since all enrichment is
local.

Rough budget for common sizes (page-size 200):

| Resources | Approx. pages | Wall time (typ.) |
|---|---|---|
| 1 k | ~5–10 | seconds |
| 25 k | ~130+aux | < 2 min |
| 100 k+ | ~500+aux | minutes; prefer `--fast` |

Levers: `--page-size` up (fewer calls, larger payloads) or down (throttled
tenants); `--fast` (drops the heavy `properties` blob, sacrificing §9.3–§9.6
columns); `--skip-policy`; `-s` scoping.

Peak RSS ≈ raw JSON of all rows × ~1.5 (maps + output copies) — hundreds of MB
at 100k resources, comfortably inside Cloud Shell limits.

---

## 14. Security model

- **Least privilege**: needs only Reader (+ policy-state read). No write
  scopes exist anywhere in the call surface.
- **No secret persistence**: credentials live inside `DefaultAzureCredential`;
  nothing is logged except row counts and file paths. The JWT decode in
  `resolve_tenant` touches only the public `tid` claim.
- **Data residency**: output lands wherever you run it — mind that an
  inventory of tagged owners/classifications is itself sensitive; treat
  exported files accordingly.
- **Snapshot consistency**: all reads occur within one short window; no
  long-lived tokens or cached state between runs.

---

## 15. Known limitations

1. **VM power state** — Graph doesn't index `instanceView`; stopped/deallocated
   VMs still report `Succeeded`. Would require per-VM compute calls (rejected
   for scale reasons).
2. **Diagnostic-setting destinations** — the probe classifies log vs metric
   categories, but doesn't verify data actually reaches the workspace; DCR
   coverage depends on the installed `azure-mgmt-monitor` version.
3. **Public-access heuristics** — types outside the decision table report
   `N/A`; WAF/Firewall frontends aren't traced.
4. **Policy freshness** — policy states reflect Graph's indexed snapshot
   (typically ≤ 15 min behind live evaluation).
5. **Tag regex collisions** — first-match-wins means an org using `owner` for
   technical owners will populate Business Owner instead; tune patterns.
6. **Extension resources** (VM extensions etc.) appear as inventory rows
   themselves since they're in `resources`; harmless noise with valid parents.
7. **Logging probe surface** — only types listed in `DIAG_CAPABLE_PREFIXES`
   are probed for diagnostic settings; exotic types may be missed, and the
   probe adds ~1 API call per eligible resource (tune with `--workers` or skip
   via `--skip-logging`).

---

## 16. Extension guide

| Want to… | Touch |
|---|---|
| Support your tagging standard | `TAG_PATTERNS` entries |
| Change compliance requirements | `-t` flag or `REQUIRED_TAGS_DEFAULT` |
| Add a derived column | append to `COLUMNS`, compute in `enrich`, add writer-safe value |
| Add another data plane (e.g. Defender secure score) | new `fetch_*` querying the relevant Graph table (`securityresources`), merge into `ctx` |
| New category mapping | `CATEGORY_MAP` |
| Different region naming | `REGION_MAP` |

New aux datasets should follow the established contract: single Graph query →
lowercased keyed set/dict in `ctx` → set-membership or lookup inside `enrich` →
wrapped in try/except in `main()` so failure degrades to `N/A`.
