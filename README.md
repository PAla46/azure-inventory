# Azure Inventory Exporter

One-shot script that produces a complete inventory of every Azure resource your
credentials can see, exported to CSV and/or Excel. Built on **Azure Resource
Graph** (single query across all subscriptions), enriched locally with derived
governance, networking, security, and operations attributes.

> **Docs:** [ARCHITECTURE.md](ARCHITECTURE.md) — system design and data flow ·
> [CALCULATIONS.md](CALCULATIONS.md) — exact decision logic behind every derived field

## Setup

```bash
pip install -r requirements.txt
az login          # or set AZURE_CLIENT_ID/SECRET/TENANT, or run on an Azure VM with MI
```

## Usage

```bash
# Everything, both formats (xlsx if openpyxl installed)
python azure_inventory.py

# Specific subscriptions only, CSV only
python azure_inventory.py -s 00000000-0000-0000-0000-000000000000 -f csv

# Custom required tags for the compliance column (empty = disable check)
python azure_inventory.py -t "Environment,Business Owner,CostCenter"

# Fast mode: skip property fetch (VNet/NSG/public-access/encryption become N/A)
python azure_inventory.py --fast

# Skip the policy compliance lookup (needs Policy Insights read access)
python azure_inventory.py --skip-policy
```

Output defaults to `azure_inventory_<timestamp>.csv/.xlsx` in the current
directory; override with `-o /path/to/basename`.

## Field sourcing

| Field | Source |
|---|---|
| Resource ID / Name / Type | Resource Graph (direct) |
| Resource Category | Mapped from provider namespace (`CATEGORY_MAP`) |
| Parent Resource ID | Parsed from ARM ID nesting |
| Tenant | Token claim / ARG `tenantId` |
| Management Group | ARG `resourcecontainers` ancestor chain |
| Subscription ID / Name | ARG + `resourcecontainers` |
| Resource Group / Region | ARG (`REGION_MAP` prettifies slugs) |
| Availability Zone | `properties.zones` where present |
| SKU / Service Tier | `sku.name` / `sku.tier` |
| Resource State | `provisioningState` / `state` / `status` props |
| Application ID/Name, Business Unit, Owners, Support Group, Environment, Criticality, Data Classification, Customer-Facing, Regulatory, Lifecycle | **Regex scan of all tags** (`TAG_PATTERNS`, first match wins) |
| Environment fallback | Inferred from resource/RG name (`prod`, `dev`, `uat`, ...) if untagged |
| Publicly Accessible | Cross-references public IPs ↔ NICs ↔ VMs/LBs; storage/web/keyvault public-network flags |
| Virtual Network / Subnet | Subnet refs in properties; VMs resolved via their NICs |
| NSG / Network Control | NSG refs on NIC/subnet properties, subnet→NSG map from VNets |
| Managed Identity | `identity.type` |
| Tag Compliance Status | Required tags present? Alias-aware (`env` satisfies `Environment`) |
| Policy Compliance Status | ARG `policyresources` policy states (worst state wins) |
| Encryption Status | Per-type: storage keySource, disk encryption type, CMK references |
| Logging & Monitoring | Three signals: diagnostic settings via Monitor API (log vs metric categories), data-collection-rule associations, and monitoring-agent extensions detected in the inventory itself |
| Backup / Recovery | Restore point collection sources (Graph) + per-vault protected-item scan (disks, VMs, SQL/HANA workloads) + platform-built-in backups (SQL PaaS, Cosmos DB, PG/MySQL Flexible) |
| Inventory Last Refreshed | Run timestamp |

Anything not determinable is `N/A`.

## Customization

Edit at the top of `azure_inventory.py`:

- `TAG_PATTERNS` — per-field regexes matched against normalized tag keys
  (lowercase, separators stripped: `business-owner` → `businessowner`). Add
  your org's tag names here.
- `REQUIRED_TAGS_DEFAULT` — tags used by the compliance column.
- `CATEGORY_MAP` — namespace → category mapping.
- `ENV_HINTS` — name-based environment inference rules.

## Notes & limitations

- Requires Reader across the target subscriptions; policy states additionally
  need `Microsoft.PolicyInsights/policyStates/read`.
- VM power state isn't exposed by Resource Graph — state shows provisioning
  state (`Succeeded`), not Running/Stopped.
- Large estates: if you hit payload errors the script auto-halves page size;
  you can also start smaller with `--page-size 50`.
- Diagnostic settings are probed live via the Azure Monitor API for known
  diag-capable types (Resource Graph does not index them); tune with
  `--workers` / `--skip-logging`. Backup truth combines restore point
  collections, per-vault protected-item scans, and platform-native backup rules.
