# Prisma Access DLP Synchronization Tool

A Python tool for synchronizing Data Loss Prevention (DLP) configuration between Palo Alto Networks Prisma Access tenants. Maintains consistent DLP policies across multiple environments by replicating custom data patterns and data profiles.

![quick_demo](https://github.com/amimran01/pa-dlp-config-sync/refs/heads/main/quick_demo.gif)

## Features

- **Two-Stage Sync**: Data patterns first, then data profiles
- **Intelligent Comparison**: Deep diff detects actual changes while ignoring metadata
- **Automatic ID Remapping**: Handles different IDs across tenants
- **Multi-Tenant Support**: Sync to multiple destinations in one run
- **Dry-Run Mode**: Preview changes before applying (default)
- **Selective Sync**: Target specific tenants or sync all at once

## Installation

```bash
git clone https://github.com/amimran01/pa-dlp-config-sync
cd pa-dlp-config-sync
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration

Create `config.yaml` in the project root:

```yaml
source:
  service_account: 'api-account@1234567890.iam.panserviceaccount.com'
  api_key: 'your-api-key-here'
  tsg_id: '1234567890'
  name: 'Dev'

destinations:
  - service_account: 'api-account@0987654321.iam.panserviceaccount.com'
    api_key: 'your-api-key-here'
    tsg_id: '0987654321'
    name: 'Staging'
  - service_account: 'api-account@0987654321.iam.panserviceaccount.com'
    api_key: 'your-api-key-here'
    tsg_id: '0987654321'
    name: 'Production'
```

**Fields**: `service_account` (service account), `api_key` (API key), `tsg_id` (Tenant Service Group ID), `name` (friendly name)

## Usage

```bash
# Dry-run (no changes)
python pa_sync.py

# Sync specific tenant(s)
python pa_sync.py --execute --tenant "Production"
python pa_sync.py --execute -t "Production" -t "Staging"

# Sync all tenants
python pa_sync.py --execute --all

# Interactive mode (confirm each tenant)
python pa_sync.py --execute
```

**Options**:
- `--execute`: Execute synchronization (without this, runs in dry-run mode)
- `--all`: Sync all destinations without confirmation
- `--tenant NAME` or `-t NAME`: Target specific tenant(s)

## How It Works

1. **Authentication**: Connects to source and destination tenants
2. **Data Patterns**: Syncs custom patterns, builds ID mappings
3. **Data Profiles**: Syncs profiles with remapped pattern/profile IDs

**Synced**: Custom data patterns and profiles (name, description, rules, expressions)  
**Excluded**: Metadata fields (`id`, `tenant_id`, `created_at`, `updated_at`, `version`)


## Limitations
- Only sync data patterns and profiles as of now
