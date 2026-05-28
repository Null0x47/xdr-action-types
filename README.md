# Defender XDR Action Types

> [!NOTE]
> This is a Python script inspired by the `Get-DefenderSchema.ps1` PowerShell script in the [ml58158/defender-xdr-advanced-hunting](https://github.com/ml58158/defender-xdr-advanced-hunting) repository. Credits goes to the maintainer of this project.

`get_defender_action_types.py` pulls the Advanced Hunting ActionTypes from the
Defender XDR internal huntingService API and writes them to JSON.

## Prerequisites

- Python3
- An active `security.microsoft.com` portal session

## Getting credentials

From the portal, open DevTools → Application → Cookies for `security.microsoft.com`:

- `--session-cookie` — the `sccauth` cookie value
- `--xsrf-token` — the `XSRF-TOKEN` cookie value (URL-encoded copy is fine)
- `--tenant-id` — your Entra ID tenant GUID

These cookies are session-bound and expire; refresh them from the portal as needed.

## Usage

```bash
python3 get_defender_action_types.py \
    --session-cookie "wN6c4hZ-x7II..." \
    --xsrf-token "CfDJ8N..." \
    --tenant-id "27c9901b-9650-4f50-b9b3-38611d797f9f"
```

Optional flags:

- `--output` — flat output path (default `./action-types.json`)
- `--output-grouped` — grouped output path (default `./action-types-grouped.json`)
- `--tables` — space-separated list of specific tables (default: all known tables)

## Output

Two files are written:

- **`action-types.json`** — flat list, one object per ActionType with `Table`, `Name`, `Description`.
- **`action-types-grouped.json`** — keyed by table name, each value a list of `{Name, Description}`.
