# forti2versa

Convert FortiGate firewall configurations to Versa SD-WAN service template format.

Parses the full FortiGate config and produces ready-to-import Versa template files — both flat (`set` commands) and structured (curly-brace Director format).

> A web-based version is also available at [versa-tools.net/convert](https://versa-tools.net/convert) — no installation required.

## Quick Start

Download the binary for your platform from [Releases](../../releases), then:

```bash
# Linux / macOS
chmod +x forti2versa-*
./forti2versa firewall.conf -t MY-TEMPLATE -n MY-ORG

# Windows (PowerShell)
.\forti2versa-windows-amd64.exe firewall.conf -t MY-TEMPLATE -n MY-ORG
```

Three files are produced:

| File | Format | Purpose |
|------|--------|---------|
| `MY-TEMPLATE.cfg` | Flat `set` commands | Paste into Director CLI via `load merge terminal` |
| `MY-TEMPLATE_4director.cfg` | Structured curly-brace | Import via Director REST API or `load merge` from file |
| `MY-TEMPLATE_report.txt` | Plain text | Conversion report — every converted, skipped, and warned object |

## What Gets Converted

| FortiGate Object | Versa Template Object | Notes |
|---|---|---|
| Firewall Addresses (ipmask, FQDN, geography) | Objects → Addresses | IP ranges auto-expanded to CIDRs. Country codes mapped to `match region`. |
| Wildcard FQDN Addresses | Objects → Addresses (FQDN) | Requires DNS Proxy enabled on VOS. |
| Address Groups | Objects → Address Groups | Nested groups preserved. Geography members handled inline in rules. |
| Custom Services (TCP/UDP/SCTP/ICMP/IP) | Objects → Services | Port ranges, multi-protocol entries supported. Source ports noted in warnings. |
| Service Groups | Objects → Service Groups | Predefined FortiGate services mapped to Versa predefined equivalents. |
| Firewall Policies | Access Policy Rules | Full 1-to-1 conversion. Action, zones, addresses, services, users, groups, schedules, logging. |
| Webfilter Profiles | URL Filtering Profiles | FortiGuard category IDs mapped to Versa predefined URL categories. |
| Application Control Lists | Match application + app-family | FortiGate app IDs and categories mapped to Versa predefined applications. |
| SSL/SSH Inspection Profiles | Decryption Policy Rules | Deep inspection → decrypt rules. Certificate inspection → SSL exempt rules. |
| AV / IPS / DNS Filter profiles | Security profile references | Mapped via config to Versa predefined profile names. |
| Schedules (recurring / one-time) | Schedule Objects | Daily/weekly time ranges. One-time schedules converted to non-recurring. |

## Installation

### Pre-compiled Binaries

Download from the [Releases](../../releases) page:

| Platform | Architecture | Binary |
|----------|-------------|--------|
| Linux | x86_64 (Intel/AMD) | `forti2versa-linux-amd64` |
| Linux | ARM64 (AWS Graviton, etc.) | `forti2versa-linux-arm64` |
| macOS | Intel | `forti2versa-darwin-amd64` |
| macOS | Apple Silicon (M1–M4) | `forti2versa-darwin-arm64` |
| Windows | x86_64 (Intel/AMD) | `forti2versa-windows-amd64.exe` |
| Windows | ARM64 | `forti2versa-windows-arm64.exe` |

### Build from Source

Requires **Go 1.22+** (no external dependencies).

```bash
git clone https://github.com/mihailvovk/forti2versa.git
cd forti2versa
go build -o forti2versa ./cmd/cli/
```

Cross-compile:

```bash
GOOS=linux   GOARCH=amd64 go build -o forti2versa-linux-amd64       ./cmd/cli/
GOOS=linux   GOARCH=arm64 go build -o forti2versa-linux-arm64       ./cmd/cli/
GOOS=darwin  GOARCH=amd64 go build -o forti2versa-darwin-amd64      ./cmd/cli/
GOOS=darwin  GOARCH=arm64 go build -o forti2versa-darwin-arm64      ./cmd/cli/
GOOS=windows GOARCH=amd64 go build -o forti2versa-windows-amd64.exe ./cmd/cli/
GOOS=windows GOARCH=arm64 go build -o forti2versa-windows-arm64.exe ./cmd/cli/
```

## Usage

```
forti2versa <input.conf> [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-c` | `converter_config.json` | Path to converter configuration JSON file |
| `-o` | `<template_name>.cfg` | Output path for the flat Versa config |
| `-r` | `<template_name>_report.txt` | Output path for the conversion report |
| `-t` | *(from config)* | Versa template name (overrides config file) |
| `-n` | *(from config)* | Versa tenant/organization name (overrides config file) |

### Examples

```bash
# Minimal — template and org from CLI flags
./forti2versa firewall.conf -t BRANCH-FW -n ACME-CORP

# With full configuration file
./forti2versa firewall.conf -c converter_config.json

# Custom output paths
./forti2versa firewall.conf -t BRANCH-FW -n ACME-CORP -o versa-output.cfg -r report.txt
```

## Configuration File

For fine-grained control over zone mapping, schedules, and security profiles, create a `converter_config.json`:

```json
{
  "template_name": "BRANCH-FIREWALL",
  "org_name": "ACME-CORP",
  "policy_name": "Default-Policy",
  "interface_zone_map": {
    "wan1": "WAN-Zone",
    "port1": "LAN-Zone",
    "port2": "LAN-Zone",
    "dmz": "DMZ-Zone",
    "ssl.root": "RAVPN-Zone",
    "internal": "Internal-Zone",
    "guest-vlan": "Guest-Zone"
  },
  "skip_orphans": true,
  "schedule_map": {
    "Business_Hours": "08:00-17:00"
  },
  "security_profile_map": {
    "av-profile": {
      "AV_drop_default": "Scan Web and Email Traffic",
      "AV_monitor_default": "Scan Web Traffic"
    },
    "ips-sensor": {
      "IPS_drop_default": "Versa Recommended Profile",
      "IPS_monitor_all": "All Attack Rules"
    },
    "webfilter-profile": {
      "Shore_Strict_Allow": "corporate",
      "Block_All_Web": "block_all"
    },
    "dnsfilter-profile": {
      "DNS_Filter_Default": "Versa Recommended"
    }
  }
}
```

### Configuration Reference

| Field | Required | Description |
|-------|----------|-------------|
| `template_name` | Yes | Name for the Versa service template. Used in all `set devices template <NAME>` commands. |
| `org_name` | Yes | Versa organization/tenant name. Used in `config orgs org-services <ORG>`. |
| `policy_name` | No | Access policy group name. Default: `Default-Policy` |
| `interface_zone_map` | Yes | Maps FortiGate interface names to Versa zone names. Every interface used in firewall policies must be mapped. |
| `skip_orphans` | No | When `true` (default), skips addresses/services not referenced by any policy. |
| `schedule_map` | No | Maps FortiGate schedule names to time ranges (`HH:MM-HH:MM`). Unmapped schedules get a placeholder with a warning. |
| `security_profile_map` | No | Maps FortiGate security profile names to Versa predefined profile names, organized by type. |

### Interface Zone Mapping

Every FortiGate interface referenced in firewall policies needs a corresponding Versa zone. Common mappings:

| FortiGate Interface | Suggested Versa Zone |
|---|---|
| `wan1` | `Intf-Internet-Zone` or `WAN-Zone` |
| `wan2` | `Intf-Internet-2-Zone` |
| `port1` | `Intf-LAN-Zone` or `LAN-Zone` |
| `port2`, `port3` | `Intf-LAN-2-Zone`, `Intf-LAN-3-Zone` |
| `dmz` | `Intf-DMZ-Zone` or `DMZ-Zone` |
| `ssl.root` | `RAVPN-Zone` |
| `internal` | `Intf-Internal-Zone` |
| `loopback` | `Intf-Mgmt-Zone` |

> **Tip:** Zone names must match zones configured on your Versa Director template. The [web portal](https://versa-tools.net/convert) auto-suggests zone mapping based on detected interfaces.

## Example Workflow

### 1. Export FortiGate Config

From the FortiGate CLI or GUI, export the full configuration backup (`.conf` file). The file should start with a version header:

```
#config-version=FGT60D-5.02-FW-build670-140314:opmode=0:vdom=0:user=admin
```

### 2. Run Conversion

```
$ ./forti2versa firewall.conf -c converter_config.json

Parsed: 35 addresses, 0 wildcard-fqdns, 14 address groups, 25 services,
  11 service groups, 4 webfilter profiles, 2 app-control profiles,
  3 ssl-ssh profiles, 2 url-filter tables, 0 onetime schedules, 26 policies
Versa config written to: BRANCH-FIREWALL.cfg
Conversion report written to: BRANCH-FIREWALL_report.txt
Structured config written to: BRANCH-FIREWALL_4director.cfg
```

### 3. Review Report

Check the report for warnings or skipped objects. Common warnings:

- **Unmapped interface** — add the interface to `interface_zone_map` and re-run
- **No security profile mapping** — add the FortiGate → Versa profile name to `security_profile_map`
- **Schedule placeholder** — add the schedule name and time range to `schedule_map`
- **NAT enabled** — Versa uses CGNAT which requires separate configuration
- **Traffic shaper** — Versa QoS uses Class of Service, requires manual config

### 4. Import into Versa Director

Using the flat config via CLI:

```
admin@versa-director> configure
admin@versa-director% load merge terminal
<paste flat config contents>
^D
admin@versa-director% commit
```

Or use the structured config (`_4director.cfg`) via the Director REST API.

## Testing

```bash
go test ./...
```

The test suite includes:

- **Parser tests** — validates FortiGate config parsing (addresses, services, policies, profiles)
- **Converter tests** — validates Versa output generation
- **Golden file tests** — compares full conversion output against known-good reference files
- **Sanitizer tests** — validates Versa name sanitization rules
- **IP range tests** — validates CIDR expansion of IP ranges

## Limitations

- NAT rules are not converted — Versa CGNAT must be configured manually
- Traffic shaping / QoS requires manual Class of Service configuration
- VPN/IPsec tunnel configuration is not converted
- Routing (static routes, OSPF, BGP) is not converted
- Interface/VLAN configuration is not converted — only firewall policy objects
- Wildcard FQDN addresses require DNS Proxy enabled on VOS
- FortiGate source port constraints are dropped (Versa matches destination port only)

## License

[MIT](LICENSE)
