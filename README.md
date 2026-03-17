# CrowdStrike Exposure Management

Query CrowdStrike Spotlight to identify which hosts are exposed to a given CVE and which vulnerabilities affect a given asset — directly from the Polarity overlay.

## Overview

This integration uses the CrowdStrike Falcon Spotlight (Exposure Management) API to support three entity types:

| Entity | Lookup Method |
|--------|--------------|
| CVE (e.g., `CVE-2022-38023`) | Direct Spotlight filter: `cve.id:'...'` |
| Hostname (custom type) | Resolve to AID via Devices API → Spotlight `aid:'...'` |
| CrowdStrike AID (32 hex chars) | Direct Spotlight filter: `aid:'...'` |

## Required OAuth2 Scopes

| Scope | Required For |
|-------|-------------|
| `vulnerabilities:read` | All lookups |
| `hosts:read` | Hostname resolution |
| `spotlight-patch:read` | Installed Patch Data (optional) |

## Installation

1. Install the integration on your Polarity server.
2. Configure the options below in the Polarity Integration Settings page.
3. Restart the integration.

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| **CrowdStrike API URL** | Base URL for the CrowdStrike API | `https://api.crowdstrike.com` |
| **Client ID** | OAuth2 Client ID | — |
| **Client Secret** | OAuth2 Client Secret | — |
| **CrowdStrike UI URL** | Falcon UI base URL for deep links | `https://falcon.crowdstrike.com` |
| **Max Results Per Lookup** | Maximum vulnerability records returned per entity | `20` |
| **Enable Installed Patch Data** | Fetch patch history for hostname/AID lookups (requires `spotlight-patch:read`) | `false` |
| **Enable Evaluation Logic** | Include evaluation logic tests in the facet query | `false` |

## Entity Type Details

### CVE Lookup
Highlight a CVE identifier in Polarity. The integration queries all assets exposed to that CVE and displays:
- Severity, CVSS score, ExPRT rating, CISA KEV status
- Count and list of all affected hosts with OS, IP, domain, and criticality
- Remediation guidance with KB references
- Deep links to the CVE page in Falcon

### Hostname Lookup
Highlight a hostname. The integration resolves it to a CrowdStrike Agent ID (AID) via the Devices API, then queries all open vulnerabilities for that asset.

### AID Lookup
Highlight a 32-character hex CrowdStrike Agent ID. Directly queries Spotlight for all vulnerabilities on that endpoint.

## Test Indicator

```
CVE-2022-38023
```

## Version History

| Version | Notes |
|---------|-------|
| 1.0.0 | Initial build — CVE, hostname, and AID lookups with Spotlight facets |

## Links

- [CrowdStrike Vulnerability Management API](https://docs.crowdstrike.com/r/ab572b16)
- [CrowdStrike Asset Management API](https://docs.crowdstrike.com/r/a9df69ec)
