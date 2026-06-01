# Multi-Tenant Scripts

This repository contains a collection of bash scripts designed to assist with multi-tenant EntraId management. These scripts facilitate bulk guest invitations and the management of application permissions across multiple tenants. And more to come :)

## Scripts Overview

### 1. BulkGuestInvite.sh
**Description:**
Enables bulk guest invitation using Microsoft Graph via `az rest`.

**Prerequisites:**
- Azure CLI (`az`) installed and logged in.
- A file named `users.txt` containing one UPN (User Principal Name) per line.

**Usage:**
1.  Prepare `users.txt`:
    ```text
    analyst1@externaltenant.com
    analyst2@externaltenant.com
    ```
2.  Run the script:
    ```bash
    ./BulkGuestInvite.sh -i users.txt
    ```

**Output:**
Prints `invitedUserEmailAddress | inviteRedeemUrl | status` for each user.

---

### 2. multipermissionadd.sh
**Description:**
Automates the assignment of specific App Role IDs (permissions) to a Service Principal across multiple tenants.

**Prerequisites:**
- Azure CLI (`az`) installed and logged in with permissions to manage applications in the target tenants.
- `jq` installed.
- A file named `tenants.txt` containing one Tenant ID per line.
- Update the script with your `APP_ID` and the desired `ROLE_IDS`.

**Configuration:**
Edit the script to set:
- `APP_ID`: The Application ID of your multi-tenant app.
- `ROLE_IDS`: Array of Role IDs you want to assign.
- `RESOURCE_APP_ID`: The Resource App ID (e.g., Microsoft Graph).

**Usage:**
```bash
./multipermissionadd.sh
```

---

### 3. multipermissiondelete.sh
**Description:**
Automates the removal of specific App Role IDs (permissions) from a Service Principal across multiple tenants.

**Prerequisites:**
- Azure CLI (`az`) installed and logged in.
- `jq` installed.
- A file named `tenants.txt` containing one Tenant ID per line.

**Configuration:**
Edit the script to set:
- `APP_ID`: The Application ID of your multi-tenant app.
- `ROLE_IDS`: Array of Role IDs you want to remove.

**Usage:**
```bash
./multipermissiondelete.sh
```

---

### 4. BulkGuestDelete.sh
**Description:**
Deletes multiple guest accounts across multiple tenants by matching the beginning of the guest UPN.

**How matching works:**
- `guests.txt` contains *guest keys* (one per line), e.g. `m.muster`
- The script searches for users where:
  - `userType == "Guest"`
  - `userPrincipalName` starts with the guest key
- Example match:
  - guest key: `m.muster`
  - guest UPN in tenant: `m.muster_hometenant.com#EXT#@contoso.onmicrosoft.com`

**Prerequisites:**
- Azure CLI (`az`) installed and logged in with permissions to read/delete users in the target tenants.
- `jq` installed.
- `curl` installed.
- A file named `tenants.txt` containing one Tenant ID per line.
- A file named `guests.txt` containing one guest key per line.

**Usage:**
1.  Prepare `tenants.txt`:
    ```text
    11111111-1111-1111-1111-111111111111
    22222222-2222-2222-2222-222222222222
    ```
2.  Prepare `guests.txt`:
    ```text
    m.muster
    another.guest_prefix
    ```
3.  Run a dry-run first:
    ```bash
    ./BulkGuestDelete.sh --dry-run
    ```
4.  Execute deletions:
    ```bash
    ./BulkGuestDelete.sh
    ```

**Options:**
- `--tenant-file FILE` (default `tenants.txt`)
- `--guest-file FILE` (default `guests.txt`)
- `--dry-run` (no deletes, prints what would be deleted)
- `--help`

**Output:**
Prints one line per tenant + guest key match, including deletion result:
`tenantId | guestKey | matchedGuestUpn | userId | action | httpStatus`

---

### 5. multitenant_ca_policy_guard.sh
**Description:**
Checks (or remediates) Conditional Access policy configuration across multiple tenants by comparing a matched policy to a reference JSON policy.

**Prerequisites:**
- Azure CLI (`az`) installed and logged in.
- `jq`, `curl`, and `base64` installed.
- A file with target tenant IDs (one per line), for example `tenants.txt`.
- A reference Conditional Access policy JSON file containing at least:
  - `state`
  - `conditions`
  - `grantControls`

**Usage:**
```bash
./multitenant_ca_policy_guard.sh \
  --target tenants.txt \
  --reference-policy first_conditional_access_policy.json \
  --mode check|change
```

**Options:**
- `--target FILE` (required): tenant list file
- `--reference-policy FILE` (required): reference policy JSON
- `--mode check|change` (required)
- `--match-string-1 STRING` (optional): policy display name contains this value
- `--match-string-2 STRING` (optional): policy display name contains this value
- `--setting-check LIST` (optional, check mode only): compact per-setting checks
- `--tablemode` (optional): print table output instead of JSON
- `--help`

**Policy matching behavior:**
- If `--match-string-1` / `--match-string-2` are omitted, the script matches by exact reference policy display name (case-insensitive).
- If multiple policies match in a tenant, no remediation is applied for safety.

**Examples:**
1. Full JSON check output:
```bash
./multitenant_ca_policy_guard.sh \
  --target ../tenants.txt \
  --reference-policy ../CA00.json \
  --mode check | jq
```

2. Compact per-setting JSON output:
```bash
./multitenant_ca_policy_guard.sh \
  --target ../tenants.txt \
  --reference-policy ../CA00.json \
  --mode check \
  --setting-check state,target-apps,assigned-users | jq
```

3. CLI table output overview:
```bash
./multitenant_ca_policy_guard.sh \
  --target ../tenants.txt \
  --reference-policy ../CA00.json \
  --mode check \
  --setting-check state,target-apps,assigned-users \
  --tablemode
```

**Supported `--setting-check` selectors:**
- `state`
- `assigned-users`
- `target-apps`
- `conditions`
- `grant-controls`
- `session-controls`
- Custom jq path selector: `path:.conditions.platforms.includePlatforms`

**Output modes:**
- Default: structured JSON report with `results`.
- `--setting-check`: compact JSON rows with:
  - `tenantId`
  - `caFound`
  - `setting`
  - `matchesReference`
- `--tablemode`: prints a readable table in CLI stdout.

---

### 6. multitenant_device_code_flow_ca_check.sh
**Description:**
Checks multiple Microsoft Entra ID tenants for Conditional Access policies that target OAuth Device Code Flow and reports whether those policies are likely effective.

**Purpose:**
- Detects Conditional Access policies by policy structure, not by display name or policy ID.
- Focuses on policies with `.conditions.authenticationFlows.transferMethods` matching `deviceCodeFlow`.
- Classifies each tenant as protected, report-only, disabled, missing, or error.
- Read-only only: the script never modifies policies.

**Prerequisites:**
- Azure CLI (`az`) installed and already logged in.
- `curl`, `jq`, and `base64` installed.
- Optional: `column` for prettier table output.
- A file named `tenants.txt` containing one tenant ID per line.

**Example `tenants.txt`:**
```text
# One tenant ID per line
11111111-1111-1111-1111-111111111111
22222222-2222-2222-2222-222222222222
```

**Usage:**
```bash
./multitenant_device_code_flow_ca_check.sh
./multitenant_device_code_flow_ca_check.sh --tenant-file tenants.txt
./multitenant_device_code_flow_ca_check.sh --json
./multitenant_device_code_flow_ca_check.sh --table
./multitenant_device_code_flow_ca_check.sh --debug
./multitenant_device_code_flow_ca_check.sh --help
```

**Output explanation:**
- Table mode prints a summary table with:
  - `TENANT_ID`
  - `TENANT_NAME`
  - `STATUS`
  - `MATCHING_POLICIES`
  - `EFFECTIVE_BLOCK`
  - `POLICY_NAMES`
  - `ERROR`
- JSON mode prints a single JSON object with `generatedAt`, `summary`, and `results`.

**Status classification:**
- `PROTECTED_ENABLED_BLOCK` - at least one matching policy is enabled, has Device Code Flow in scope, and includes `block` in grant controls.
- `PRESENT_ENABLED_NON_BLOCK` - a matching policy is enabled, but grant controls do not clearly block access.
- `REPORT_ONLY` - a matching policy exists but is only `enabledForReportingButNotEnforced`.
- `DISABLED` - a matching policy exists but is disabled.
- `MISSING` - no matching Conditional Access policy was found.
- `ERROR_NO_TOKEN` - no Microsoft Graph token could be acquired for the tenant.
- `ERROR_CONTEXT_MISMATCH` - the acquired token did not match the requested tenant.
- `ERROR_LIST_POLICIES` - Microsoft Graph policy listing failed.

**Notes:**
- The script is check-only and does not remediate, create, delete, or modify any policy.
- It uses the existing Azure CLI session and does not call `az login`.

## Setup

1.  Clone this repository.
2.  Ensure scripts are executable:
    ```bash
    chmod +x *.sh
    ```
3.  Install dependencies (`az` CLI, `jq`, `curl`).
4.  Authenticate with Azure CLI:
    ```bash
    az login
    ```

## Disclaimer
These scripts are provided "as is" without warranty of any kind. Please test thoroughly in a non-production environment before running against production tenants.
