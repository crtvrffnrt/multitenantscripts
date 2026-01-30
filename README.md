# Multi-Tenant Scripts

This repository contains a collection of bash scripts designed to assist with multi-tenant Azure AD management. These scripts facilitate bulk guest invitations and the management of application permissions across multiple tenants.

## Scripts Overview

### 1. BulkGuestInvite.sh
**Description:**
Enables bulk guest invitation using Microsoft Graph via `az rest`. This is particularly useful for tenants without Entra ID P2 licensing where Access Packages cannot be used.

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
