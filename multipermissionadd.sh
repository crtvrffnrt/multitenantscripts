#!/bin/bash
set -euo pipefail

# Configuration
APP_ID="<YOUR_APP_ID_HERE>"    # Your multi-tenant app registration ID
TENANT_FILE="tenants.txt"

# ---------------------------------------------------------------
# ADD ALL ROLE IDs HERE:
# Example: Graph Mail.Read, Directory.Read.All, Files.Read.All
# ---------------------------------------------------------------
ROLE_IDS=(
  "<ROLE_ID_1>"
  "<ROLE_ID_2>"
)

# ---------------------------------------------------------------
# DEFINE THE RESOURCE APP ID FOR THESE ROLE IDS
# (All RoleIds in the list MUST belong to the SAME resource)
#
# Microsoft Graph:       00000003-0000-0000-c000-000000000000
# Exchange Online:       00000002-0000-0ff1-ce00-000000000000
# Defender for Endpoint: fc780465-2017-40d4-a0c5-307022471b92
# ---------------------------------------------------------------
RESOURCE_APP_ID="00000003-0000-0000-c000-000000000000"


# ---------------------------------------------------------------
# START SCRIPT
# ---------------------------------------------------------------
echo "Using Azure CLI login:"
az account show --query user -o table


if [ ! -f "$TENANT_FILE" ]; then
  echo "tenants.txt missing"
  exit 1
fi


while IFS= read -r TENANT_ID || [ -n "${TENANT_ID:-}" ]; do
  case "$TENANT_ID" in ""|\#*) continue ;; esac

  echo "-------------------------------------------------------------"
  echo "Processing tenant: $TENANT_ID"
  echo "-------------------------------------------------------------"

  TOKEN=$(az account get-access-token \
    --tenant "$TENANT_ID" \
    --resource https://graph.microsoft.com \
    --query accessToken -o tsv 2>/dev/null || true)

  if [ -z "$TOKEN" ]; then
    echo "ERROR: Cannot acquire token for tenant $TENANT_ID"
    continue
  fi


  SP_ID=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId%20eq%20'${APP_ID}'" \
    | jq -r '.value[0].id')

  if [ "$SP_ID" = "null" ] || [ -z "$SP_ID" ]; then
    echo "App not present in tenant → skipping"
    continue
  fi

  echo "App SP ID: $SP_ID"


  RESOURCE_SP_ID=$(curl -s \
    -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId%20eq%20'${RESOURCE_APP_ID}'" \
    | jq -r '.value[0].id')

  if [ "$RESOURCE_SP_ID" = "null" ] || [ -z "$RESOURCE_SP_ID" ]; then
    echo "Resource SP not found in tenant → skipping"
    continue
  fi

  echo "Resource SP: $RESOURCE_SP_ID"


  for ROLE_ID in "${ROLE_IDS[@]}"; do
    echo "Checking RoleId: $ROLE_ID"

    ASSIGNED=$(curl -s \
      -H "Authorization: Bearer $TOKEN" \
      "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/appRoleAssignments" \
      | jq -r ".value[] | select(.appRoleId==\"${ROLE_ID}\") | .id")

    if [ -n "$ASSIGNED" ]; then
      echo "Already assigned → OK"
      continue
    fi

    echo "Assigning $ROLE_ID ..."

    curl -s -X POST \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{
            \"principalId\": \"${SP_ID}\",
            \"resourceId\": \"${RESOURCE_SP_ID}\",
            \"appRoleId\": \"${ROLE_ID}\"
          }" \
      "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/appRoleAssignments" >/dev/null

    echo "Assigned RoleId: $ROLE_ID to tenant: $TENANT_ID"
  done

done < "$TENANT_FILE"

echo "-------------------------------------------------------------"
echo "Completed multi-tenant multi-permission assignment."
echo "-------------------------------------------------------------"
