#!/bin/bash
set -euo pipefail

APP_ID="<YOUR_APP_ID_HERE>"   # Your app registration
TENANT_FILE="tenants.txt"

# ---------------------------------------------------------------
# LIST ALL ROLE IDs YOU WANT TO DELETE HERE:
# ---------------------------------------------------------------
ROLE_IDS=(
        "<ROLE_ID_TO_DELETE>"
)

if [ ! -f "$TENANT_FILE" ]; then
  echo "tenants.txt missing"
  exit 1
fi

echo "Using existing Azure CLI login for user:"
az account show --query user -o table


while IFS= read -r TENANT_ID || [ -n "${TENANT_ID:-}" ]; do
  TENANT_ID="${TENANT_ID%%$'\r'}"

  case "$TENANT_ID" in ""|\#*) continue ;; esac

  echo "-------------------------------------------------------------"
  echo "Processing tenant: ${TENANT_ID}"
  echo "-------------------------------------------------------------"


  GRAPH_TOKEN=$(az account get-access-token \
      --resource https://graph.microsoft.com \
      --tenant "${TENANT_ID}" \
      --query accessToken -o tsv 2>/dev/null || true)

  if [ -z "${GRAPH_TOKEN}" ]; then
    echo "ERROR: Could not get Graph token for tenant ${TENANT_ID}"
    continue
  fi


  SP_ID=$(curl -s \
      -H "Authorization: Bearer ${GRAPH_TOKEN}" \
      "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId%20eq%20'${APP_ID}'" \
      | jq -r '.value[0].id')

  if [ "${SP_ID:-}" = "null" ] || [ -z "${SP_ID:-}" ]; then
    echo "App not found in tenant → skipping"
    continue
  fi

  echo "SP_ID: ${SP_ID}"


  for ROLE_ID in "${ROLE_IDS[@]}"; do
    echo "Checking RoleId: $ROLE_ID"

    ASSIGNMENT_ID=$(curl -s \
        -H "Authorization: Bearer ${GRAPH_TOKEN}" \
        "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/appRoleAssignments" \
        | jq -r ".value[] | select(.appRoleId == \"${ROLE_ID}\") | .id")


    if [ -z "${ASSIGNMENT_ID}" ]; then
      echo "Role ${ROLE_ID} not assigned → nothing to delete"
      continue
    fi

    echo "Deleting assignment ${ASSIGNMENT_ID} for RoleId ${ROLE_ID} ..."

    curl -s -X DELETE \
      -H "Authorization: Bearer ${GRAPH_TOKEN}" \
      "https://graph.microsoft.com/v1.0/servicePrincipals/${SP_ID}/appRoleAssignments/${ASSIGNMENT_ID}"

    echo "Removed role ${ROLE_ID} from tenant ${TENANT_ID}"
  done

done < "$TENANT_FILE"

echo "-------------------------------------------------------------"
echo "Completed multi-tenant removal."
echo "-------------------------------------------------------------"
