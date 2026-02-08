#!/usr/bin/env bash
set -euo pipefail

TENANT_FILE="tenants.txt"
GUEST_FILE="guests.txt"
DRY_RUN=0

usage() {
  cat <<'EOF'
BulkGuestDelete.sh - delete multiple guest users across multiple tenants

This script:
- Reads tenant IDs from tenants.txt (or --tenant-file)
- Reads guest keys from guests.txt (or --guest-file)
- For each tenant and guest key:
  - Finds users where userType == "Guest" and userPrincipalName starts with the guest key
  - Deletes each matched user

The "guest key" can be the first part of the guest UPN.
Example: guests.txt contains "p.binder_analyst" and the tenant has
"p.binder_analyst_abtis.de#EXT#@contoso.onmicrosoft.com" -> this matches.

Requirements:
- Azure CLI: az
- curl
- jq
- An Azure CLI login with permissions to read/delete users in each tenant

Usage:
  ./BulkGuestDelete.sh
  ./BulkGuestDelete.sh --tenant-file tenants.txt --guest-file guests.txt
  ./BulkGuestDelete.sh --dry-run

Options:
  --tenant-file FILE   Tenants list file (default: tenants.txt)
  --guest-file FILE    Guest keys list file (default: guests.txt)
  --dry-run            Do not delete, only print what would be deleted
  -h, --help           Show this help

Input file formats:
- One entry per line
- Blank lines and lines starting with # are ignored
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: Missing required command: $1" >&2; exit 1; }
}

strip_cr() {
  # Normalize CRLF files.
  printf '%s' "${1%%$'\r'}"
}

odata_escape() {
  # OData string literal escaping: single-quote becomes doubled.
  # https://www.odata.org/documentation/odata-version-2-0/uri-conventions/
  printf '%s' "$1" | sed "s/'/''/g"
}

get_graph_token() {
  local tenant_id="$1"
  az account get-access-token \
    --tenant "$tenant_id" \
    --resource https://graph.microsoft.com \
    --query accessToken -o tsv 2>/dev/null || true
}

graph_list_guest_users_by_prefix() {
  local token="$1"
  local guest_key="$2"
  local base_url="https://graph.microsoft.com/v1.0/users"
  local escaped_key
  escaped_key="$(odata_escape "$guest_key")"

  local resp next
  resp="$(curl -sS -G \
    -H "Authorization: Bearer ${token}" \
    --data-urlencode "\$select=id,userPrincipalName,userType" \
    --data-urlencode "\$top=999" \
    --data-urlencode "\$filter=userType eq 'Guest' and startswith(userPrincipalName,'${escaped_key}')" \
    "${base_url}")"

  echo "$resp" | jq -c '.value[]?'
  next="$(echo "$resp" | jq -r '."@odata.nextLink" // empty')"

  while [ -n "${next:-}" ]; do
    resp="$(curl -sS -H "Authorization: Bearer ${token}" "${next}")"
    echo "$resp" | jq -c '.value[]?'
    next="$(echo "$resp" | jq -r '."@odata.nextLink" // empty')"
  done
}

graph_delete_user() {
  local token="$1"
  local user_id="$2"
  curl -sS -o /dev/null -w "%{http_code}" \
    -X DELETE \
    -H "Authorization: Bearer ${token}" \
    "https://graph.microsoft.com/v1.0/users/${user_id}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --tenant-file) TENANT_FILE="${2:-}"; shift 2 ;;
    --guest-file) GUEST_FILE="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "ERROR: Unknown argument: $1" >&2
      echo >&2
      usage >&2
      exit 2
      ;;
  esac
done

need_cmd az
need_cmd curl
need_cmd jq

if [ ! -f "$TENANT_FILE" ]; then
  echo "ERROR: Tenant file not found: $TENANT_FILE" >&2
  exit 1
fi

if [ ! -f "$GUEST_FILE" ]; then
  echo "ERROR: Guest file not found: $GUEST_FILE" >&2
  exit 1
fi

echo "Using Azure CLI login:"
az account show --query user -o table
echo

echo "tenantId | guestKey | matchedGuestUpn | userId | action | httpStatus"

total_found=0
total_deleted=0
total_failed=0
total_skipped=0

while IFS= read -r TENANT_ID || [ -n "${TENANT_ID:-}" ]; do
  TENANT_ID="$(strip_cr "${TENANT_ID:-}")"
  case "$TENANT_ID" in ""|\#*) continue ;; esac

  token="$(get_graph_token "$TENANT_ID")"
  if [ -z "${token:-}" ]; then
    echo "${TENANT_ID} | - | - | - | ERROR_NO_TOKEN | -"
    total_failed=$((total_failed + 1))
    continue
  fi

  while IFS= read -r GUEST_KEY || [ -n "${GUEST_KEY:-}" ]; do
    GUEST_KEY="$(strip_cr "${GUEST_KEY:-}")"
    case "$GUEST_KEY" in ""|\#*) continue ;; esac

    found_any=0
    while IFS= read -r user_json; do
      [ -z "${user_json:-}" ] && continue
      found_any=1

      user_id="$(echo "$user_json" | jq -r '.id // empty')"
      upn="$(echo "$user_json" | jq -r '.userPrincipalName // empty')"
      user_type="$(echo "$user_json" | jq -r '.userType // empty')"

      if [ -z "${user_id:-}" ] || [ -z "${upn:-}" ]; then
        echo "${TENANT_ID} | ${GUEST_KEY} | - | - | ERROR_PARSE | -"
        total_failed=$((total_failed + 1))
        continue
      fi

      total_found=$((total_found + 1))

      if [ "${user_type}" != "Guest" ]; then
        echo "${TENANT_ID} | ${GUEST_KEY} | ${upn} | ${user_id} | SKIP_NOT_GUEST | -"
        total_skipped=$((total_skipped + 1))
        continue
      fi

      if [ "$DRY_RUN" -eq 1 ]; then
        echo "${TENANT_ID} | ${GUEST_KEY} | ${upn} | ${user_id} | DRY_RUN | -"
        total_skipped=$((total_skipped + 1))
        continue
      fi

      http_status="$(graph_delete_user "$token" "$user_id" || true)"
      if [ "${http_status}" = "204" ]; then
        echo "${TENANT_ID} | ${GUEST_KEY} | ${upn} | ${user_id} | DELETED | ${http_status}"
        total_deleted=$((total_deleted + 1))
      else
        echo "${TENANT_ID} | ${GUEST_KEY} | ${upn} | ${user_id} | DELETE_FAILED | ${http_status}"
        total_failed=$((total_failed + 1))
      fi
    done < <(graph_list_guest_users_by_prefix "$token" "$GUEST_KEY" || true)

    if [ "$found_any" -eq 0 ]; then
      echo "${TENANT_ID} | ${GUEST_KEY} | - | - | NOT_FOUND | -"
    fi
  done < "$GUEST_FILE"
done < "$TENANT_FILE"

echo
echo "Summary:"
echo "  Matched users:  ${total_found}"
echo "  Deleted:        ${total_deleted}"
echo "  Skipped:        ${total_skipped}"
echo "  Failed:         ${total_failed}"

