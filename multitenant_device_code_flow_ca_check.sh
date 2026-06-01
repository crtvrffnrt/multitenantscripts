#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
TENANT_FILE="tenants.txt"
JSON_MODE=0
TABLE_MODE=1
DEBUG_MODE=0

RESULTS_FILE=""
TEMP_DIR=""
LAST_TOKEN_ERROR=""
LAST_CONTEXT_ERROR=""
LAST_LIST_ERROR=""

SUMMARY_TENANTS_TOTAL=0
SUMMARY_PROTECTED=0
SUMMARY_PRESENT=0
SUMMARY_REPORT_ONLY=0
SUMMARY_DISABLED=0
SUMMARY_MISSING=0
SUMMARY_ERRORS=0

usage() {
  cat <<'EOF'
Usage:
  multitenant_device_code_flow_ca_check.sh
  multitenant_device_code_flow_ca_check.sh --tenant-file tenants.txt
  multitenant_device_code_flow_ca_check.sh --json
  multitenant_device_code_flow_ca_check.sh --table
  multitenant_device_code_flow_ca_check.sh --debug
  multitenant_device_code_flow_ca_check.sh --help

Purpose:
  Check multiple Microsoft Entra ID tenants for Conditional Access policies
  that target OAuth Device Code Flow and summarize whether the policies are
  likely effective.

Options:
  --tenant-file FILE   Tenant list file (default: tenants.txt)
  --json               Emit a single JSON object to stdout
  --table              Emit a human-readable table to stdout (default)
  --debug              Print extra logs to stderr
  -h, --help           Show this help

Input file format:
  - One tenant ID per line
  - Blank lines are ignored
  - Lines starting with # are ignored
  - CRLF files are supported

Notes:
  - Uses the existing Azure CLI session. It does not run az login.
  - Read-only only: no PATCH, POST, DELETE, or remediation actions.
EOF
}

log() {
  printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

warn() {
  printf '[%s] WARN: %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

err() {
  printf '[%s] ERROR: %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

debug() {
  if [ "$DEBUG_MODE" -eq 1 ]; then
    printf '[%s] DEBUG: %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    err "Missing required command: $1"
    exit 1
  }
}

strip_cr() {
  printf '%s' "${1%%$'\r'}"
}

trim() {
  local s="${1:-}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

json_escape_string() {
  jq -Rn --arg s "$1" '$s'
}

graph_request() {
  local method="$1"
  local token="$2"
  local url="$3"
  local tmp_err response status body err_text

  tmp_err="$(mktemp)"
  response="$(curl -sS -X "$method" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -w $'\n%{http_code}' \
    "$url" 2>"$tmp_err" || true)"

  status="${response##*$'\n'}"
  body="${response%$'\n'*}"

  if ! [[ "$status" =~ ^[0-9]{3}$ ]]; then
    status="000"
    err_text="$(tr '\n' ' ' < "$tmp_err" | cut -c1-400)"
    body="$(jq -cn --arg message "curl failed for ${method} ${url%%\?*}: ${err_text}" \
      '{error:{code:"CURL_FAILED",message:$message}}')"
  elif [ -z "$body" ] && [ "$status" = "000" ]; then
    body='{"error":{"code":"CURL_FAILED","message":"empty curl response"}}'
  fi

  rm -f "$tmp_err"
  printf '%s\n%s' "$status" "$body"
}

jwt_tid_from_token() {
  local token="$1"
  local payload padded mod

  payload="$(printf '%s' "$token" | cut -d'.' -f2)"
  [ -n "$payload" ] || return 1

  payload="${payload//-/+}"
  payload="${payload//_/\/}"
  mod=$(( ${#payload} % 4 ))
  case "$mod" in
    0) padded="$payload" ;;
    2) padded="${payload}==" ;;
    3) padded="${payload}=" ;;
    *) return 1 ;;
  esac

  if printf '%s' "$padded" | base64 -d 2>/dev/null | jq -r '.tid // empty' 2>/dev/null; then
    return 0
  fi

  printf '%s' "$padded" | base64 --decode 2>/dev/null | jq -r '.tid // empty' 2>/dev/null || true
}

token_matches_tenant() {
  local token="$1"
  local tenant_id="$2"
  local tid

  tid="$(jwt_tid_from_token "$token" || true)"
  [ -n "$tid" ] || return 1
  [ "${tid,,}" = "${tenant_id,,}" ]
}

verify_token_tenant_context() {
  local tenant_id="$1"
  local token="$2"
  local tid org_resp status body org_id

  LAST_CONTEXT_ERROR=""

  tid="$(jwt_tid_from_token "$token" || true)"
  if [ -n "$tid" ]; then
    if [ "${tid,,}" = "${tenant_id,,}" ]; then
      return 0
    fi
    LAST_CONTEXT_ERROR="JWT tid claim ${tid} does not match requested tenant ${tenant_id}"
    return 1
  fi

  org_resp="$(graph_request GET "$token" "https://graph.microsoft.com/v1.0/organization?\$select=id,displayName")"
  status="${org_resp%%$'\n'*}"
  body="${org_resp#*$'\n'}"
  if [ "$status" != "200" ]; then
    LAST_CONTEXT_ERROR="Could not verify tenant context via Microsoft Graph organization endpoint (HTTP ${status})"
    return 1
  fi

  org_id="$(printf '%s' "$body" | jq -r '.value[0].id // empty' 2>/dev/null || true)"
  if [ -z "$org_id" ]; then
    LAST_CONTEXT_ERROR="Could not verify tenant context: organization id missing"
    return 1
  fi

  if [ "${org_id,,}" = "${tenant_id,,}" ]; then
    return 0
  fi

  LAST_CONTEXT_ERROR="Organization id ${org_id} does not match requested tenant ${tenant_id}"
  return 1
}

get_access_token_for_tenant() {
  local tenant_id="$1"
  local token=""

  token="$(az account get-access-token --tenant "$tenant_id" --resource https://graph.microsoft.com --query accessToken -o tsv 2>/dev/null || true)"
  if [ -n "$token" ]; then
    printf '%s' "$token"
    return 0
  fi

  token="$(az account get-access-token --tenant "$tenant_id" --resource-type ms-graph --query accessToken -o tsv 2>/dev/null || true)"
  if [ -n "$token" ]; then
    printf '%s' "$token"
    return 0
  fi

  token="$(az account get-access-token --tenant "$tenant_id" --scope https://graph.microsoft.com/.default --query accessToken -o tsv 2>/dev/null || true)"
  if [ -n "$token" ]; then
    printf '%s' "$token"
    return 0
  fi

  LAST_TOKEN_ERROR="Unable to acquire Microsoft Graph token for tenant ${tenant_id}"
  return 1
}

list_conditional_access_policies() {
  local token="$1"
  local out_file="$2"
  local urls
  local page_url response status body next_link
  local tried_v1=0

  LAST_LIST_ERROR=""
  urls=(
    "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?\$top=999"
    "https://graph.microsoft.com/beta/identity/conditionalAccess/policies?\$top=999"
  )

  for page_url in "${urls[@]}"; do
    : > "$out_file"
    tried_v1=$((tried_v1 + 1))
    next_link="$page_url"

    while :; do
      response="$(graph_request GET "$token" "$next_link")"
      status="${response%%$'\n'*}"
      body="${response#*$'\n'}"

      if [ "$status" != "200" ]; then
        LAST_LIST_ERROR="Policy listing failed with HTTP ${status}"
        if [ "$tried_v1" -eq 1 ]; then
          debug "v1.0 policy listing failed; retrying beta"
          break
        fi
        return 1
      fi

      if ! printf '%s' "$body" | jq -c '.value[]?' >> "$out_file"; then
        LAST_LIST_ERROR="Policy listing response could not be parsed"
        if [ "$tried_v1" -eq 1 ]; then
          debug "v1.0 policy listing parse failed; retrying beta"
          break
        fi
        return 1
      fi

      next_link="$(printf '%s' "$body" | jq -r '."@odata.nextLink" // empty' 2>/dev/null || true)"
      [ -n "$next_link" ] || return 0
    done
  done

  return 1
}

is_device_code_flow_policy() {
  local policy_json="$1"

  jq -e '
    [.conditions.authenticationFlows.transferMethods? | .. | strings | ascii_downcase | select(. == "devicecodeflow")] | length > 0
  ' >/dev/null 2>&1 <<< "$policy_json"
}

get_policy_effectiveness() {
  local policy_json="$1"

  jq -c '
    def list_has_values($v):
      if $v == null then false
      elif ($v | type) == "array" then
        any($v[]; ((tostring | ascii_downcase) != "none") and (tostring != ""))
      elif ($v | type) == "string" then
        ((ascii_downcase != "none") and . != "")
      else
        true
      end;

    def has_scope:
      list_has_values(.conditions.users.includeUsers)
      or list_has_values(.conditions.users.excludeUsers)
      or list_has_values(.conditions.users.includeGroups)
      or list_has_values(.conditions.users.excludeGroups)
      or list_has_values(.conditions.users.includeRoles)
      or list_has_values(.conditions.users.excludeRoles)
      or list_has_values(.conditions.users.includeGuestsOrExternalUsers)
      or list_has_values(.conditions.users.excludeGuestsOrExternalUsers)
      or list_has_values(.conditions.applications.includeApplications)
      or list_has_values(.conditions.applications.excludeApplications)
      or list_has_values(.conditions.applications.includeAuthenticationContextClassReferences)
      or list_has_values(.conditions.applications.includeUserActions)
      or list_has_values(.conditions.clientAppTypes);

    def blocks_access:
      ((.grantControls.builtInControls // [])
       | map(tostring | ascii_downcase)
       | index("block")) != null;

    . as $p
    | {
        state: ($p.state // ""),
        stateNormalized: (($p.state // "") | ascii_downcase),
        reportOnly: ((($p.state // "") | ascii_downcase) == "enabledforreportingbutnotenforced"),
        disabled: ((($p.state // "") | ascii_downcase) == "disabled"),
        enabled: ((($p.state // "") | ascii_downcase) == "enabled"),
        blocksAccess: blocks_access,
        hasScope: has_scope,
        likelyEffective: (((($p.state // "") | ascii_downcase) == "enabled") and blocks_access and has_scope)
      }
  ' <<< "$policy_json"
}

get_policy_scope_summary() {
  local policy_json="$1"

  jq -c '
    def fmt_list($v):
      if $v == null then "none"
      elif ($v | type) == "array" then
        if ($v | length) == 0 then "none" else ($v | map(tostring) | join(", ")) end
      elif ($v | type) == "string" then
        if ($v | ascii_downcase) == "none" or $v == "" then "none" else $v end
      else
        ($v | tostring)
      end;

    def fmt_pair($include; $exclude):
      "include=" + fmt_list($include) + "; exclude=" + fmt_list($exclude);

    {
      users: fmt_pair(.conditions.users.includeUsers; .conditions.users.excludeUsers),
      groups: fmt_pair(.conditions.users.includeGroups; .conditions.users.excludeGroups),
      roles: fmt_pair(.conditions.users.includeRoles; .conditions.users.excludeRoles),
      applications: fmt_pair(.conditions.applications.includeApplications; .conditions.applications.excludeApplications),
      clientAppTypes: fmt_list(.conditions.clientAppTypes)
    }
  ' <<< "$policy_json"
}

append_result() {
  local result_json="$1"
  printf '%s\n' "$result_json" >> "$RESULTS_FILE"
}

print_table() {
  if command -v column >/dev/null 2>&1; then
    column -t -s $'\t'
  else
    cat
  fi
}

build_policy_output() {
  local policy_json="$1"
  local scope_summary="$2"
  local effectiveness_json="$3"

  jq -cn \
    --argjson policy "$policy_json" \
    --argjson scopeSummary "$scope_summary" \
    --argjson effectiveness "$effectiveness_json" \
    '{
      policyId: ($policy.id // ""),
      displayName: ($policy.displayName // ""),
      state: ($policy.state // ""),
      transferMethods: (
        $policy.conditions.authenticationFlows.transferMethods
        | if type == "array" then map(tostring) | join(", ")
          elif . == null then ""
          else tostring
          end
      ),
      blocksAccess: ($effectiveness.blocksAccess // false),
      builtInControls: ($policy.grantControls.builtInControls // []),
      operator: ($policy.grantControls.operator // ""),
      scopeSummary: $scopeSummary
    }
    + (if ($policy.templateId // "") != "" then {templateId: $policy.templateId} else {} end)'
}

build_result_json() {
  local tenant_id="$1"
  local tenant_display_name="$2"
  local status="$3"
  local matching_policy_count="$4"
  local effective_policy_found="$5"
  local message="$6"
  local policies_json="$7"
  local error_text="$8"

  jq -cn \
    --arg tenantId "$tenant_id" \
    --arg tenantDisplayName "$tenant_display_name" \
    --arg status "$status" \
    --arg message "$message" \
    --arg error "$error_text" \
    --argjson matchingPolicyCount "$matching_policy_count" \
    --argjson effectivePolicyFound "$effective_policy_found" \
    --argjson policies "$policies_json" \
    '{
      tenantId: $tenantId,
      tenantDisplayName: $tenantDisplayName,
      status: $status,
      matchingPolicyCount: $matchingPolicyCount,
      effectivePolicyFound: $effectivePolicyFound,
      message: $message,
      policies: $policies,
      error: $error
    }'
}

get_tenant_display_name() {
  local token="$1"
  local response status body display_name

  response="$(graph_request GET "$token" "https://graph.microsoft.com/v1.0/organization?\$select=id,displayName")"
  status="${response%%$'\n'*}"
  body="${response#*$'\n'}"
  if [ "$status" != "200" ]; then
    printf '%s' ""
    return 0
  fi

  display_name="$(printf '%s' "$body" | jq -r '.value[0].displayName // empty' 2>/dev/null || true)"
  printf '%s' "$display_name"
}

update_summary_counts() {
  case "$1" in
    PROTECTED_ENABLED_BLOCK) SUMMARY_PROTECTED=$((SUMMARY_PROTECTED + 1)) ;;
    PRESENT_ENABLED_NON_BLOCK) SUMMARY_PRESENT=$((SUMMARY_PRESENT + 1)) ;;
    REPORT_ONLY) SUMMARY_REPORT_ONLY=$((SUMMARY_REPORT_ONLY + 1)) ;;
    DISABLED) SUMMARY_DISABLED=$((SUMMARY_DISABLED + 1)) ;;
    MISSING) SUMMARY_MISSING=$((SUMMARY_MISSING + 1)) ;;
    ERROR_*) SUMMARY_ERRORS=$((SUMMARY_ERRORS + 1)) ;;
  esac
}

process_tenant() {
  local tenant_id="$1"
  local token tenant_display_name policies_tmp
  local policy_json scope_summary effectiveness_json policy_output
  local matching_policies_json
  local matching_policy_count=0
  local effective_policy_found=0
  local status="MISSING"
  local message=""
  local error_text=""
  local has_enabled_block=0
  local has_enabled=0
  local has_report_only=0
  local has_disabled=0

  if ! token="$(get_access_token_for_tenant "$tenant_id")"; then
    error_text="$LAST_TOKEN_ERROR"
    status="ERROR_NO_TOKEN"
    message="Could not acquire a Microsoft Graph token for the tenant."
    append_result "$(build_result_json "$tenant_id" "" "$status" 0 0 "$message" '[]' "$error_text")"
    update_summary_counts "$status"
    return 0
  fi

  if ! verify_token_tenant_context "$tenant_id" "$token"; then
    error_text="${LAST_CONTEXT_ERROR:-Token context could not be verified}"
    status="ERROR_CONTEXT_MISMATCH"
    message="The Graph token did not match the requested tenant."
    append_result "$(build_result_json "$tenant_id" "" "$status" 0 0 "$message" '[]' "$error_text")"
    update_summary_counts "$status"
    return 0
  fi

  tenant_display_name="$(get_tenant_display_name "$token")"

  policies_tmp="$(mktemp)"
  if ! list_conditional_access_policies "$token" "$policies_tmp"; then
    error_text="${LAST_LIST_ERROR:-Policy listing failed}"
    status="ERROR_LIST_POLICIES"
    message="Could not list Conditional Access policies from Microsoft Graph."
    append_result "$(build_result_json "$tenant_id" "$tenant_display_name" "$status" 0 0 "$message" '[]' "$error_text")"
    rm -f "$policies_tmp"
    update_summary_counts "$status"
    return 0
  fi

  matching_policies_json='[]'

  while IFS= read -r policy_json || [ -n "${policy_json:-}" ]; do
    [ -n "$policy_json" ] || continue
    if ! is_device_code_flow_policy "$policy_json"; then
      continue
    fi

    matching_policy_count=$((matching_policy_count + 1))

    effectiveness_json="$(get_policy_effectiveness "$policy_json")"
    scope_summary="$(get_policy_scope_summary "$policy_json")"
    policy_output="$(build_policy_output "$policy_json" "$scope_summary" "$effectiveness_json")"
    matching_policies_json="$(jq -cn --argjson existing "$matching_policies_json" --argjson item "$policy_output" '$existing + [$item]')"

    if printf '%s' "$effectiveness_json" | jq -e '.enabled and .blocksAccess and .hasScope' >/dev/null 2>&1; then
      has_enabled_block=1
    fi
    if printf '%s' "$effectiveness_json" | jq -e '.enabled' >/dev/null 2>&1; then
      has_enabled=1
    elif printf '%s' "$effectiveness_json" | jq -e '.reportOnly' >/dev/null 2>&1; then
      has_report_only=1
    elif printf '%s' "$effectiveness_json" | jq -e '.disabled' >/dev/null 2>&1; then
      has_disabled=1
    fi
  done < "$policies_tmp"

  rm -f "$policies_tmp"

  if [ "$matching_policy_count" -eq 0 ]; then
    status="MISSING"
    message="No Conditional Access policy targeting OAuth Device Code Flow was found."
    append_result "$(build_result_json "$tenant_id" "$tenant_display_name" "$status" 0 0 "$message" '[]' "")"
    update_summary_counts "$status"
    return 0
  fi

  if [ "$has_enabled_block" -eq 1 ]; then
    status="PROTECTED_ENABLED_BLOCK"
    effective_policy_found=1
    message="At least one enabled Device Code Flow policy blocks access."
  elif [ "$has_enabled" -eq 1 ]; then
    status="PRESENT_ENABLED_NON_BLOCK"
    message="An enabled Device Code Flow policy exists, but its grant controls do not clearly block access."
  elif [ "$has_report_only" -eq 1 ]; then
    status="REPORT_ONLY"
    message="A Device Code Flow policy exists, but it is only in report-only mode."
  elif [ "$has_disabled" -eq 1 ]; then
    status="DISABLED"
    message="A Device Code Flow policy exists, but it is disabled."
  else
    status="MISSING"
    message="A policy matched the Device Code Flow condition, but no effective state could be derived."
  fi

  append_result "$(build_result_json "$tenant_id" "$tenant_display_name" "$status" "$matching_policy_count" "$effective_policy_found" "$message" "$matching_policies_json" "")"
  update_summary_counts "$status"
}

cleanup() {
  if [ -n "${TEMP_DIR:-}" ] && [ -d "$TEMP_DIR" ]; then
    rm -rf "$TEMP_DIR"
  fi
}

main() {
  local tenant_line tenant_id active_user

  while [ $# -gt 0 ]; do
    case "$1" in
      --tenant-file)
        if [ $# -lt 2 ]; then
          err "Missing value for --tenant-file"
          exit 2
        fi
        TENANT_FILE="$2"
        shift 2
        ;;
      --json)
        JSON_MODE=1
        TABLE_MODE=0
        shift
        ;;
      --table)
        TABLE_MODE=1
        JSON_MODE=0
        shift
        ;;
      --debug)
        DEBUG_MODE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        err "Unknown argument: $1"
        usage >&2
        exit 2
        ;;
    esac
  done

  need_cmd az
  need_cmd curl
  need_cmd jq
  need_cmd base64

  if ! az account show >/dev/null 2>&1; then
    err "Azure CLI is not logged in or the current account context is unavailable."
    exit 1
  fi
  active_user="$(az account show --query user.name -o tsv 2>/dev/null || true)"
  if [ -z "$active_user" ] || [ "$active_user" = "null" ]; then
    active_user="$(az account show --query user.type -o tsv 2>/dev/null || true)"
  fi
  if [ -z "$active_user" ] || [ "$active_user" = "null" ]; then
    active_user="current Azure CLI session"
  fi
  log "Using Azure CLI login: ${active_user}"

  if [ ! -f "$TENANT_FILE" ]; then
    err "Tenant file not found: $TENANT_FILE"
    exit 1
  fi

  TEMP_DIR="$(mktemp -d)"
  RESULTS_FILE="${TEMP_DIR}/results.jsonl"
  : > "$RESULTS_FILE"
  trap cleanup EXIT

  while IFS= read -r tenant_line || [ -n "${tenant_line:-}" ]; do
    tenant_id="$(trim "$(strip_cr "${tenant_line:-}")")"
    case "$tenant_id" in
      ""|\#*) continue ;;
    esac

    SUMMARY_TENANTS_TOTAL=$((SUMMARY_TENANTS_TOTAL + 1))
    log "Processing tenant: ${tenant_id}"
    process_tenant "$tenant_id"
  done < "$TENANT_FILE"

  if [ "$JSON_MODE" -eq 1 ]; then
    jq -cs \
      --arg generatedAt "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
      --arg script "$SCRIPT_NAME" \
      --argjson tenantsTotal "$SUMMARY_TENANTS_TOTAL" \
      --argjson protectedEnabledBlock "$SUMMARY_PROTECTED" \
      --argjson presentEnabledNonBlock "$SUMMARY_PRESENT" \
      --argjson reportOnly "$SUMMARY_REPORT_ONLY" \
      --argjson disabled "$SUMMARY_DISABLED" \
      --argjson missing "$SUMMARY_MISSING" \
      --argjson errors "$SUMMARY_ERRORS" \
      '{
        generatedAt: $generatedAt,
        script: $script,
        summary: {
          tenantsTotal: $tenantsTotal,
          protectedEnabledBlock: $protectedEnabledBlock,
          presentEnabledNonBlock: $presentEnabledNonBlock,
          reportOnly: $reportOnly,
          disabled: $disabled,
          missing: $missing,
          errors: $errors
        },
        results: .
      }' < "$RESULTS_FILE"
    return 0
  fi

  {
    printf 'TENANT_ID\tTENANT_NAME\tSTATUS\tMATCHING_POLICIES\tEFFECTIVE_BLOCK\tPOLICY_NAMES\tERROR\n'
    jq -r '
      [
        .tenantId,
        (.tenantDisplayName // ""),
        .status,
        (.matchingPolicyCount | tostring),
        ((.effectivePolicyFound // false) | tostring),
        ((.policies // []) | map(.displayName) | join("; ")),
        (.error // "")
      ] | @tsv
    ' < "$RESULTS_FILE"
    printf '\nSummary:\n'
    printf '  Tenants total:           %s\n' "$SUMMARY_TENANTS_TOTAL"
    printf '  PROTECTED_ENABLED_BLOCK: %s\n' "$SUMMARY_PROTECTED"
    printf '  PRESENT_ENABLED_NON_BLOCK: %s\n' "$SUMMARY_PRESENT"
    printf '  REPORT_ONLY:            %s\n' "$SUMMARY_REPORT_ONLY"
    printf '  DISABLED:                %s\n' "$SUMMARY_DISABLED"
    printf '  MISSING:                 %s\n' "$SUMMARY_MISSING"
    printf '  ERRORS:                  %s\n' "$SUMMARY_ERRORS"
  } | print_table
}

main "$@"
