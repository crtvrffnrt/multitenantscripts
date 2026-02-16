#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

TARGET_FILE=""
REFERENCE_POLICY=""
MATCH_STRING_1=""
MATCH_STRING_2=""
MODE=""
SETTING_CHECKS_RAW=""
TABLE_MODE=0
DEBUG_MODE=0
REFERENCE_POLICY_NAME=""
LAST_TOKEN_ERROR=""
LAST_CONTEXT_ERROR=""
LAST_LIST_ERROR=""
SETTING_CHECK_MODE=0
declare -a SETTING_CHECK_KEYS=()
declare -a SETTING_CHECK_PATHS=()

usage() {
  cat <<'EOF'
Usage:
  multitenant_ca_policy_guard.sh \
    --target tenants.txt \
    --reference-policy first_conditional_access_policy.json \
    [--match-string-1 "CDOC Analysts"] \
    [--match-string-2 "CA00"] \
    [--setting-check state,target-apps,assigned-users] \
    [--tablemode] \
    [--debug] \
    --mode check|change

Required parameters:
  --target FILE              Tenant list file (one tenant ID per line)
  --reference-policy FILE    Reference Conditional Access policy JSON
  --match-string-1 STRING    Optional: policy displayName must contain this substring
  --match-string-2 STRING    Optional: policy displayName must contain this substring
  --setting-check LIST       Optional compact check output for specific settings (comma-separated)
  --tablemode                Optional: print CLI table output instead of JSON
  --debug                    Optional: verbose debug logs to stderr
  --mode check|change        Execution mode

Behavior:
  check  - evaluate compliance and print structured JSON output
  change - evaluate, patch non-compliant policy, re-validate, print JSON output

Setting-check mode:
  - Use with --mode check to emit compact per-setting results:
      tenantId, caFound, setting, matchesReference, error
  - Supported setting names:
      state, assigned-users, target-apps, conditions, grant-controls, session-controls
  - Custom paths are supported with path:<jq-path>, for example:
      --setting-check state,path:.conditions.platforms.includePlatforms

Notes:
  - Uses current active Azure CLI session (no az login performed by script)
  - If no match strings are provided, policy displayName must exactly match reference policy name (case-insensitive)
  - Never changes displayName
  - If multiple policies match in one tenant, no change is applied and result is reported
EOF
}

log() { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
warn() { printf '[%s] WARN: %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
err() { printf '[%s] ERROR: %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2; }
debug() {
  if [[ "$DEBUG_MODE" -eq 1 ]]; then
    printf '[%s] DEBUG: %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing required command: $1"; exit 1; }
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

json_escape() {
  jq -Rn --arg s "$1" '$s'
}

normalize_policy_json() {
  jq -c '
    def deep_sort:
      if type == "object" then
        to_entries
        | sort_by(.key)
        | map(.value |= deep_sort)
        | from_entries
      elif type == "array" then
        map(deep_sort) | sort_by(tostring)
      else
        .
      end;

    walk(
      if type == "object" then
        with_entries(
          select((.key | test("@odata"; "i")) | not)
        )
      else
        .
      end
    )
    | del(
        .id,
        .createdDateTime,
        .modifiedDateTime,
        .deletedDateTime,
        .templateId,
        .displayName
      )
    | deep_sort
  '
}

build_patch_payload_from_reference() {
  jq -c '
    {
      state: .state,
      conditions: .conditions,
      grantControls: .grantControls
    }
    + (if has("sessionControls") then {sessionControls: .sessionControls} else {} end)
  ' "$REFERENCE_POLICY"
}

get_access_token_for_tenant() {
  local tenant_id="$1"
  local token=""
  local err_file
  local -a az_cmd
  err_file="$(mktemp)"
  LAST_TOKEN_ERROR=""
  debug "Token acquisition started for tenant ${tenant_id}"

  # 1) Legacy/resource syntax (works in many existing environments).
  az_cmd=(az account get-access-token --tenant "$tenant_id" --resource https://graph.microsoft.com --query accessToken -o tsv)
  if command -v timeout >/dev/null 2>&1; then
    token="$(timeout "${AZ_TOKEN_TIMEOUT_SEC:-30}" "${az_cmd[@]}" 2>"$err_file" || true)"
  else
    token="$("${az_cmd[@]}" 2>"$err_file" || true)"
  fi
  if [[ -n "${token:-}" ]]; then
    debug "Token acquired via legacy resource syntax for tenant ${tenant_id}"
    rm -f "$err_file"
    printf '%s' "$token"
    return 0
  fi
  LAST_TOKEN_ERROR+="legacy(resource): $(tr '\n' ' ' < "$err_file") "

  # 2) Resource-type syntax.
  az_cmd=(az account get-access-token --tenant "$tenant_id" --resource-type ms-graph --query accessToken -o tsv)
  if command -v timeout >/dev/null 2>&1; then
    token="$(timeout "${AZ_TOKEN_TIMEOUT_SEC:-30}" "${az_cmd[@]}" 2>"$err_file" || true)"
  else
    token="$("${az_cmd[@]}" 2>"$err_file" || true)"
  fi
  if [[ -n "${token:-}" ]]; then
    debug "Token acquired via resource-type syntax for tenant ${tenant_id}"
    rm -f "$err_file"
    printf '%s' "$token"
    return 0
  fi
  LAST_TOKEN_ERROR+="resource-type(ms-graph): $(tr '\n' ' ' < "$err_file") "

  # 3) Scope syntax.
  az_cmd=(az account get-access-token --tenant "$tenant_id" --scope https://graph.microsoft.com/.default --query accessToken -o tsv)
  if command -v timeout >/dev/null 2>&1; then
    token="$(timeout "${AZ_TOKEN_TIMEOUT_SEC:-30}" "${az_cmd[@]}" 2>"$err_file" || true)"
  else
    token="$("${az_cmd[@]}" 2>"$err_file" || true)"
  fi
  if [[ -n "${token:-}" ]]; then
    debug "Token acquired via scope syntax for tenant ${tenant_id}"
    rm -f "$err_file"
    printf '%s' "$token"
    return 0
  fi
  LAST_TOKEN_ERROR+="scope(.default): $(tr '\n' ' ' < "$err_file") "

  # 4) No explicit tenant fallback (guest/GDAP sessions can still mint token).
  az_cmd=(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)
  if command -v timeout >/dev/null 2>&1; then
    token="$(timeout "${AZ_TOKEN_TIMEOUT_SEC:-30}" "${az_cmd[@]}" 2>"$err_file" || true)"
  else
    token="$("${az_cmd[@]}" 2>"$err_file" || true)"
  fi
  if [[ -n "${token:-}" ]] && token_matches_tenant "$token" "$tenant_id"; then
    debug "Token acquired via no-tenant fallback and matched tenant ${tenant_id}"
    rm -f "$err_file"
    printf '%s' "$token"
    return 0
  fi
  LAST_TOKEN_ERROR+="fallback(no-tenant): $(tr '\n' ' ' < "$err_file") "

  rm -f "$err_file"
  return 1
}

jwt_tid_from_token() {
  local token="$1"
  local payload padded mod
  payload="$(printf '%s' "$token" | cut -d'.' -f2)"
  [[ -n "$payload" ]] || return 1

  payload="${payload//-/+}"
  payload="${payload//_/\/}"
  mod=$(( ${#payload} % 4 ))
  if [[ "$mod" -eq 2 ]]; then
    padded="${payload}=="
  elif [[ "$mod" -eq 3 ]]; then
    padded="${payload}="
  elif [[ "$mod" -eq 0 ]]; then
    padded="$payload"
  else
    return 1
  fi

  printf '%s' "$padded" | base64 -d 2>/dev/null | jq -r '.tid // empty' 2>/dev/null || true
}

token_matches_tenant() {
  local token="$1"
  local tenant_id="$2"
  local tid
  tid="$(jwt_tid_from_token "$token")"
  [[ -n "${tid:-}" ]] || return 1
  [[ "${tid,,}" == "${tenant_id,,}" ]]
}

graph_request() {
  local method="$1"
  local token="$2"
  local url="$3"
  local body_file="${4:-}"

  local raw status body
  local curl_connect_timeout curl_max_time
  curl_connect_timeout="${CURL_CONNECT_TIMEOUT_SEC:-10}"
  curl_max_time="${CURL_MAX_TIME_SEC:-45}"

  if [[ -n "$body_file" ]]; then
    if ! raw="$(curl -sS -X "$method" \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: application/json" \
      --connect-timeout "$curl_connect_timeout" \
      --max-time "$curl_max_time" \
      --data "@${body_file}" \
      "$url" \
      -w $'\n%{http_code}' 2>&1)"; then
      status="000"
      body="$(jq -cn --arg m "$(printf 'curl error (%s): %.800s' "$method" "$raw")" '{error:{code:"CURL_FAILED",message:$m}}')"
      printf '%s\n%s' "$status" "$body"
      return 0
    fi
  else
    if ! raw="$(curl -sS -X "$method" \
      -H "Authorization: Bearer ${token}" \
      --connect-timeout "$curl_connect_timeout" \
      --max-time "$curl_max_time" \
      "$url" \
      -w $'\n%{http_code}' 2>&1)"; then
      status="000"
      body="$(jq -cn --arg m "$(printf 'curl error (%s): %.800s' "$method" "$raw")" '{error:{code:"CURL_FAILED",message:$m}}')"
      printf '%s\n%s' "$status" "$body"
      return 0
    fi
  fi

  status="${raw##*$'\n'}"
  body="${raw%$'\n'*}"
  if [[ ! "$status" =~ ^[0-9]{3}$ ]]; then
    status="000"
    body="$(jq -cn --arg m "$(printf 'unexpected HTTP wrapper output: %.800s' "$raw")" '{error:{code:"HTTP_PARSE_FAILED",message:$m}}')"
  fi
  printf '%s\n%s' "$status" "$body"
}

verify_token_tenant_context() {
  local tenant_id="$1"
  local token="$2"
  local response status body org_id
  LAST_CONTEXT_ERROR=""

  # Preferred: verify by token claim; works even with restricted Graph permissions.
  if token_matches_tenant "$token" "$tenant_id"; then
    debug "Tenant context verified via token claim for tenant ${tenant_id}"
    return 0
  fi

  debug "Token claim check failed for tenant ${tenant_id}, verifying via Graph organization endpoint"
  response="$(graph_request GET "$token" "https://graph.microsoft.com/v1.0/organization?\$select=id,displayName")"
  status="$(printf '%s' "$response" | head -n1)"
  body="$(printf '%s' "$response" | tail -n +2)"

  if [[ "$status" != "200" ]]; then
    LAST_CONTEXT_ERROR="Context verification Graph call failed with HTTP ${status}"
    debug "Tenant context verification Graph call failed for ${tenant_id} with status ${status}"
    return 1
  fi

  org_id="$(printf '%s' "$body" | jq -r '.value[0].id // empty' 2>/dev/null || true)"
  if [[ -z "$org_id" ]]; then
    LAST_CONTEXT_ERROR="Context verification response had no organization id"
    return 1
  fi

  if [[ "${org_id,,}" != "${tenant_id,,}" ]]; then
    LAST_CONTEXT_ERROR="Context mismatch. Token org id ${org_id} does not match target tenant ${tenant_id}"
    debug "Tenant context mismatch for ${tenant_id}: org id was ${org_id}"
    return 1
  fi

  debug "Tenant context verified via Graph organization call for tenant ${tenant_id}"
  return 0
}

list_policies_with_fallback() {
  local token="$1"
  local response status body
  local next api_version page_count
  local all_json='[]'
  LAST_LIST_ERROR=""

  for api_version in "v1.0" "beta"; do
    next="https://graph.microsoft.com/${api_version}/identity/conditionalAccess/policies"
    all_json='[]'
    page_count=0
    local success=1
    debug "Listing CA policies using Graph ${api_version}"

    while [[ -n "$next" ]]; do
      page_count=$((page_count + 1))
      debug "Graph ${api_version} page ${page_count}: ${next}"
      response="$(graph_request GET "$token" "$next")"
      status="$(printf '%s' "$response" | head -n1)"
      body="$(printf '%s' "$response" | tail -n +2)"

      if [[ "$status" != "200" ]]; then
        LAST_LIST_ERROR="Graph ${api_version} list failed with HTTP ${status}: $(printf '%.500s' "$body")"
        debug "Graph ${api_version} list failed at page ${page_count} with status ${status}"
        success=0
        break
      fi

      if ! jq empty <<< "$body" >/dev/null 2>&1; then
        LAST_LIST_ERROR="Graph ${api_version} list returned invalid JSON body"
        debug "Graph ${api_version} list returned invalid JSON at page ${page_count}"
        success=0
        break
      fi

      all_json="$(jq -c --argjson current "$all_json" --argjson page "$body" '$current + ($page.value // [])' <<< '{}')"
      next="$(printf '%s' "$body" | jq -r '."@odata.nextLink" // empty')"
      debug "Graph ${api_version} page ${page_count} fetched; nextLink present: $([[ -n "$next" ]] && echo true || echo false)"
    done

    if [[ "$success" -eq 1 ]]; then
      debug "Policy listing successful using ${api_version}; pages fetched: ${page_count}"
      printf '%s\n%s' "$api_version" "$all_json"
      return 0
    fi
  done

  debug "Policy listing failed for both v1.0 and beta"
  return 1
}

compute_diff_entries() {
  local actual="$1"
  local expected="$2"

  jq -cn --argjson actual "$actual" --argjson expected "$expected" '
    def allpaths(x): [x | paths];
    def getp(obj; p): try (obj | getpath(p)) catch "__MISSING__";
    def pstr(p): (p | map(tostring) | join("."));
    (
      ([allpaths($actual)[], allpaths($expected)[]] | unique) as $ps
      | [ $ps[] as $p
          | (getp($actual; $p)) as $a
          | (getp($expected; $p)) as $e
          | select($a != $e)
          | {path: pstr($p), actual: $a, expected: $e}
        ]
    )
  '
}

compute_deviation_object() {
  local actual="$1"
  local expected="$2"

  jq -cn --argjson actual "$actual" --argjson expected "$expected" '
    def arr(v): if v == null then [] elif (v | type) == "array" then v else [v] end;
    def diff(expected; actual): (arr(expected) - arr(actual));
    def scope(users):
      if ((users.includeUsers // []) | index("All")) != null then "all_users"
      elif ((users.includeGroups // []) | length) > 0 then "specific_groups"
      else "scoped_or_specific_users"
      end;
    def allpaths(x): [x | paths];
    def getp(obj; p): try (obj | getpath(p)) catch "__MISSING__";
    def pstr(p): (p | map(tostring) | join("."));
    def leaf_diffs(a; b):
      ([allpaths(a)[], allpaths(b)[]] | unique) as $ps
      | [ $ps[] as $p
          | (getp(a; $p)) as $av
          | (getp(b; $p)) as $bv
          | select($av != $bv)
          | {path: pstr($p), actual: $av, expected: $bv}
        ];

    {
      assignments: {
        actualScope: scope($actual.conditions.users // {}),
        expectedScope: scope($expected.conditions.users // {}),
        missingIncludeGroups: diff(($expected.conditions.users.includeGroups // []); ($actual.conditions.users.includeGroups // [])),
        missingExcludeGroups: diff(($expected.conditions.users.excludeGroups // []); ($actual.conditions.users.excludeGroups // [])),
        missingIncludeUsers: diff(($expected.conditions.users.includeUsers // []); ($actual.conditions.users.includeUsers // [])),
        missingExcludeUsers: diff(($expected.conditions.users.excludeUsers // []); ($actual.conditions.users.excludeUsers // [])),
        missingIncludeRoles: diff(($expected.conditions.users.includeRoles // []); ($actual.conditions.users.includeRoles // [])),
        missingExcludeRoles: diff(($expected.conditions.users.excludeRoles // []); ($actual.conditions.users.excludeRoles // []))
      },
      targetApps: {
        compliant: (($actual.conditions.applications // null) == ($expected.conditions.applications // null)),
        actual: ($actual.conditions.applications // null),
        expected: ($expected.conditions.applications // null)
      },
      conditionDifferences: leaf_diffs(($actual.conditions // {}); ($expected.conditions // {})),
      grantControlDifferences: leaf_diffs(($actual.grantControls // {}); ($expected.grantControls // {})),
      sessionControlDifferences: leaf_diffs(($actual.sessionControls // {}); ($expected.sessionControls // {}))
    }
  '
}

setting_name_to_path() {
  local raw="$1"
  local token norm custom

  token="$(trim "$raw")"
  [[ -n "$token" ]] || return 1

  if [[ "$token" == path:* ]]; then
    custom="${token#path:}"
    custom="$(trim "$custom")"
    [[ "$custom" == .* ]] || return 1
    printf '%s\n%s' "$custom" "$custom"
    return 0
  fi

  if [[ "$token" == .* ]]; then
    printf '%s\n%s' "$token" "$token"
    return 0
  fi

  norm="${token,,}"
  norm="${norm// /}"
  norm="${norm//-/}"
  norm="${norm//_/}"

  case "$norm" in
    state)
      printf 'state\n.state'
      ;;
    assigneduser|assignedusers|users)
      printf 'assigned-users\n.conditions.users'
      ;;
    targetapp|targetapps|app|apps|application|applications)
      printf 'target-apps\n.conditions.applications'
      ;;
    conditions)
      printf 'conditions\n.conditions'
      ;;
    grantcontrol|grantcontrols|grant)
      printf 'grant-controls\n.grantControls'
      ;;
    sessioncontrol|sessioncontrols|session)
      printf 'session-controls\n.sessionControls'
      ;;
    *)
      return 1
      ;;
  esac
}

normalize_json_value() {
  local json_value="$1"
  jq -cn --argjson v "$json_value" '
    def deep_sort:
      if type == "object" then
        to_entries
        | sort_by(.key)
        | map(.value |= deep_sort)
        | from_entries
      elif type == "array" then
        map(deep_sort) | sort_by(tostring)
      else
        .
      end;
    (
      $v
      | walk(
          if type == "object" then
            with_entries(select((.key | test("@odata"; "i")) | not))
          else
            .
          end
        )
      | deep_sort
    )
  '
}

build_setting_rows() {
  local tenant_id="$1"
  local found="$2"
  local actual_policy_json="$3"
  local err_msg="${4:-}"
  local i key path actual expected actual_norm expected_norm matches

  for i in "${!SETTING_CHECK_KEYS[@]}"; do
    key="${SETTING_CHECK_KEYS[$i]}"
    path="${SETTING_CHECK_PATHS[$i]}"

    if [[ "$found" == "true" ]]; then
      actual="$(jq -c "$path // null" <<< "$actual_policy_json")"
      expected="$(jq -c "$path // null" "$REFERENCE_POLICY")"
      actual_norm="$(normalize_json_value "$actual")"
      expected_norm="$(normalize_json_value "$expected")"
      if [[ "$actual_norm" == "$expected_norm" ]]; then
        matches="true"
      else
        matches="false"
      fi
    else
      matches="false"
    fi

    append_result "$(jq -cn \
      --arg tenantId "$tenant_id" \
      --arg setting "$key" \
      --arg error "$err_msg" \
      --argjson caFound "$found" \
      --argjson matchesReference "$matches" \
      '{
        tenantId: $tenantId,
        caFound: $caFound,
        setting: $setting,
        matchesReference: $matchesReference,
        error: $error
      }')"
  done
}

append_result() {
  local json="$1"
  jq -c --argjson item "$json" '. + [$item]' "$RESULTS_FILE" > "${RESULTS_FILE}.tmp"
  mv "${RESULTS_FILE}.tmp" "$RESULTS_FILE"
}

print_table() {
  local tsv="$1"
  if command -v column >/dev/null 2>&1; then
    printf '%s\n' "$tsv" | column -t -s $'\t'
  else
    printf '%s\n' "$tsv"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target)
        TARGET_FILE="${2:-}"; shift 2
        ;;
      --reference-policy)
        REFERENCE_POLICY="${2:-}"; shift 2
        ;;
      --match-string-1)
        MATCH_STRING_1="${2:-}"; shift 2
        ;;
      --match-string-2)
        MATCH_STRING_2="${2:-}"; shift 2
        ;;
      --mode)
        MODE="${2:-}"; shift 2
        ;;
      --setting-check)
        SETTING_CHECKS_RAW="${2:-}"; shift 2
        ;;
      --tablemode)
        TABLE_MODE=1; shift 1
        ;;
      --debug|--deebug)
        DEBUG_MODE=1; shift 1
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
}

validate_inputs() {
  [[ -n "$TARGET_FILE" ]] || { err "--target is required"; exit 2; }
  [[ -n "$REFERENCE_POLICY" ]] || { err "--reference-policy is required"; exit 2; }
  [[ -n "$MODE" ]] || { err "--mode is required"; exit 2; }
  [[ "$MODE" == "check" || "$MODE" == "change" ]] || { err "--mode must be check|change"; exit 2; }

  [[ -f "$TARGET_FILE" ]] || { err "Tenant file not found: $TARGET_FILE"; exit 1; }
  [[ -f "$REFERENCE_POLICY" ]] || { err "Reference policy file not found: $REFERENCE_POLICY"; exit 1; }

  jq empty "$REFERENCE_POLICY" >/dev/null 2>&1 || { err "Reference policy is not valid JSON: $REFERENCE_POLICY"; exit 1; }

  local has_state has_conditions has_grants
  has_state="$(jq -r 'has("state")' "$REFERENCE_POLICY")"
  has_conditions="$(jq -r 'has("conditions")' "$REFERENCE_POLICY")"
  has_grants="$(jq -r 'has("grantControls")' "$REFERENCE_POLICY")"
  [[ "$has_state" == "true" && "$has_conditions" == "true" && "$has_grants" == "true" ]] || {
    err "Reference policy must include at least: state, conditions, grantControls"
    exit 1
  }

  REFERENCE_POLICY_NAME="$(jq -r '.displayName // .Name // empty' "$REFERENCE_POLICY")"
  if [[ -z "$REFERENCE_POLICY_NAME" && -z "$MATCH_STRING_1" && -z "$MATCH_STRING_2" ]]; then
    err "Reference policy must include displayName/Name when match strings are not provided"
    exit 1
  fi

  if [[ -n "${SETTING_CHECKS_RAW:-}" ]]; then
    local raw_items item resolved key path
    if [[ "$MODE" != "check" ]]; then
      err "--setting-check can only be used with --mode check"
      exit 2
    fi

    SETTING_CHECK_MODE=1
    IFS=',' read -r -a raw_items <<< "$SETTING_CHECKS_RAW"
    for item in "${raw_items[@]}"; do
      item="$(trim "$item")"
      [[ -n "$item" ]] || continue
      if ! resolved="$(setting_name_to_path "$item")"; then
        err "Unknown setting-check selector: $item"
        err "Use: state, assigned-users, target-apps, conditions, grant-controls, session-controls, or path:<jq-path>"
        exit 2
      fi
      key="$(printf '%s' "$resolved" | head -n1)"
      path="$(printf '%s' "$resolved" | tail -n1)"
      SETTING_CHECK_KEYS+=("$key")
      SETTING_CHECK_PATHS+=("$path")
    done

    if [[ "${#SETTING_CHECK_KEYS[@]}" -eq 0 ]]; then
      err "--setting-check was provided but no valid selectors were parsed"
      exit 2
    fi
  fi
}

main() {
  need_cmd az
  need_cmd jq
  need_cmd curl
  need_cmd base64

  parse_args "$@"
  validate_inputs
  debug "Arguments parsed. mode=${MODE}, tablemode=${TABLE_MODE}, setting_check_mode=${SETTING_CHECK_MODE}, target=${TARGET_FILE}"

  if ! az account show >/dev/null 2>&1; then
    err "Azure CLI is not logged in. Run: az login"
    exit 1
  fi

  REFERENCE_NORMALIZED="$(normalize_policy_json < "$REFERENCE_POLICY")"
  PATCH_PAYLOAD="$(build_patch_payload_from_reference)"

  RESULTS_FILE="$(mktemp)"
  echo '[]' > "$RESULTS_FILE"
  trap 'rm -f "$RESULTS_FILE" "${RESULTS_FILE}.tmp"' EXIT

  local tenant_id token api_version policies_json matches_count
  local tenant_json result_json
  local policy_json policy_id display_name
  local actual_normalized compliant deviations
  local patch_response patch_status patch_body post_json post_norm post_compliant post_diff
  local match1_lc match2_lc reference_name_lc

  match1_lc="${MATCH_STRING_1,,}"
  match2_lc="${MATCH_STRING_2,,}"
  reference_name_lc="${REFERENCE_POLICY_NAME,,}"

  while IFS= read -r tenant_id || [[ -n "${tenant_id:-}" ]]; do
    tenant_id="$(strip_cr "${tenant_id:-}")"
    case "$tenant_id" in ""|\#*) continue ;; esac

    log "Processing tenant ${tenant_id}"
    debug "Starting tenant workflow for ${tenant_id}"

    token="$(get_access_token_for_tenant "$tenant_id")"
    if [[ -z "${token:-}" ]]; then
      debug "Skipping tenant ${tenant_id}: token acquisition failed"
      if [[ "$SETTING_CHECK_MODE" -eq 1 ]]; then
        build_setting_rows "$tenant_id" "false" "{}" "ERROR_NO_TOKEN: ${LAST_TOKEN_ERROR:-Could not get Graph token for tenant}"
        continue
      fi
      append_result "$(jq -cn \
        --arg tenantId "$tenant_id" \
        --arg tokenError "${LAST_TOKEN_ERROR:-}" \
        '{
          tenantId: $tenantId,
          status: "ERROR_NO_TOKEN",
          policyExists: false,
          configurationCompliant: false,
          remediationAttempted: false,
          message: "Could not get Graph token for tenant",
          tokenAcquisitionError: $tokenError
        }')"
      continue
    fi

    if ! verify_token_tenant_context "$tenant_id" "$token"; then
      debug "Skipping tenant ${tenant_id}: tenant context verification failed"
      if [[ "$SETTING_CHECK_MODE" -eq 1 ]]; then
        build_setting_rows "$tenant_id" "false" "{}" "ERROR_TENANT_CONTEXT_MISMATCH: ${LAST_CONTEXT_ERROR:-Tenant context verification failed}"
        continue
      fi
      append_result "$(jq -cn \
        --arg tenantId "$tenant_id" \
        --arg details "${LAST_CONTEXT_ERROR:-}" \
        '{
          tenantId: $tenantId,
          status: "ERROR_TENANT_CONTEXT_MISMATCH",
          policyExists: false,
          configurationCompliant: false,
          remediationAttempted: false,
          message: "Tenant context verification failed, skipping for safety",
          details: $details
        }')"
      continue
    fi

    if ! tenant_json="$(list_policies_with_fallback "$token")"; then
      debug "Skipping tenant ${tenant_id}: unable to list policies"
      if [[ "$SETTING_CHECK_MODE" -eq 1 ]]; then
        build_setting_rows "$tenant_id" "false" "{}" "ERROR_LIST_POLICIES_FAILED: ${LAST_LIST_ERROR:-Failed to list Conditional Access policies}"
        continue
      fi
      append_result "$(jq -cn \
        --arg tenantId "$tenant_id" \
        --arg details "${LAST_LIST_ERROR:-}" \
        '{
          tenantId: $tenantId,
          status: "ERROR_LIST_POLICIES_FAILED",
          policyExists: false,
          configurationCompliant: false,
          remediationAttempted: false,
          message: "Failed to list Conditional Access policies via v1.0 and beta",
          details: $details
        }')"
      continue
    fi

    api_version="$(printf '%s' "$tenant_json" | head -n1)"
    policies_json="$(printf '%s' "$tenant_json" | tail -n +2)"

    matches_count="$(
      jq -r --arg m1 "$match1_lc" --arg m2 "$match2_lc" --arg ref "$reference_name_lc" '
        [ .[]
          | select(
              (.displayName // "" | ascii_downcase) as $dn
              | if ($m1 == "" and $m2 == "") then
                  ($dn == $ref)
                else
                  (($m1 == "" or ($dn | contains($m1)))
                  and
                  ($m2 == "" or ($dn | contains($m2))))
                end
            )
        ] | length
      ' <<< "$policies_json"
    )"
    debug "Tenant ${tenant_id}: matching policies count=${matches_count}"

    if [[ "$matches_count" == "0" ]]; then
      if [[ "$SETTING_CHECK_MODE" -eq 1 ]]; then
        build_setting_rows "$tenant_id" "false" "{}" "NOT_FOUND: No matching policy in tenant"
        continue
      fi
      append_result "$(jq -cn \
        --arg tenantId "$tenant_id" \
        --arg api "$api_version" \
        '{
          tenantId: $tenantId,
          graphApiVersionUsed: $api,
          status: "NOT_FOUND",
          policyExists: false,
          configurationCompliant: false,
          remediationAttempted: false,
          remediationApplied: false
        }')"
      continue
    fi

    if [[ "$matches_count" != "1" ]]; then
      debug "Tenant ${tenant_id}: multiple matching policies found"
      if [[ "$SETTING_CHECK_MODE" -eq 1 ]]; then
        build_setting_rows "$tenant_id" "false" "{}" "MULTIPLE_MATCHES: Multiple matching policies found"
        continue
      fi
      append_result "$(
        jq -cn \
          --arg tenantId "$tenant_id" \
          --arg api "$api_version" \
          --argjson matches "$(jq -c --arg m1 "$match1_lc" --arg m2 "$match2_lc" --arg ref "$reference_name_lc" '
            [ .[]
              | select(
                  (.displayName // "" | ascii_downcase) as $dn
                  | if ($m1 == "" and $m2 == "") then
                      ($dn == $ref)
                    else
                      (($m1 == "" or ($dn | contains($m1)))
                      and
                      ($m2 == "" or ($dn | contains($m2))))
                    end
                )
              | {id, displayName, state}
            ]
          ' <<< "$policies_json")" \
          '{
            tenantId: $tenantId,
            graphApiVersionUsed: $api,
            status: "MULTIPLE_MATCHES",
            policyExists: true,
            configurationCompliant: false,
            remediationAttempted: false,
            remediationApplied: false,
            message: "Multiple matching policies found. No action taken.",
            matchingPolicies: $matches
          }'
      )"
      continue
    fi

    policy_json="$(
      jq -c --arg m1 "$match1_lc" --arg m2 "$match2_lc" --arg ref "$reference_name_lc" '
        [ .[]
          | select(
              (.displayName // "" | ascii_downcase) as $dn
              | if ($m1 == "" and $m2 == "") then
                  ($dn == $ref)
                else
                  (($m1 == "" or ($dn | contains($m1)))
                  and
                  ($m2 == "" or ($dn | contains($m2))))
                end
            )
        ][0]
      ' <<< "$policies_json"
    )"

    policy_id="$(jq -r '.id // empty' <<< "$policy_json")"
    display_name="$(jq -r '.displayName // empty' <<< "$policy_json")"

    if [[ -z "$policy_id" ]]; then
      debug "Tenant ${tenant_id}: matched policy had empty id"
      if [[ "$SETTING_CHECK_MODE" -eq 1 ]]; then
        build_setting_rows "$tenant_id" "false" "{}" "ERROR_MATCH_PARSE: Matched policy had no id"
        continue
      fi
      append_result "$(jq -cn \
        --arg tenantId "$tenant_id" \
        '{
          tenantId: $tenantId,
          status: "ERROR_MATCH_PARSE",
          policyExists: false,
          configurationCompliant: false,
          remediationAttempted: false,
          remediationApplied: false,
          message: "Matched policy had no id"
        }')"
      continue
    fi

    actual_normalized="$(normalize_policy_json <<< "$policy_json")"

    if [[ "$SETTING_CHECK_MODE" -eq 1 ]]; then
      debug "Tenant ${tenant_id}: emitting compact setting-check rows"
      build_setting_rows "$tenant_id" "true" "$policy_json" ""
      continue
    fi

    compliant="false"
    if [[ "$actual_normalized" == "$REFERENCE_NORMALIZED" ]]; then
      compliant="true"
    fi
    debug "Tenant ${tenant_id}: compliance result=${compliant}"

    deviations="$(compute_deviation_object "$actual_normalized" "$REFERENCE_NORMALIZED")"

    if [[ "$MODE" == "check" ]]; then
      append_result "$(jq -cn \
        --arg tenantId "$tenant_id" \
        --arg api "$api_version" \
        --arg policyId "$policy_id" \
        --arg displayName "$display_name" \
        --argjson compliant "$compliant" \
        --argjson deviations "$deviations" \
        '{
          tenantId: $tenantId,
          graphApiVersionUsed: $api,
          status: "CHECKED",
          policyExists: true,
          policyId: $policyId,
          policyDisplayName: $displayName,
          configurationCompliant: $compliant,
          remediationAttempted: false,
          remediationApplied: false,
          deviations: $deviations
        }')"
      continue
    fi

    # change mode
    if [[ "$compliant" == "true" ]]; then
      debug "Tenant ${tenant_id}: already compliant, no remediation needed"
      append_result "$(jq -cn \
        --arg tenantId "$tenant_id" \
        --arg api "$api_version" \
        --arg policyId "$policy_id" \
        --arg displayName "$display_name" \
        --argjson deviations "$deviations" \
        '{
          tenantId: $tenantId,
          graphApiVersionUsed: $api,
          status: "ALREADY_COMPLIANT",
          policyExists: true,
          policyId: $policyId,
          policyDisplayName: $displayName,
          configurationCompliant: true,
          remediationAttempted: false,
          remediationApplied: false,
          deviations: $deviations
        }')"
      continue
    fi

    if ! verify_token_tenant_context "$tenant_id" "$token"; then
      debug "Tenant ${tenant_id}: pre-patch tenant context check failed"
      append_result "$(jq -cn \
        --arg tenantId "$tenant_id" \
        --arg policyId "$policy_id" \
        --arg displayName "$display_name" \
        --argjson deviations "$deviations" \
        '{
          tenantId: $tenantId,
          status: "ERROR_PREPATCH_TENANT_CONTEXT_MISMATCH",
          policyExists: true,
          policyId: $policyId,
          policyDisplayName: $displayName,
          configurationCompliant: false,
          remediationAttempted: false,
          remediationApplied: false,
          deviations: $deviations,
          message: "Tenant context check failed before PATCH. No action taken."
        }')"
      continue
    fi

    patch_file="$(mktemp)"
    printf '%s' "$PATCH_PAYLOAD" > "$patch_file"

    patch_response="$(graph_request PATCH "$token" "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/${policy_id}" "$patch_file")"
    rm -f "$patch_file"

    patch_status="$(printf '%s' "$patch_response" | head -n1)"
    patch_body="$(printf '%s' "$patch_response" | tail -n +2)"

    if [[ "$patch_status" != "204" ]]; then
      debug "Tenant ${tenant_id}: patch failed with status ${patch_status}"
      append_result "$(jq -cn \
        --arg tenantId "$tenant_id" \
        --arg policyId "$policy_id" \
        --arg displayName "$display_name" \
        --arg statusCode "$patch_status" \
        --arg body "$patch_body" \
        --argjson deviations "$deviations" \
        '{
          tenantId: $tenantId,
          status: "PATCH_FAILED",
          policyExists: true,
          policyId: $policyId,
          policyDisplayName: $displayName,
          configurationCompliant: false,
          remediationAttempted: true,
          remediationApplied: false,
          deviations: $deviations,
          patchHttpStatus: $statusCode,
          patchResponseBody: $body
        }')"
      continue
    fi

    # re-fetch and validate
    post_resp="$(graph_request GET "$token" "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/${policy_id}")"
    post_status="$(printf '%s' "$post_resp" | head -n1)"
    post_body="$(printf '%s' "$post_resp" | tail -n +2)"

    if [[ "$post_status" != "200" ]]; then
      debug "Tenant ${tenant_id}: patch succeeded but refetch failed with status ${post_status}"
      append_result "$(jq -cn \
        --arg tenantId "$tenant_id" \
        --arg policyId "$policy_id" \
        --arg displayName "$display_name" \
        --arg statusCode "$post_status" \
        --arg body "$post_body" \
        --argjson deviations "$deviations" \
        '{
          tenantId: $tenantId,
          status: "PATCHED_BUT_REFETCH_FAILED",
          policyExists: true,
          policyId: $policyId,
          policyDisplayName: $displayName,
          configurationCompliant: false,
          remediationAttempted: true,
          remediationApplied: true,
          deviationsBeforeChange: $deviations,
          refetchHttpStatus: $statusCode,
          refetchBody: $body
        }')"
      continue
    fi

    post_norm="$(normalize_policy_json <<< "$post_body")"
    post_compliant="false"
    if [[ "$post_norm" == "$REFERENCE_NORMALIZED" ]]; then
      post_compliant="true"
    fi
    debug "Tenant ${tenant_id}: post-remediation compliance result=${post_compliant}"

    post_diff="$(compute_diff_entries "$actual_normalized" "$post_norm")"

    append_result "$(jq -cn \
      --arg tenantId "$tenant_id" \
      --arg policyId "$policy_id" \
      --arg displayName "$display_name" \
      --argjson compliant "$post_compliant" \
      --argjson beforeDeviations "$deviations" \
      --argjson changedFields "$post_diff" \
      --argjson afterDeviations "$(compute_deviation_object "$post_norm" "$REFERENCE_NORMALIZED")" \
      '{
        tenantId: $tenantId,
        status: "REMEDIATED",
        policyExists: true,
        policyId: $policyId,
        policyDisplayName: $displayName,
        configurationCompliant: $compliant,
        remediationAttempted: true,
        remediationApplied: true,
        fieldsChanged: $changedFields,
        deviationsBeforeChange: $beforeDeviations,
        deviationsAfterChange: $afterDeviations
      }')"
  done < "$TARGET_FILE"

  local results_json
  results_json="$(cat "$RESULTS_FILE")"

  if [[ "$TABLE_MODE" -eq 1 ]]; then
    debug "Rendering output in table mode"
    if [[ "$SETTING_CHECK_MODE" -eq 1 ]]; then
      print_table "$(
        jq -r '
          (["tenantId","caFound","setting","matchesReference","error"] | @tsv),
          (.[] | [.tenantId, (.caFound | tostring), .setting, (.matchesReference | tostring), (.error // "")] | @tsv)
        ' <<< "$results_json"
      )"
    else
      print_table "$(
        jq -r '
          (["tenantId","status","policyExists","configurationCompliant","remediationApplied","policyDisplayName"] | @tsv),
          (.[] | [
            .tenantId,
            .status,
            ((.policyExists // false) | tostring),
            ((.configurationCompliant // false) | tostring),
            ((.remediationApplied // false) | tostring),
            (.policyDisplayName // "")
          ] | @tsv)
        ' <<< "$results_json"
      )"
    fi
  else
    debug "Rendering output in JSON mode"
    if [[ "$SETTING_CHECK_MODE" -eq 1 ]]; then
      jq -cn \
        --arg script "$SCRIPT_NAME" \
        --arg mode "$MODE" \
        --arg targetFile "$TARGET_FILE" \
        --arg referencePolicy "$REFERENCE_POLICY" \
        --arg match1 "$MATCH_STRING_1" \
        --arg match2 "$MATCH_STRING_2" \
        --arg settingCheck "$SETTING_CHECKS_RAW" \
        --arg generatedAt "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --argjson results "$results_json" \
        '{
          script: $script,
          mode: $mode,
          generatedAtUtc: $generatedAt,
          inputs: {
            targetFile: $targetFile,
            referencePolicy: $referencePolicy,
            matchString1: $match1,
            matchString2: $match2,
            settingCheck: $settingCheck
          },
          columns: ["tenantId", "caFound", "setting", "matchesReference", "error"],
          results: $results
        }'
    else
      jq -cn \
        --arg script "$SCRIPT_NAME" \
        --arg mode "$MODE" \
        --arg targetFile "$TARGET_FILE" \
        --arg referencePolicy "$REFERENCE_POLICY" \
        --arg match1 "$MATCH_STRING_1" \
        --arg match2 "$MATCH_STRING_2" \
        --arg generatedAt "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --argjson results "$results_json" \
        '{
          script: $script,
          mode: $mode,
          generatedAtUtc: $generatedAt,
          inputs: {
            targetFile: $targetFile,
            referencePolicy: $referencePolicy,
            matchString1: $match1,
            matchString2: $match2
          },
          results: $results
        }'
    fi
  fi
}

main "$@"
