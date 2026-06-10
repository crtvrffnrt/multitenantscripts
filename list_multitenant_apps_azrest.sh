#!/usr/bin/env bash
set -euo pipefail

TENANT_FILE=""
INCLUDE_ALL=false
NO_HEADER=false
VERBOSE=false
OUTPUT="table"
INCLUDE_ENTERPRISE=true

usage() {
  cat <<'USAGE'
Usage:
  ./list_multitenant_apps_azrest.sh [options]

Purpose:
  Enumerate Entra ID app registrations configured for multi-tenant sign-in and
  having redirect URIs by default. Also checks enterprise application instances
  by default, so apps whose home tenant differs from the queried tenant are visible.

Options:
  -t, --tenants FILE         Tenant IDs to process, one per line. Blank lines and
                             lines beginning with # are ignored.
  --all                      Include records with no redirect URI.
  --no-enterprise-apps       Only query local app registrations from /applications.
  -o, --output FORMAT        table, tsv, simple, or json. Default: table.
  --json                     Shortcut for --output json.
  --simple                   Shortcut for --output simple.
  --no-header                Suppress header for table, tsv, and simple output.
  -v, --verbose              Print progress and query details to stderr.
  -h, --help                 Show this help text.

Output columns:
  Kind, Risk, AppName, ObjectId, TenantId, HomeTenantId, HomeTenantRelation,
  AppId, SignInAudience, RedirectCount, SecuritySignals

Notes:
  - applicationRegistration records are owned by the queried tenant.
  - enterpriseApplication records come from service principals. Their home tenant
    is appOwnerOrganizationId when Microsoft Graph exposes it.
USAGE
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

log() {
  if [[ "$VERBOSE" == true ]]; then
    echo "[*] $*" >&2
  fi
  return 0
}

warn() {
  echo "[!] $*" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

trim_line() {
  sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

json_escape() {
  jq -Rr @uri <<< "$1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--tenants|-tenants)
      [[ $# -ge 2 ]] || fail "Missing file after $1"
      TENANT_FILE="$2"
      shift 2
      ;;
    --all)
      INCLUDE_ALL=true
      shift
      ;;
    --no-enterprise-apps)
      INCLUDE_ENTERPRISE=false
      shift
      ;;
    -o|--output)
      [[ $# -ge 2 ]] || fail "Missing format after $1"
      OUTPUT="$2"
      shift 2
      ;;
    --json)
      OUTPUT="json"
      shift
      ;;
    --simple)
      OUTPUT="simple"
      shift
      ;;
    --no-header)
      NO_HEADER=true
      shift
      ;;
    -v|--verbose)
      VERBOSE=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "Unknown argument: $1"
      ;;
  esac
done

case "$OUTPUT" in
  table|tsv|simple|json) ;;
  *) fail "Unsupported output format: $OUTPUT" ;;
esac

require_cmd az
require_cmd jq

az account show >/dev/null 2>&1 || fail "Azure CLI is not logged in. Run: az login"

TENANTS=()
if [[ -n "$TENANT_FILE" ]]; then
  [[ -f "$TENANT_FILE" ]] || fail "Tenant file not found: $TENANT_FILE"
  while IFS= read -r raw_line || [[ -n "${raw_line:-}" ]]; do
    tenant_id="$(printf '%s' "$raw_line" | trim_line)"
    [[ -z "$tenant_id" ]] && continue
    TENANTS+=("$tenant_id")
  done < "$TENANT_FILE"
else
  active_tenant="$(az account show --query tenantId -o tsv 2>/dev/null)"
  [[ -n "$active_tenant" ]] || fail "Could not determine active tenant ID"
  TENANTS+=("$active_tenant")
fi

[[ ${#TENANTS[@]} -gt 0 ]] || fail "No tenant IDs to process"

GRAPH_RESOURCE="https://graph.microsoft.com/"
GRAPH_APPID="00000003-0000-0000-c000-000000000000"
GRAPH_SP_FILTER="appId eq '${GRAPH_APPID}'"
GRAPH_PERM_URL="https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=$(json_escape "$GRAPH_SP_FILTER")&\$select=appRoles,oauth2PermissionScopes&\$top=1"
APP_FILTER="signInAudience eq 'AzureADMultipleOrgs' or signInAudience eq 'AzureADandPersonalMicrosoftAccount'"
APP_SELECT="id,displayName,appId,signInAudience,publisherDomain,createdDateTime,web,spa,publicClient,requiredResourceAccess,passwordCredentials,keyCredentials,appRoles,isFallbackPublicClient,servicePrincipalLockConfiguration,verifiedPublisher"
APP_QUERY_URL="https://graph.microsoft.com/v1.0/applications?\$filter=$(json_escape "$APP_FILTER")&\$select=${APP_SELECT}&\$top=999"
SP_FILTER="servicePrincipalType eq 'Application'"
SP_SELECT="id,displayName,appId,appOwnerOrganizationId,servicePrincipalType,publisherName,createdDateTime,replyUrls,tags,appRoles,oauth2PermissionScopes,preferredSingleSignOnMode,verifiedPublisher"
SP_QUERY_URL="https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=$(json_escape "$SP_FILTER")&\$select=${SP_SELECT}&\$top=999"

graph_get() {
  local tenant_id="$1"
  local url="$2"
  local token

  log "GET ${url}"
  token="$(az account get-access-token \
    --tenant "$tenant_id" \
    --resource "$GRAPH_RESOURCE" \
    --query accessToken \
    -o tsv 2>/dev/null)" || return 1

  [[ -n "$token" ]] || return 1

  az rest \
    --method GET \
    --url "$url" \
    --skip-authorization-header \
    --headers "Authorization=Bearer ${token}" "ConsistencyLevel=eventual" \
    -o json 2>/dev/null
}

load_graph_permission_map() {
  local tenant_id="$1"
  local sp_json

  if ! sp_json="$(graph_get "$tenant_id" "$GRAPH_PERM_URL")"; then
    echo '{}' && return 0
  fi

  jq -c '
    (.value[0] // {}) as $sp
    | (
        [($sp.appRoles // [])[] | {key: .id, value: ("Role:" + (.value // .displayName // .id))}]
        +
        [($sp.oauth2PermissionScopes // [])[] | {key: .id, value: ("Scope:" + (.value // .adminConsentDisplayName // .id))}]
      )
    | map(select(.key != null and .value != null))
    | from_entries
  ' <<< "$sp_json" 2>/dev/null || echo '{}'
}

emit_application_records() {
  local tenant_id="$1"
  local graph_map="$2"

  jq -c \
    --arg tenantId "$tenant_id" \
    --argjson includeAll "$INCLUDE_ALL" \
    --argjson graphMap "$graph_map" '
      def redirect_uris:
        ([.web.redirectUris[]?, .spa.redirectUris[]?, .publicClient.redirectUris[]?] | unique);

      def soonest_expiry($arr):
        (($arr // []) | map(.endDateTime? // empty) | sort | .[0]) // "none";

      def permission_count($permType):
        [(.requiredResourceAccess // [])[]?.resourceAccess[]? | select(.type == $permType)] | length;

      def graph_permission_names:
        [
          (.requiredResourceAccess // [])[]?
          | select(.resourceAppId == "00000003-0000-0000-c000-000000000000")
          | .resourceAccess[]?
          | (.id as $id | ($graphMap[$id] // ("id:" + $id)))
        ] | unique;

      def risk_level($plainHttp; $interesting; $roles; $implicit; $fallback):
        if ($plainHttp > 0 or ($roles > 0 and $interesting > 0)) then "high"
        elif ($implicit or $fallback or $interesting > 0) then "medium"
        else "review" end;

      .value[]?
      | select(."@odata.type"? == null or ."@odata.type" == "#microsoft.graph.application")
      | . as $app
      | ($app | redirect_uris) as $redirects
      | select($includeAll or (($redirects | length) > 0))
      | ($app | graph_permission_names) as $graphPerms
      | (
          $graphPerms
          | map(select(test("(Directory|RoleManagement|Application|AppRoleAssignment|PrivilegedAccess|Policy|AuditLog|User\\.ReadWrite|Group\\.ReadWrite|Mail\\.|Files\\.|Sites\\.|offline_access)"; "i")))
        ) as $interestingPerms
      | (
          $redirects
          | map(select(test("^https://"; "i") and (test("^https://(localhost|127\\.0\\.0\\.1|\\[::1\\])"; "i") | not)))
          | length
        ) as $publicHttpsRedirects
      | (
          $redirects
          | map(select(test("^http://"; "i") and (test("^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])"; "i") | not)))
          | length
        ) as $plainHttpRedirects
      | (
          $redirects
          | map(select(test("^(https?://)?(localhost|127\\.0\\.0\\.1|\\[::1\\])"; "i")))
          | length
        ) as $localhostRedirects
      | (($app.web.implicitGrantSettings.enableAccessTokenIssuance // false) or ($app.web.implicitGrantSettings.enableIdTokenIssuance // false)) as $implicitGrant
      | ($app | permission_count("Role")) as $roleCount
      | {
          kind: "applicationRegistration",
          risk: risk_level($plainHttpRedirects; ($interestingPerms | length); $roleCount; $implicitGrant; ($app.isFallbackPublicClient // false)),
          appName: ($app.displayName // ""),
          objectId: ($app.id // ""),
          tenantId: $tenantId,
          homeTenantId: $tenantId,
          homeTenantRelation: "currentTenant",
          appId: ($app.appId // ""),
          signInAudience: ($app.signInAudience // ""),
          redirectUris: $redirects,
          redirectCount: ($redirects | length),
          securitySignals: {
            redirects: ($redirects | length),
            publicHttps: $publicHttpsRedirects,
            plainHttp: $plainHttpRedirects,
            localhost: $localhostRedirects,
            secrets: (($app.passwordCredentials // []) | length),
            soonestSecretExpiry: soonest_expiry($app.passwordCredentials),
            certs: (($app.keyCredentials // []) | length),
            soonestCertExpiry: soonest_expiry($app.keyCredentials),
            permissionRoles: $roleCount,
            permissionScopes: ($app | permission_count("Scope")),
            interestingGraphPermissions: ($interestingPerms[0:12]),
            implicitGrant: $implicitGrant,
            fallbackPublicClient: ($app.isFallbackPublicClient // false),
            appRoles: (($app.appRoles // []) | length),
            publisher: ($app.publisherDomain // "none"),
            verifiedPublisher: ($app.verifiedPublisher.displayName // "none"),
            servicePrincipalLockEnabled: ($app.servicePrincipalLockConfiguration.isEnabled // null),
            createdDateTime: ($app.createdDateTime // "unknown")
          }
        }
    '
}

emit_service_principal_records() {
  local tenant_id="$1"

  jq -c \
    --arg tenantId "$tenant_id" \
    --argjson includeAll "$INCLUDE_ALL" '
      def redirect_uris:
        ([.replyUrls[]?] | unique);

      def relation($home):
        if ($home == null or $home == "") then "unknown"
        elif $home == $tenantId then "currentTenant"
        else "differentTenant" end;

      def risk_level($homeRel; $plainHttp; $publicHttps; $sso):
        if ($plainHttp > 0) then "high"
        elif ($homeRel == "differentTenant" and $publicHttps > 0) then "medium"
        elif ($sso != null and $sso != "") then "review"
        else "review" end;

      .value[]?
      | select(.servicePrincipalType == "Application")
      | . as $sp
      | ($sp | redirect_uris) as $redirects
      | select($includeAll or (($redirects | length) > 0))
      | ($sp.appOwnerOrganizationId // "") as $homeTenant
      | (relation($homeTenant)) as $homeRel
      | (
          $redirects
          | map(select(test("^https://"; "i") and (test("^https://(localhost|127\\.0\\.0\\.1|\\[::1\\])"; "i") | not)))
          | length
        ) as $publicHttpsRedirects
      | (
          $redirects
          | map(select(test("^http://"; "i") and (test("^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])"; "i") | not)))
          | length
        ) as $plainHttpRedirects
      | (
          $redirects
          | map(select(test("^(https?://)?(localhost|127\\.0\\.0\\.1|\\[::1\\])"; "i")))
          | length
        ) as $localhostRedirects
      | {
          kind: "enterpriseApplication",
          risk: risk_level($homeRel; $plainHttpRedirects; $publicHttpsRedirects; ($sp.preferredSingleSignOnMode // "")),
          appName: ($sp.displayName // ""),
          objectId: ($sp.id // ""),
          tenantId: $tenantId,
          homeTenantId: (if $homeTenant == "" then "unknown" else $homeTenant end),
          homeTenantRelation: $homeRel,
          appId: ($sp.appId // ""),
          signInAudience: "unknownFromServicePrincipal",
          redirectUris: $redirects,
          redirectCount: ($redirects | length),
          securitySignals: {
            redirects: ($redirects | length),
            publicHttps: $publicHttpsRedirects,
            plainHttp: $plainHttpRedirects,
            localhost: $localhostRedirects,
            appRolesExposed: (($sp.appRoles // []) | length),
            delegatedScopesExposed: (($sp.oauth2PermissionScopes // []) | length),
            preferredSingleSignOnMode: ($sp.preferredSingleSignOnMode // "none"),
            publisher: ($sp.publisherName // "none"),
            verifiedPublisher: ($sp.verifiedPublisher.displayName // "none"),
            tags: ($sp.tags // []),
            createdDateTime: ($sp.createdDateTime // "unknown")
          }
        }
    '
}

record_to_tsv() {
  jq -r '
    def signal_text:
      .securitySignals as $s
      | [
          "redirects=\($s.redirects)",
          "publicHttps=\($s.publicHttps)",
          "plainHttp=\($s.plainHttp)",
          "localhost=\($s.localhost)",
          "publisher=\($s.publisher)",
          "verifiedPublisher=\($s.verifiedPublisher)"
        ]
      + (if ($s | has("interestingGraphPermissions")) and (($s.interestingGraphPermissions | length) > 0) then ["graphPerms=\($s.interestingGraphPermissions | join(","))"] else [] end)
      + (if ($s | has("permissionRoles")) then ["permRoles=\($s.permissionRoles)", "permScopes=\($s.permissionScopes)"] else [] end)
      + (if ($s | has("implicitGrant")) then ["implicitGrant=\($s.implicitGrant)", "fallbackPublicClient=\($s.fallbackPublicClient)"] else [] end)
      | join("|");

    [
      .kind,
      .risk,
      .appName,
      .objectId,
      .tenantId,
      .homeTenantId,
      .homeTenantRelation,
      .appId,
      .signInAudience,
      (.redirectCount | tostring),
      signal_text
    ] | @tsv
  '
}

record_to_simple() {
  jq -r '
    [
      .risk,
      .kind,
      .homeTenantRelation,
      .appName,
      .appId,
      (.redirectCount | tostring),
      ((.redirectUris[0] // "none") | tostring)
    ] | @tsv
  '
}

record_to_table() {
  jq -r '
    def key_signals:
      .securitySignals as $s
      | [
          "https=\($s.publicHttps)",
          "http=\($s.plainHttp)",
          "local=\($s.localhost)"
        ]
      + (if ($s | has("interestingGraphPermissions")) and (($s.interestingGraphPermissions | length) > 0) then ["graph=\($s.interestingGraphPermissions[0:4] | join(","))"] else [] end)
      + (if ($s | has("implicitGrant")) and $s.implicitGrant then ["implicit=true"] else [] end)
      + (if ($s | has("fallbackPublicClient")) and $s.fallbackPublicClient then ["fallbackPublic=true"] else [] end)
      + (if ($s | has("verifiedPublisher")) and $s.verifiedPublisher != "none" then ["verified=\($s.verifiedPublisher)"] else [] end)
      | join("|");

    [
      .risk,
      .kind,
      .homeTenantRelation,
      .appName,
      .appId,
      (.redirectCount | tostring),
      ((.redirectUris[0] // "none") | tostring),
      key_signals
    ] | @tsv
  '
}

sort_records() {
  jq -s -c '
    def risk_rank:
      if .risk == "high" then 0
      elif .risk == "medium" then 1
      else 2 end;
    sort_by(risk_rank, .kind, .homeTenantRelation, .appName) | .[]
  '
}

print_header() {
  [[ "$NO_HEADER" == true ]] && return 0

  case "$OUTPUT" in
    table)
      printf 'Risk\tKind\tHomeTenantRelation\tAppName\tAppId\tRedirects\tFirstRedirect\tKeySignals\n'
      ;;
    simple)
      printf 'Risk\tKind\tHomeTenantRelation\tAppName\tAppId\tRedirectCount\tFirstRedirect\n'
      ;;
    tsv)
      printf 'Kind\tRisk\tAppName\tObjectId\tTenantId\tHomeTenantId\tHomeTenantRelation\tAppId\tSignInAudience\tRedirectCount\tSecuritySignals\n'
      ;;
  esac
}

format_tabular() {
  if [[ "$OUTPUT" == "table" ]] && command -v column >/dev/null 2>&1; then
    column -t -s "$(printf '\t')"
  else
    cat
  fi
}

collect_records() {
  local tenant_id graph_map next_url page_json

  for tenant_id in "${TENANTS[@]}"; do
    log "Processing tenant: ${tenant_id}"

    if ! az account get-access-token --tenant "$tenant_id" --resource "$GRAPH_RESOURCE" --query accessToken -o tsv >/dev/null 2>&1; then
      warn "Cannot acquire Microsoft Graph token for tenant ${tenant_id}; skipping"
      continue
    fi

    graph_map="$(load_graph_permission_map "$tenant_id")"
    [[ -n "$graph_map" ]] || graph_map='{}'

    next_url="$APP_QUERY_URL"
    while [[ -n "$next_url" && "$next_url" != "null" ]]; do
      if ! page_json="$(graph_get "$tenant_id" "$next_url")"; then
        warn "Failed to query applications in tenant ${tenant_id}; skipping remaining application pages"
        break
      fi

      emit_application_records "$tenant_id" "$graph_map" <<< "$page_json"
      next_url="$(jq -r '."@odata.nextLink" // empty' <<< "$page_json")"
    done

    if [[ "$INCLUDE_ENTERPRISE" == true ]]; then
      next_url="$SP_QUERY_URL"
      while [[ -n "$next_url" && "$next_url" != "null" ]]; do
        if ! page_json="$(graph_get "$tenant_id" "$next_url")"; then
          warn "Failed to query service principals in tenant ${tenant_id}; skipping remaining enterprise application pages"
          break
        fi

        emit_service_principal_records "$tenant_id" <<< "$page_json"
        next_url="$(jq -r '."@odata.nextLink" // empty' <<< "$page_json")"
      done
    fi
  done
}

if [[ "$OUTPUT" == "json" ]]; then
  collect_records | jq -s 'sort_by(.tenantId, .kind, .risk, .appName)'
elif [[ "$OUTPUT" == "simple" ]]; then
  { print_header; collect_records | sort_records | record_to_simple; } | format_tabular
elif [[ "$OUTPUT" == "table" ]]; then
  { print_header; collect_records | sort_records | record_to_table; } | format_tabular
else
  { print_header; collect_records | sort_records | record_to_tsv; } | format_tabular
fi
