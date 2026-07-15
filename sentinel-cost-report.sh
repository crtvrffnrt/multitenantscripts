#!/usr/bin/env bash
set -euo pipefail

# Microsoft Sentinel Cost Report (EUR) v1.0.0 -- read-only Azure CLI reporting.
SCRIPT_VERSION="1.0.0"
TMPDIR=""

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
cleanup() { [[ -n "${TMPDIR}" && -d "${TMPDIR}" ]] && rm -rf -- "${TMPDIR}"; }
trap cleanup EXIT
need() { command -v "$1" >/dev/null 2>&1 || die "Required dependency '$1' is not installed or not on PATH."; }
html_escape() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' -e "s/'/\&#39;/g"; }
valid_json() { jq -e . "$1" >/dev/null 2>&1; }
valid_positive_integer() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }
valid_positive_decimal() { [[ "$1" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] && awk -v n="$1" 'BEGIN {exit !(n > 0)}'; }
format_eur() { LC_NUMERIC=C awk -v n="${1:-0}" 'BEGIN {printf "%.2f EUR", n+0}'; }
format_bytes() { LC_NUMERIC=C awk -v n="${1:-0}" 'BEGIN { split("bytes KB MB GB TB", u, " "); i=1; while (n >= 1024 && i < 5) {n/=1024;i++} if(i==1) printf "%.0f %s",n,u[i]; else printf "%.2f %s",n,u[i] }'; }
format_gb() { LC_NUMERIC=C awk -v n="${1:-0}" 'BEGIN {printf "%.2f GB",n+0}'; }
query_az() {
  local name="$1" kql="$2" out
  out="${TMPDIR}/${name}.json"
  if ! az monitor log-analytics query --workspace "$WORKSPACE_CUSTOMER_ID" --analytics-query "$kql" --timespan "${REPORT_START}/${REPORT_END}" --output json >"$out" 2>"${out}.err"; then
    printf 'Log Analytics query %s failed: %s\n' "$name" "$(tr '\n' ' ' < "${out}.err")" >&2
    return 1
  fi
  valid_json "$out" || { printf 'Log Analytics query %s returned invalid JSON.\n' "$name" >&2; return 1; }
  printf '%s\n' "$out"
}
select_number() {
  local prompt="$1" count="$2" default="$3" value
  while true; do
    read -r -p "$prompt" value
    value="${value:-$default}"
    [[ "$value" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= count )) && { printf '%s\n' "$value"; return; }
    printf 'Please enter a number from 1 to %s.\n' "$count" >&2
  done
}
prompt_days() { local x; while true; do read -r -p 'How many complete days should the report cover? [30]: ' x; x="${x:-30}"; valid_positive_integer "$x" && { printf '%s\n' "$x"; return; }; printf 'Enter a positive whole number (recommended: 1 to 365).\n' >&2; done; }
prompt_price() { local label="$1" default="$2" x; while true; do read -r -p "$label [$default]: " x; x="${x:-$default}"; valid_positive_decimal "$x" && { printf '%s\n' "$x"; return; }; printf 'Enter a positive decimal value.\n' >&2; done; }

for tool in az jq curl; do need "$tool"; done
az account show -o json >/dev/null 2>&1 || die "Azure CLI is not authenticated. Run: az login"
TMPDIR="$(mktemp -d)" || die 'Unable to create a secure temporary directory.'

SUBS="${TMPDIR}/subscriptions.json"
az account list --all --output json >"$SUBS" || die 'Unable to list Azure subscriptions.'
jq -e '[.[] | select(.state == "Enabled")] | length > 0' "$SUBS" >/dev/null || die 'No enabled Azure subscriptions are visible in this Azure CLI session.'
CURRENT_SUB="$(az account show --query id -o tsv)"
mapfile -t SUB_ROWS < <(jq -r '.[] | select(.state == "Enabled") | [.name,.id,.tenantId,(.isDefault // false)] | @tsv' "$SUBS")
printf '\nAvailable Azure subscriptions:\n\n'
for i in "${!SUB_ROWS[@]}"; do IFS=$'\t' read -r n id tenant def <<<"${SUB_ROWS[$i]}"; printf '[%d] %s\n    Subscription ID: %s\n    Tenant ID: %s\n    Current: %s\n' "$((i+1))" "$n" "$id" "$tenant" "$([[ "$id" == "$CURRENT_SUB" ]] && echo yes || echo no)"; done
if ((${#SUB_ROWS[@]} == 1)); then SUB_INDEX=1; printf 'Only one enabled subscription; selecting it automatically.\n'; else SUB_INDEX="$(select_number 'Select subscription [current]: ' "${#SUB_ROWS[@]}" "$(for i in "${!SUB_ROWS[@]}"; do [[ "${SUB_ROWS[$i]}" == *$'\t'"$CURRENT_SUB"$'\t'* ]] && echo $((i+1)); done | head -1)")"; fi
IFS=$'\t' read -r SUB_NAME SUB_ID TENANT_ID _ <<<"${SUB_ROWS[$((SUB_INDEX-1))]}"
az account set --subscription "$SUB_ID" || die 'Unable to select subscription.'
[[ "$(az account show --query id -o tsv)" == "$SUB_ID" ]] || die 'Azure CLI did not select the requested subscription.'

# Sentinel discovery: solutions named SecurityInsights provide a durable link to the workspace.
SOLUTIONS="${TMPDIR}/solutions.json"
az resource list --resource-type 'Microsoft.OperationsManagement/solutions' --output json >"$SOLUTIONS" || die 'Unable to discover Sentinel solutions.'
WORKSPACES="${TMPDIR}/workspaces.tsv"; : >"$WORKSPACES"
while IFS=$'\t' read -r solution_id solution_name wsid; do
  [[ "${solution_name,,}" == *securityinsights* ]] || continue
  if [[ -z "$wsid" || "$wsid" == "null" ]]; then
    # Standard solution names are SecurityInsights(<workspace>); infer only inside its resource group.
    wsname="${solution_name#*\(}"; wsname="${wsname%\)}"; rg="$(awk -F/ '{for(i=1;i<=NF;i++) if(tolower($i)=="resourcegroups") print $(i+1)}' <<<"$solution_id")"
    wsid="$(az monitor log-analytics workspace show -g "$rg" -n "$wsname" --query id -o tsv 2>/dev/null || true)"
  fi
  [[ -n "$wsid" ]] || continue
  az monitor log-analytics workspace show --ids "$wsid" --output json 2>/dev/null | jq -r --arg evidence "Solution: ${solution_name}" '[.name,.resourceGroup,.id,.customerId,.location,$evidence] | @tsv' >>"$WORKSPACES" || true
done < <(jq -r '.[] | [.id,.name,(.properties.workspaceResourceId // "")] | @tsv' "$SOLUTIONS")
sort -u "$WORKSPACES" -o "$WORKSPACES"
mapfile -t WS_ROWS < "$WORKSPACES"
((${#WS_ROWS[@]})) || die 'No Microsoft Sentinel-enabled Log Analytics workspace was found in the selected subscription.'
printf '\nDiscovered Microsoft Sentinel workspaces:\n\n'
for i in "${!WS_ROWS[@]}"; do IFS=$'\t' read -r wn wrg wid wcid wloc wevidence <<<"${WS_ROWS[$i]}"; printf '[%d] %s\n    Resource group: %s\n    Location: %s\n    Subscription: %s\n    Evidence: %s\n' "$((i+1))" "$wn" "$wrg" "$wloc" "$SUB_NAME" "$wevidence"; done
if ((${#WS_ROWS[@]} == 1)); then WS_INDEX=1; printf 'Only one Sentinel workspace; selecting it automatically.\n'; else WS_INDEX="$(select_number 'Select workspace [1]: ' "${#WS_ROWS[@]}" 1)"; fi
IFS=$'\t' read -r WORKSPACE_NAME WORKSPACE_RG WORKSPACE_ID WORKSPACE_CUSTOMER_ID WORKSPACE_LOCATION SENTINEL_EVIDENCE <<<"${WS_ROWS[$((WS_INDEX-1))]}"

DAYS="$(prompt_days)"; INGESTION_PRICE="$(prompt_price 'Sentinel ingestion price in EUR per GB' 5.17)"; RETENTION_PRICE="$(prompt_price 'Retention price in EUR per GB/month' 0.126)"
REPORT_START="$(date -u -d "${DAYS} days ago" +%Y-%m-%dT00:00:00Z)"; REPORT_END="$(date -u +%Y-%m-%dT00:00:00Z)"; GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SAFE_WS="$(printf '%s' "$WORKSPACE_NAME" | sed 's/[^[:alnum:]. _-]/_/g; s/ /_/g; s/^_//; s/_$//')"; DEFAULT_OUTPUT="./sentinel-cost-${SAFE_WS}-$(date -u +%Y%m%dT%H%M%SZ).html"
read -r -p "Output HTML file [$DEFAULT_OUTPUT]: " OUTPUT; OUTPUT="${OUTPUT:-$DEFAULT_OUTPUT}"; mkdir -p -- "$(dirname -- "$OUTPUT")" 2>/dev/null || die 'Output directory cannot be created.'
[[ -w "$(dirname -- "$OUTPUT")" ]] || die 'Output directory is not writable.'
if [[ -e "$OUTPUT" ]]; then read -r -p "File exists. Overwrite? [y/N]: " answer; [[ "$answer" =~ ^[Yy]$ ]] || die 'Refusing to overwrite existing file.'; fi

SUMMARY_KQL="let ReportStart=datetime(${REPORT_START}); let ReportEnd=datetime(${REPORT_END}); Usage | where TimeGenerated >= ReportStart and TimeGenerated < ReportEnd | where IsBillable == true | summarize TotalBillableIngestionGB=coalesce(sum(Quantity)/1024.0,0.0) | extend ReportStart=format_datetime(ReportStart,'yyyy-MM-dd'), ReportEnd=format_datetime(ReportEnd,'yyyy-MM-dd'), AverageBillableGBPerDay=TotalBillableIngestionGB/${DAYS}.0, EstimatedIngestionCostEUR=TotalBillableIngestionGB*${INGESTION_PRICE}, DataOlderThan90DaysGB=real(null), EstimatedRetentionCostEUR=real(null) | project ReportStart,ReportEnd,TotalBillableIngestionGB,AverageBillableGBPerDay,EstimatedIngestionCostEUR,DataOlderThan90DaysGB,EstimatedRetentionCostEUR"
DETAIL_KQL="let ReportStart=datetime(${REPORT_START}); let ReportEnd=datetime(${REPORT_END}); let Categories=datatable(Type:string,LogCategory:string)[ 'AuditLogs','Microsoft Entra ID','SigninLogs','Microsoft Entra ID','AADNonInteractiveUserSignInLogs','Microsoft Entra ID','AADRiskyUsers','Microsoft Entra ID','AADRiskyServicePrincipalSignInLogs','Microsoft Entra ID','AADServicePrincipalSignInLogs','Microsoft Entra ID','AADManagedIdentitySignInLogs','Microsoft Entra ID','AADProvisioningLogs','Microsoft Entra ID','DeviceLogonEvents','Microsoft Defender for Endpoint','DeviceEvents','Microsoft Defender for Endpoint','DeviceNetworkInfo','Microsoft Defender for Endpoint','DeviceImageLoadEvents','Microsoft Defender for Endpoint','DeviceFileEvents','Microsoft Defender for Endpoint','DeviceInfo','Microsoft Defender for Endpoint','DeviceProcessEvents','Microsoft Defender for Endpoint','DeviceNetworkEvents','Microsoft Defender for Endpoint','DeviceRegistryEvents','Microsoft Defender for Endpoint','EmailAttachmentInfo','Microsoft Defender for Office 365','EmailEvents','Microsoft Defender for Office 365','EmailPostDeliveryEvents','Microsoft Defender for Office 365','EmailUrlInfo','Microsoft Defender for Office 365','UrlClickEvents','Microsoft Defender for Office 365','IdentityLogonEvents','Microsoft Defender for Identity','IdentityQueryEvents','Microsoft Defender for Identity','IdentityDirectoryEvents','Microsoft Defender for Identity','CloudAppEvents','Microsoft Defender for Cloud Apps','BehaviorAnalytics','User Entity Behavior Analytics','UserPeerAnalytics','User Entity Behavior Analytics','UserAccessAnalytics','User Entity Behavior Analytics','IdentityInfo','User Entity Behavior Analytics','AZFWApplicationRule','Firewall','AZFWDnsQuery','Firewall','AZFWNatRule','Firewall','AZFWNetworkRule','Firewall','AZFWThreatIntel','Firewall','WindowsFirewall','Firewall','Syslog','Syslog/CEF','CommonSecurityLog','Syslog/CEF','AWSCloudTrail','AWS Logs','AWSVPCFlow','AWS Logs','AWSGuardDuty','AWS Logs','AzureDiagnostics','Azure Resources','AzureActivity','Azure Resources','StorageBlobLogs','Azure Storage','StorageFileLogs','Azure Storage','StorageTableLogs','Azure Storage','StorageQueueLogs','Azure Storage','ThreatIntelligenceIndicator','Sentinel','SentinelHealth','Sentinel','Watchlist','Sentinel','HuntingBookmark','Sentinel','SentinelAudit','Sentinel','DnsEvents','DNS Logs','DnsInventory','DNS Logs','LAQueryLogs','Management','Operation','Management','Perf','Performance','SecurityNestedRecommendation','Microsoft Defender for Cloud','SecurityRecommendation','Microsoft Defender for Cloud','SecurityRegulatoryCompliance','Microsoft Defender for Cloud','SecureScoreControls','Microsoft Defender for Cloud','SecurityBaseline','Microsoft Defender for Cloud','SecureScores','Microsoft Defender for Cloud']; Usage | where TimeGenerated >= ReportStart and TimeGenerated < ReportEnd | where IsBillable == true | summarize BillableBytes=sum(Quantity)*1024.0*1024.0 by TableName=DataType | join kind=leftouter Categories on \$left.TableName == \$right.Type | extend LogCategory=case(TableName endswith '_CL','Custom Log',isnotempty(LogCategory),LogCategory,'Other'), BillableGB=BillableBytes/1024.0/1024.0/1024.0, EstimatedCostEUR=(BillableBytes/1024.0/1024.0/1024.0)*${INGESTION_PRICE} | project LogCategory,TableName,BillableBytes,BillableGB,EstimatedCostEUR | order by LogCategory asc, EstimatedCostEUR desc, TableName asc"
DAILY_KQL="let ReportStart=datetime(${REPORT_START}); let ReportEnd=datetime(${REPORT_END}); range Date from ReportStart to datetime_add('day',-1,ReportEnd) step 1d | join kind=leftouter (Usage | where TimeGenerated >= ReportStart and TimeGenerated < ReportEnd | where IsBillable == true | summarize BillableGB=sum(Quantity)/1024.0 by Date=startofday(TimeGenerated)) on Date | extend BillableGB=coalesce(BillableGB,0.0), EstimatedCostEUR=coalesce(BillableGB,0.0)*${INGESTION_PRICE} | project Date=format_datetime(Date,'yyyy-MM-dd'),BillableGB,EstimatedCostEUR | order by Date asc"
SUMMARY_JSON="$(query_az summary "$SUMMARY_KQL")" || die 'Required summary query failed. Check Log Analytics query permission and Usage table access.'
DETAIL_JSON="$(query_az detail "$DETAIL_KQL")" || die 'Required detailed ingestion query failed. Check Log Analytics query permission and Usage table access.'
DAILY_JSON="$(query_az daily "$DAILY_KQL")" || die 'Required daily trend query failed. Check Log Analytics query permission and Usage table access.'
META_JSON="${TMPDIR}/metadata.json"; az monitor log-analytics workspace show --ids "$WORKSPACE_ID" --output json >"$META_JSON" 2>/dev/null || printf '{}' >"$META_JSON"

SUMMARY_ROW="$(jq -c 'if type=="array" then .[0] else .tables[0].rows[0] end // {}' "$SUMMARY_JSON")"; TOTAL_GB="$(jq -r '.TotalBillableIngestionGB // 0' <<<"$SUMMARY_ROW")"; TOTAL_COST="$(jq -r '.EstimatedIngestionCostEUR // 0' <<<"$SUMMARY_ROW")"; AVG_GB="$(jq -r '.AverageBillableGBPerDay // 0' <<<"$SUMMARY_ROW")"
DETAIL_TOTAL="$(jq '[.[] | (.BillableGB // 0 | tonumber)] | add // 0' "$DETAIL_JSON")"; DIFF="$(awk -v a="$TOTAL_GB" -v b="$DETAIL_TOTAL" 'BEGIN {d=a-b; if(d<0)d=-d; print d}')"

{
cat <<'HTML'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Microsoft Sentinel Cost Summary (EUR)</title><style>
*{box-sizing:border-box}body{margin:0;background:#f5f7fa;color:#172b4d;font:14px "Segoe UI",Arial,sans-serif}.wrap{max-width:1280px;margin:auto;padding:30px}.hero{border-left:6px solid #0078d4;background:#fff;padding:24px;margin-bottom:18px;box-shadow:0 1px 3px #0001}h1{margin:0 0 8px;color:#003b6f;font-size:28px}h2{font-size:20px;margin:28px 0 12px;color:#003b6f}.muted{color:#586a7d}.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;margin-top:16px}.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{background:#fff;padding:18px;border:1px solid #e1e7ed}.card .value{border-left:4px solid #107c10;padding-left:12px;font-size:25px;font-weight:600;margin-top:8px;color:#17365d}.card .small{font-size:13px;margin-top:5px;color:#586a7d}.panel{background:#fff;border:1px solid #e1e7ed;padding:18px;overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;background:#eaf3fa;color:#003b6f;padding:10px;border-bottom:2px solid #0078d4;white-space:nowrap}td{padding:9px 10px;border-bottom:1px solid #e7edf2}tbody tr:nth-child(even){background:#fafcfd}.num{text-align:right;white-space:nowrap}.category td{background:#e9f4ea!important;color:#175d1b;font-weight:600;border-top:2px solid #a8d5aa}.grand td{background:#003b6f!important;color:#fff;font-weight:700}.bar{height:7px;background:#dcecf8;border-radius:4px;min-width:50px}.bar span{display:block;height:100%;background:#0078d4;border-radius:4px}dl{display:grid;grid-template-columns:max-content 1fr;gap:8px 18px;margin:0}dt{font-weight:600}@media(max-width:760px){.wrap{padding:14px}.cards{grid-template-columns:1fr 1fr}h1{font-size:23px}}@media print{body{background:#fff}.wrap{max-width:none;padding:0}.hero,.panel,.card{box-shadow:none}h2{page-break-after:avoid}tr{page-break-inside:avoid}}
</style></head><body><main class="wrap">
HTML
printf '<header class="hero"><h1>Microsoft Sentinel Cost Summary (EUR)</h1><div class="muted">Read-only estimate based on billable Log Analytics ingestion</div><div class="meta"><div><b>Workspace</b><br>%s</div><div><b>Resource group</b><br>%s</div><div><b>Subscription</b><br>%s<br><span class="muted">%s</span></div><div><b>Tenant ID</b><br>%s</div><div><b>Azure region</b><br>%s</div><div><b>Report period (UTC)</b><br>%s to %s</div></div></header>' "$(html_escape "$WORKSPACE_NAME")" "$(html_escape "$WORKSPACE_RG")" "$(html_escape "$SUB_NAME")" "$(html_escape "$SUB_ID")" "$(html_escape "$TENANT_ID")" "$(html_escape "$WORKSPACE_LOCATION")" "$REPORT_START" "$REPORT_END"
printf '<section class="cards"><article class="card"><div>Total billable ingestion</div><div class="value">%s</div></article><article class="card"><div>Estimated ingestion cost</div><div class="value">%s</div><div class="small">%s per GB</div></article><article class="card"><div>Average billable GB/day</div><div class="value">%s</div></article><article class="card"><div>Data older than 90 days</div><div class="value">Unavailable</div><div class="small">Retention estimate unavailable</div></article></section>' "$(format_gb "$TOTAL_GB")" "$(format_eur "$TOTAL_COST")" "$(format_eur "$INGESTION_PRICE")" "$(format_gb "$AVG_GB")"
printf '<h2>Detailed expanded cost table</h2><section class="panel"><table><thead><tr><th>Log category</th><th>Table</th><th class="num">Billable ingestion</th><th></th><th class="num">Estimated cost</th></tr></thead><tbody>'
maxgb="$(jq '[.[] | (.BillableGB // 0 | tonumber)] | max // 1' "$DETAIL_JSON")"; current=""
while IFS=$'\t' read -r cat table bytes gb cost; do
  if [[ "$cat" != "$current" ]]; then
    [[ -n "$current" ]] && printf '<tr class="category"><td colspan="4">%s subtotal</td><td class="num">%s</td></tr>' "$(html_escape "$current")" "$(format_eur "$cat_cost")"
    current="$cat"; cat_cost=0
  fi
  cat_cost="$(awk -v a="$cat_cost" -v b="$cost" 'BEGIN{print a+b}')"; width="$(awk -v a="$gb" -v b="$maxgb" 'BEGIN{printf "%.2f",(b>0?a/b*100:0)}')"
  printf '<tr><td>%s</td><td>%s</td><td class="num">%s<br><span class="muted">%s</span></td><td><div class="bar"><span style="width:%s%%"></span></div></td><td class="num">%s</td></tr>' "$(html_escape "$cat")" "$(html_escape "$table")" "$(format_gb "$gb")" "$(format_bytes "$bytes")" "$width" "$(format_eur "$cost")"
done < <(jq -r 'sort_by(.LogCategory) | group_by(.LogCategory) | sort_by(-([.[] | (.EstimatedCostEUR // 0 | tonumber)] | add)) | .[] | sort_by(-(.EstimatedCostEUR // 0 | tonumber), .TableName)[] | [(.LogCategory // "Other"),(.TableName // ""),(.BillableBytes // 0),(.BillableGB // 0),(.EstimatedCostEUR // 0)] | @tsv' "$DETAIL_JSON")
[[ -n "$current" ]] && printf '<tr class="category"><td colspan="4">%s subtotal</td><td class="num">%s</td></tr>' "$(html_escape "$current")" "$(format_eur "$cat_cost")"
printf '<tr class="grand"><td colspan="2">Grand total</td><td class="num">%s</td><td></td><td class="num">%s</td></tr></tbody></table></section>' "$(format_gb "$DETAIL_TOTAL")" "$(format_eur "$TOTAL_COST")"
printf '<h2>Daily ingestion trend</h2><section class="panel"><table><thead><tr><th>Date (UTC)</th><th class="num">Billable GB</th><th class="num">Estimated cost</th></tr></thead><tbody>'
jq -r '.[] | [(.Date // ""),(.BillableGB // 0),(.EstimatedCostEUR // 0)] | @tsv' "$DAILY_JSON" | while IFS=$'\t' read -r day gb cost; do printf '<tr><td>%s</td><td class="num">%s</td><td class="num">%s</td></tr>' "$(html_escape "$day")" "$(format_gb "$gb")" "$(format_eur "$cost")"; done
sku="$(jq -r '.sku.name // "Unavailable"' "$META_JSON")"; quota="$(jq -r '.workspaceCapping.dailyQuotaGb // "Not configured"' "$META_JSON")"; retention="$(jq -r '.retentionInDays // "Unavailable"' "$META_JSON")"
printf '</tbody></table></section><h2>Workspace metadata and parameters</h2><section class="panel"><dl><dt>Workspace resource ID</dt><dd>%s</dd><dt>Workspace customer ID</dt><dd>%s</dd><dt>Sentinel evidence</dt><dd>%s</dd><dt>Workspace SKU</dt><dd>%s</dd><dt>Daily quota</dt><dd>%s</dd><dt>Workspace retention</dt><dd>%s days</dd><dt>Ingestion price</dt><dd>%s EUR per GB</dd><dt>Retention price</dt><dd>%s EUR per GB/month</dd><dt>Generated (UTC)</dt><dd>%s</dd><dt>Script version</dt><dd>%s</dd></dl></section><h2>Notes</h2><section class="panel"><ul><li>Costs are estimates based on billable Log Analytics ingestion and configured prices.</li><li>Azure Cost Management and the Azure invoice remain authoritative.</li><li>Microsoft 365 E5/A5/F5/G5 ingestion benefits are excluded.</li><li>Data older than 90 days and retention cost are unavailable: accurately measuring retained historical data requires broad table queries and is not reliably available from Usage ingestion records.</li><li>Retention estimates may differ from actual billing depending on workspace and table retention configuration.</li></ul></section></main></body></html>\n' "$(html_escape "$WORKSPACE_ID")" "$(html_escape "$WORKSPACE_CUSTOMER_ID")" "$(html_escape "$SENTINEL_EVIDENCE")" "$(html_escape "$sku")" "$(html_escape "$quota")" "$(html_escape "$retention")" "$(html_escape "$INGESTION_PRICE")" "$(html_escape "$RETENTION_PRICE")" "$GENERATED_AT" "$SCRIPT_VERSION"
} >"$OUTPUT" || { rm -f -- "$OUTPUT"; die 'Failed to create HTML report.'; }
printf 'Report created: %s\nSummary GB: %s; detail GB: %s; difference: %s GB\n' "$OUTPUT" "$TOTAL_GB" "$DETAIL_TOTAL" "$DIFF"
