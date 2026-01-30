#!/bin/bash

# ---------------------------------------------------------------------
# Bulk Guest Invitation Script for SOC Analyst Accounts
#
# Context:
# Some customers do not have Entra ID P2 licensing. In these tenants,
# Access Packages and Entitlement Management cannot be used to invite
# external SOC analyst accounts. This script enables bulk guest
# invitation using Microsoft Graph via `az rest`.
#
# Usage:
# Prepare a file named users.txt containing one UPN per line:
#   analyst1@externaltenant.com
#   analyst2@externaltenant.com
#   analyst3@externaltenant.com
#
# Run:
#   ./invite-guests.sh -i users.txt
#
# Output:
# The script prints three values per entry:
#   invitedUserEmailAddress | inviteRedeemUrl | status
#
# Each SOC analyst must receive their own personal redemption link.
# They must open the link with their analyst account and accept guest
# permissions. This establishes their B2B guest identity in the
# customer’s tenant.
# ---------------------------------------------------------------------

while getopts "i:" opt; do
  case "$opt" in
    i) INPUT_FILE=$OPTARG ;;
  esac
done

if [ -z "$INPUT_FILE" ]; then
  echo "Usage: $0 -i users.txt"
  exit 1
fi

while read -r upn; do
  [ -z "$upn" ] && continue

  result=$(az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/invitations" \
    --headers "Content-Type=application/json" \
    --body "{
      \"invitedUserEmailAddress\": \"$upn\",
      \"inviteRedirectUrl\": \"https://myapps.microsoft.com\",
      \"sendInvitationMessage\": false
    }")

  email=$(echo "$result" | jq -r '.invitedUserEmailAddress')
  url=$(echo "$result" | jq -r '.inviteRedeemUrl')
  status=$(echo "$result" | jq -r '.status')

  echo "$email | $url | $status"
done < "$INPUT_FILE"

#!/bin/bash

while getopts "i:" opt; do
  case "$opt" in
    i) INPUT_FILE=$OPTARG ;;
  esac
done

if [ -z "$INPUT_FILE" ]; then
  echo "Usage: $0 -i users.txt"
  exit 1
fi

while IFS= read -r upn; do
  [ -z "$upn" ] && continue

  result=$(az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/invitations" \
    --headers "Content-Type=application/json" \
    --body "{
      \"invitedUserEmailAddress\": \"$upn\",
      \"inviteRedirectUrl\": \"https://myapps.microsoft.com\",
      \"sendInvitationMessage\": false
    }" < /dev/null)     # prevent az from consuming the remaining lines

  email=$(echo "$result" | jq -r '.invitedUserEmailAddress')
  url=$(echo "$result" | jq -r '.inviteRedeemUrl')
  status=$(echo "$result" | jq -r '.status')

  echo "$email | $url | $status"
done < "$INPUT_FILE
