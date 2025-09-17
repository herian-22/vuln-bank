#!/bin/bash

# Ambil semua variabel dari environment
PIPELINE_STATUS=$1
REPO_NAME=$2
RUN_URL=$3
PIPELINE_COLOR=$4
GITLEAKS_SUMMARY=$5
BANDIT_SUMMARY=$6
TRIVY_SUMMARY=$7
DAST_SUMMARY=$8
COMMIT_SHA=$9
GITHUB_ACTOR=${10}

# Gunakan jq untuk membangun JSON dengan aman
# Ini adalah cara paling andal untuk menangani string multi-baris dan karakter khusus
jq -n \
  --arg pipeline_status "$PIPELINE_STATUS" \
  --arg repo_name "$REPO_NAME" \
  --arg run_url "$RUN_URL" \
  --argjson pipeline_color "$PIPELINE_COLOR" \
  --arg gitleaks_summary "$GITLEAKS_SUMMARY" \
  --arg bandit_summary "$BANDIT_SUMMARY" \
  --arg trivy_summary "$TRIVY_SUMMARY" \
  --arg dast_summary "$DAST_SUMMARY" \
  --arg commit_sha "$COMMIT_SHA" \
  --arg github_actor "$GITHUB_ACTOR" \
'{
  "embeds": [{
    "title": "Laporan Ringkasan DevSecOps Pipeline",
    "description": "Status Pipeline: **\($pipeline_status)**\nRepositori: **\($repo_name)**",
    "url": $run_url,
    "color": $pipeline_color,
    "fields": [
      { "name": "Secret Scanning (Gitleaks)", "value": "```\($gitleaks_summary)```" },
      { "name": "SAST (Bandit)", "value": "```\($bandit_summary)```" },
      { "name": "Container Scanning (Trivy)", "value": "```\($trivy_summary)```" },
      { "name": "DAST (OWASP ZAP)", "value": "```\($dast_summary)```" }
    ],
    "footer": { "text": "Commit: \($commit_sha) oleh \($github_actor)" }
  }]
}'