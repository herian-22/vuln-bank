#!/bin/bash
# scripts/generate_payload.sh

# Assign arguments to named variables
PIPELINE_STATUS=$1
REPO_NAME=$2
RUN_URL=$3
PIPELINE_COLOR=$4
SECRET_SUMMARY=$5
SAST_SUMMARY=$6
CONTAINER_SUMMARY=$7
MISCONFIG_SUMMARY=$8
DAST_SUMMARY=$9
COMMIT_SHA=${10}
ACTOR=${11}

# Create a JSON payload using a template
# This method is safer than building the string manually
cat <<EOF
{
  "username": "DevSecOps Bot",
  "avatar_url": "https://i.imgur.com/fJc1mOa.png",
  "embeds": [
    {
      "title": "DevSecOps Pipeline Status: $PIPELINE_STATUS",
      "url": "$RUN_URL",
      "color": "$PIPELINE_COLOR",
      "fields": [
        {
          "name": "Repository",
          "value": "$REPO_NAME",
          "inline": true
        },
        {
          "name": "Triggered by",
          "value": "$ACTOR",
          "inline": true
        },
        {
          "name": "Commit",
          "value": "\`$COMMIT_SHA\`"
        },
        {
          "name": "🛡️ Secret Scan (Gitleaks)",
          "value": "$SECRET_SUMMARY"
        },
        {
          "name": "🔬 SAST (Bandit)",
          "value": "$SAST_SUMMARY"
        },
        {
          "name": "📦 Container Scan (Trivy)",
          "value": "$CONTAINER_SUMMARY"
        }
      ],
      "footer": {
        "text": "Security scan results",
        "icon_url": "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png"
      },
      "timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%S.000Z')"
    }
  ]
}
EOF