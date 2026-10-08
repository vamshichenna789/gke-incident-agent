#!/usr/bin/env bash
set -euo pipefail

: "${GCP_PROJECT_ID:?Set GCP_PROJECT_ID}"
: "${VERTEX_AI_REGION:?Set VERTEX_AI_REGION}"
: "${GKE_CLUSTER_LOCATION:?Set GKE_CLUSTER_LOCATION}"
: "${GKE_CLUSTER_NAME:?Set GKE_CLUSTER_NAME}"
: "${TARGET_NAMESPACE:?Set TARGET_NAMESPACE}"
: "${GCP_SERVICE_ACCOUNT_EMAIL:?Set GCP_SERVICE_ACCOUNT_EMAIL}"
: "${ARTIFACT_REPOSITORY:?Set ARTIFACT_REPOSITORY}"
: "${GITHUB_OWNER:?Set GITHUB_OWNER}"
: "${GITHUB_REPOSITORY:?Set GITHUB_REPOSITORY}"
: "${GITHUB_TOKEN_SECRET:?Set GITHUB_TOKEN_SECRET}"
: "${REMEDIATION_WORKLOAD:?Set REMEDIATION_WORKLOAD}"
: "${REMEDIATION_FILE_PATH:?Set REMEDIATION_FILE_PATH}"
: "${REMEDIATION_ANCHOR_KEY:?Set REMEDIATION_ANCHOR_KEY}"
: "${REMEDIATION_INSERT_LINE:?Set REMEDIATION_INSERT_LINE}"
: "${IMAGE_TAG:=latest}"

IMAGE="${VERTEX_AI_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${ARTIFACT_REPOSITORY}/incident-agent:${IMAGE_TAG}"

export GCP_PROJECT_ID VERTEX_AI_REGION GKE_CLUSTER_LOCATION GKE_CLUSTER_NAME TARGET_NAMESPACE GITHUB_OWNER GITHUB_REPOSITORY GITHUB_TOKEN_SECRET REMEDIATION_WORKLOAD REMEDIATION_FILE_PATH REMEDIATION_ANCHOR_KEY REMEDIATION_INSERT_LINE

# Enable required APIs.
gcloud services enable \
  container.googleapis.com \
  artifactregistry.googleapis.com \
  aiplatform.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com \
  secretmanager.googleapis.com \
  --project="${GCP_PROJECT_ID}"

# Build and publish the image.
gcloud builds submit . \
  --project="${GCP_PROJECT_ID}" \
  --tag="${IMAGE}"

# Render placeholders in manifests without committing environment-specific values.
sed \
  -e "s|<GCP_PROJECT_ID>|${GCP_PROJECT_ID}|g" \
  -e "s|<VERTEX_AI_REGION>|${VERTEX_AI_REGION}|g" \
  -e "s|<GKE_CLUSTER_LOCATION>|${GKE_CLUSTER_LOCATION}|g" \
  -e "s|<GKE_CLUSTER_NAME>|${GKE_CLUSTER_NAME}|g" \
  -e "s|<TARGET_NAMESPACE>|${TARGET_NAMESPACE}|g" \
  -e "s|<GITHUB_OWNER>|${GITHUB_OWNER}|g" \
  -e "s|<GITHUB_REPOSITORY>|${GITHUB_REPOSITORY}|g" \
  -e "s|<GITHUB_TOKEN_SECRET_NAME>|${GITHUB_TOKEN_SECRET}|g" \
  -e "s|<REMEDIATION_WORKLOAD>|${REMEDIATION_WORKLOAD}|g" \
  -e "s|<REMEDIATION_FILE_PATH>|${REMEDIATION_FILE_PATH}|g" \
  -e "s|<REMEDIATION_ANCHOR_KEY>|${REMEDIATION_ANCHOR_KEY}|g" \
  -e "s|<REMEDIATION_INSERT_LINE>|${REMEDIATION_INSERT_LINE}|g" \
  k8s/configmap.yaml > /tmp/incident-agent-configmap.yaml

sed \
  -e "s|<GCP_SERVICE_ACCOUNT_EMAIL>|${GCP_SERVICE_ACCOUNT_EMAIL}|g" \
  k8s/serviceaccount.yaml > /tmp/incident-agent-serviceaccount.yaml

sed \
  -e "s|<ARTIFACT_REGISTRY_IMAGE>|${IMAGE}|g" \
  k8s/deployment.yaml > /tmp/incident-agent-deployment.yaml

kubectl create namespace ai-agent --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f /tmp/incident-agent-configmap.yaml
kubectl apply -f /tmp/incident-agent-serviceaccount.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f /tmp/incident-agent-deployment.yaml

kubectl -n ai-agent rollout status deployment/incident-agent --timeout=180s
kubectl -n ai-agent get pods -l app=incident-agent -o wide
