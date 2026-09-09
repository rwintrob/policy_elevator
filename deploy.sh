#!/usr/bin/env bash
# ==============================================================================
# GCP Provisioning & Cloud Run Deployment Script for JIT Org Policy Elevator
# ==============================================================================
set -euo pipefail

# Configuration Defaults (Override via environment variables)
PROJECT_ID="${GCP_PROJECT_ID:-policy-elevator}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="jit-policy-elevator"
SA_NAME="jit-policy-elevator-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if [ -z "$PROJECT_ID" ]; then
    echo "ERROR: GCP_PROJECT_ID is not set and gcloud default project is empty."
    echo "Usage: GCP_PROJECT_ID=your-project-id ./deploy.sh"
    exit 1
fi

echo "======================================================================"
echo " Starting Deployment: JIT Org Policy Permission Elevator & Dashboard"
echo " Target GCP Project: ${PROJECT_ID}"
echo " Region:            ${REGION}"
echo " Service Account:   ${SA_EMAIL}"
echo "======================================================================"

# 1. Enable Required Google Cloud APIs
echo "[1/5] Enabling required GCP APIs..."
gcloud services enable \
    iam.googleapis.com \
    cloudresourcemanager.googleapis.com \
    orgpolicy.googleapis.com \
    run.googleapis.com \
    firestore.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    --project="${PROJECT_ID}"

# 2. Create Service Account for Elevator Tool
echo "[2/5] Provisioning Elevator Service Account..."
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    gcloud iam service-accounts create "${SA_NAME}" \
        --display-name="JIT Org Policy Elevator Tool Service Account" \
        --project="${PROJECT_ID}"
    echo "Created Service Account: ${SA_EMAIL}"
else
    echo "Service Account ${SA_EMAIL} already exists."
fi

# 3. Grant Required IAM Permissions to Service Account
echo "[3/5] Binding IAM permissions to Elevator Service Account..."

# Grant Project IAM Admin at Organization or Target Project level so elevator can modify IAM policy
# Note: For strict security, you can bind roles/resourcemanager.projectIamAdmin per target project
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/resourcemanager.projectIamAdmin" \
    --condition=None >/dev/null

# Grant Firestore User for audit logging
gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/datastore.user" \
    --condition=None >/dev/null

# Grant Storage Object Admin to Compute SA and Cloud Build SA for Cloud Run source deployment
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')
COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
CLOUDBUILD_SA="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/storage.objectAdmin" \
    --condition=None >/dev/null 2>&1 || true

gcloud projects add-iam-policy-binding "${PROJECT_ID}" \
    --member="serviceAccount:${CLOUDBUILD_SA}" \
    --role="roles/storage.objectAdmin" \
    --condition=None >/dev/null 2>&1 || true

# Build environment variables string
ENV_VARS="GCP_PROJECT_ID=${PROJECT_ID}:GCP_ORGANIZATION_ID=${GCP_ORGANIZATION_ID:-527512186146}:ALLOWED_DOMAINS=${ALLOWED_DOMAINS:-rwintrob.altostrat.com,altostrat.com}"

if [ -n "${SMTP_HOST:-}" ]; then ENV_VARS="${ENV_VARS}:SMTP_HOST=${SMTP_HOST}"; fi
if [ -n "${SMTP_PORT:-}" ]; then ENV_VARS="${ENV_VARS}:SMTP_PORT=${SMTP_PORT}"; fi
if [ -n "${SMTP_USER:-}" ]; then ENV_VARS="${ENV_VARS}:SMTP_USER=${SMTP_USER}"; fi
if [ -n "${SMTP_PASSWORD:-}" ]; then ENV_VARS="${ENV_VARS}:SMTP_PASSWORD=${SMTP_PASSWORD}"; fi
if [ -n "${SMTP_SENDER:-}" ]; then ENV_VARS="${ENV_VARS}:SMTP_SENDER=${SMTP_SENDER}"; fi
if [ -n "${SENDGRID_API_KEY:-}" ]; then ENV_VARS="${ENV_VARS}:SENDGRID_API_KEY=${SENDGRID_API_KEY}"; fi

# 4. Build and Deploy Container to Cloud Run
echo "[4/5] Deploying Container to Google Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
    --source="." \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --service-account="${SA_EMAIL}" \
    --no-allow-unauthenticated \
    --port=8080 \
    --set-env-vars="^:^${ENV_VARS}" \
    --platform=managed \
    --quiet

# 5. Retrieve Deployment Details
SERVICE_URL=$(gcloud run services describe "${SERVICE_NAME}" --region="${REGION}" --project="${PROJECT_ID}" --format="value(status.url)")

echo "======================================================================"
echo " DEPLOYMENT SUCCESSFUL! 🎉"
echo " Service Name: ${SERVICE_NAME}"
echo " Service URL:  ${SERVICE_URL}"
echo "======================================================================"
echo "Next Steps:"
echo "1. Configure GCP Identity-Aware Proxy (IAP) on Cloud Run service URL to guard dashboard access."
echo "2. Grant users 'roles/run.invoker' or IAP Access User permissions to access dashboard."
echo "======================================================================"
