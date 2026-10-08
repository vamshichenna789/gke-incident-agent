# Implementation Guide

## Goal

Deploy a read-only AI incident triage agent for a GKE namespace. The agent collects Kubernetes, logging, and monitoring evidence, asks Gemini on Vertex AI for evidence-based RCA, validates a remediation plan, and can optionally open a GitOps pull request for a narrowly defined remediation.

## Architecture

```text
GKE
 ├─ Kubernetes state/events
 ├─ Cloud Logging
 └─ Cloud Monitoring
        |
        v
GKE Remote MCP + bounded Cloud tools
        |
        v
Evidence normalization
        |
        v
Gemini / Vertex AI
        |
        +--> Incident report
        |
        +--> Remediation plan
                    |
                    v
              Safety validator
                    |
             +------+------+
             |             |
           manual       GitOps PR
                           |
                      human approval
                           |
                         Argo CD
                           |
                           v
                          GKE
```

## Required components

| Component | Purpose |
|---|---|
| GKE | Runs the agent and target workloads |
| GKE Remote MCP | Read-only Kubernetes investigation interface |
| Vertex AI | Gemini reasoning |
| Cloud Logging | Runtime/application evidence |
| Cloud Monitoring | Resource/health evidence |
| Kubernetes RBAC | Limits Kubernetes visibility |
| Workload Identity Federation | Keyless Google Cloud authentication |
| Secret Manager | Stores GitHub token, if PR remediation is enabled |
| GitHub | Stores GitOps manifests and receives PRs |
| Argo CD | Applies approved GitOps changes |

## Deployment checklist

### A. Google Cloud

1. Select a project.
2. Enable GKE, Artifact Registry, Vertex AI, Logging, Monitoring, and Secret Manager APIs.
3. Create a dedicated Google service account.
4. Grant minimum required IAM roles.
5. Ensure GKE Workload Identity Federation is enabled.

### B. Kubernetes

1. Create namespace `ai-agent`.
2. Create Kubernetes service account `incident-agent`.
3. Annotate it with the Google service account email.
4. Create the read-only ClusterRole and binding.
5. Confirm `get/list` works for investigation resources.
6. Confirm Secrets cannot be read.

### C. Configuration

Set these values in your deployment environment:

```text
GCP_PROJECT_ID
VERTEX_AI_REGION
GKE_CLUSTER_LOCATION
GKE_CLUSTER_NAME
TARGET_NAMESPACE
GCP_SERVICE_ACCOUNT_EMAIL
ARTIFACT_REPOSITORY
GITHUB_OWNER                 # optional
GITHUB_REPOSITORY            # optional
GITHUB_TOKEN_SECRET          # optional
```

The Kubernetes ConfigMap contains non-secret configuration. GitHub tokens must remain in Secret Manager.

### D. Container

Build and publish:

```bash
gcloud builds submit . \
  --project="$GCP_PROJECT_ID" \
  --tag="${VERTEX_AI_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${ARTIFACT_REPOSITORY}/incident-agent:${IMAGE_TAG}"
```

Use immutable image digests for production deployments.

### E. Deploy

```bash
./deploy.sh
kubectl -n ai-agent rollout status deployment/incident-agent --timeout=180s
kubectl -n ai-agent logs deployment/incident-agent -f
```

## Evidence flow

The agent's preferred order is:

1. Kubernetes workload state.
2. Kubernetes events.
3. Related pod/container state.
4. Cloud Logging when runtime logs add diagnostic value.
5. Cloud Monitoring when resource pressure or measurable platform behavior matters.
6. Cross-source correlation.

Do not allow the model to invent missing evidence.

## Remediation safety

The model never receives direct Kubernetes write access. The remediation plan is structured and validated. Every action must explicitly require human approval.

Only an application-controlled adapter can create a GitHub change. This keeps repository write operations outside the model's tool surface.

For a new workload, implement a deterministic adapter that maps a known root cause to a known manifest change. Do not implement a generic "edit any file however the model asks" function.

## GitHub setup

Use a fine-grained token scoped to the target repository. Store it in Secret Manager:

```bash
printf '%s' '<GITHUB_TOKEN>' | gcloud secrets versions add "$GITHUB_TOKEN_SECRET" \
  --data-file=- \
  --project="$GCP_PROJECT_ID"
```

Grant only:

```text
roles/secretmanager.secretAccessor
```

to the agent service account on that secret.

## Argo CD

Point an Argo CD Application at the GitOps repository and a path containing Kubernetes manifests. The agent should create a PR; a human should review and merge it. Argo CD then reconciles the approved commit.

The agent itself should not hold Argo CD administrative credentials.

## Validation

Use these checks after deployment:

```bash
kubectl -n ai-agent get pod -l app=incident-agent
kubectl -n ai-agent auth can-i get pods
kubectl -n ai-agent auth can-i get events
kubectl -n ai-agent auth can-i get secrets
```

Expected final check:

```text
no
```

Check the logs for:

```text
GKE MCP connection configured
Starting Incident Investigation
STRUCTURED EVIDENCE
AI INCIDENT REPORT
REMEDIATION PLAN
```

If GitHub remediation is enabled, also expect the controlled GitHub adapter to report its eligibility decision and, when applicable, a pull-request URL.

## Production hardening

Before production:

- Replace broad project-level roles with resource-level IAM where practical.
- Use immutable image digests.
- Add network egress controls for the agent.
- Add admission/policy controls.
- Add structured audit logs for every remediation attempt.
- Add PR approval policies and CODEOWNERS.
- Add automated rollback and Argo CD health checks.
- Add test incidents for each supported failure mode.
- Monitor token/secret access and GitHub API usage.
- Treat all model-generated content as untrusted data.
