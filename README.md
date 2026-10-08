# AI-Powered GKE Incident Triage Agent

A production-oriented reference implementation of a **read-only Kubernetes incident-response agent for GKE**. It uses Google ADK + Gemini on Vertex AI, GKE Remote MCP, Cloud Logging, Cloud Monitoring, Kubernetes RBAC, Workload Identity Federation, and an optional GitOps pull-request remediation path.

The design deliberately separates **AI reasoning** from **privileged execution**:

```text
Engineer / Alert
      |
      v
Incident Triage Agent
      |
      +--> GKE Remote MCP --------> Kubernetes state/events/logs
      |
      +--> Cloud Logging ---------> runtime evidence
      |
      +--> Cloud Monitoring ------> resource evidence
      |
      v
Evidence normalization + correlation
      |
      v
Gemini / Vertex AI
      |
      v
Incident report + remediation plan
      |
      v
Safety validation
      |
      +--> Manual investigation
      |
      +--> GitOps PR --> Human review --> Argo CD --> GKE
```

## Security model

The agent is intentionally read-only against Kubernetes. Its Kubernetes identity should have only the `get`/`list` permissions required for incident investigation. It must not have access to Kubernetes Secrets, `exec`, `delete`, `patch`, or `update`.

Google Cloud access uses **GKE Workload Identity Federation**. Do not mount service-account JSON keys into the pod.

GitHub remediation is application-controlled rather than exposed as an unrestricted ADK tool. The GitHub token is read from Google Secret Manager, and every generated remediation action must require human approval before merge.

## Prerequisites

- A Google Cloud project with billing enabled
- A GKE cluster with Workload Identity Federation enabled
- `gcloud`, `kubectl`, Docker/Cloud Build
- Vertex AI API
- Artifact Registry
- Cloud Logging and Cloud Monitoring
- Google ADK / Gemini dependencies installed by the container
- Optional: a GitHub repository containing the GitOps manifests
- Optional: Argo CD for GitOps deployment

## 1. Configure your environment

Export values for your environment:

```bash
export GCP_PROJECT_ID="<GCP_PROJECT_ID>"
export VERTEX_AI_REGION="<VERTEX_AI_REGION>"
export GKE_CLUSTER_LOCATION="<GKE_CLUSTER_LOCATION>"
export GKE_CLUSTER_NAME="<GKE_CLUSTER_NAME>"
export TARGET_NAMESPACE="<TARGET_NAMESPACE>"
export GCP_SERVICE_ACCOUNT_EMAIL="<GCP_SERVICE_ACCOUNT_EMAIL>"
export ARTIFACT_REPOSITORY="<ARTIFACT_REPOSITORY>"
export IMAGE_TAG="v1"
```

For GitHub-backed remediation:

```bash
export GITHUB_OWNER="<GITHUB_OWNER>"
export GITHUB_REPOSITORY="<GITHUB_REPOSITORY>"
export GITHUB_TOKEN_SECRET="<GITHUB_TOKEN_SECRET_NAME>"
export REMEDIATION_WORKLOAD="<REMEDIATION_WORKLOAD>"
export REMEDIATION_FILE_PATH="<REMEDIATION_FILE_PATH>"
export REMEDIATION_ANCHOR_KEY="<REMEDIATION_ANCHOR_KEY>"
export REMEDIATION_INSERT_LINE="<REMEDIATION_INSERT_LINE>"
```

## 2. Create the Google service account

Create a dedicated Google service account for the agent and grant only the roles required by your deployment. A typical starting point is:

```bash
gcloud iam service-accounts create incident-agent \
  --project="$GCP_PROJECT_ID" \
  --display-name="GKE Incident Triage Agent"
```

Grant Vertex AI, logging, monitoring, GKE MCP/cluster-viewer, and Secret Manager access as required:

```bash
gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="serviceAccount:$GCP_SERVICE_ACCOUNT_EMAIL" \
  --role="roles/aiplatform.user"

gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="serviceAccount:$GCP_SERVICE_ACCOUNT_EMAIL" \
  --role="roles/logging.viewer"

gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="serviceAccount:$GCP_SERVICE_ACCOUNT_EMAIL" \
  --role="roles/monitoring.viewer"

gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="serviceAccount:$GCP_SERVICE_ACCOUNT_EMAIL" \
  --role="roles/container.clusterViewer"

gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
  --member="serviceAccount:$GCP_SERVICE_ACCOUNT_EMAIL" \
  --role="roles/mcp.toolUser"
```

If GitHub remediation is enabled, grant Secret Manager access only to the specific GitHub token secret rather than broadly at project scope.

## 3. Configure the Kubernetes identity

The Kubernetes service account is `incident-agent` in namespace `ai-agent`. Annotate it with your Google service account and create the Workload Identity binding between them.

```bash
kubectl create namespace ai-agent --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/rbac.yaml
```

Then bind the Kubernetes service account to the Google service account:

```bash
gcloud iam service-accounts add-iam-policy-binding "$GCP_SERVICE_ACCOUNT_EMAIL" \
  --project="$GCP_PROJECT_ID" \
  --role="roles/iam.workloadIdentityUser" \
  --member="serviceAccount:${GCP_PROJECT_ID}.svc.id.goog[ai-agent/incident-agent]"
```

Verify:

```bash
kubectl -n ai-agent get serviceaccount incident-agent -o yaml
kubectl -n ai-agent auth can-i get pods
kubectl -n ai-agent auth can-i get secrets
```

The final command should return `no` for the agent identity.

## 4. Create the GitHub secret (optional)

Create a fine-grained GitHub token with repository-scoped access. For PR remediation, the token needs only the repository permissions required to read/write contents and create pull requests.

Store it in Secret Manager:

```bash
gcloud secrets create "$GITHUB_TOKEN_SECRET" --project="$GCP_PROJECT_ID" 2>/dev/null || true
printf '%s' '<GITHUB_TOKEN>' | gcloud secrets versions add "$GITHUB_TOKEN_SECRET" \
  --data-file=- \
  --project="$GCP_PROJECT_ID"
```

Grant the agent service account access to this one secret:

```bash
gcloud secrets add-iam-policy-binding "$GITHUB_TOKEN_SECRET" \
  --project="$GCP_PROJECT_ID" \
  --member="serviceAccount:$GCP_SERVICE_ACCOUNT_EMAIL" \
  --role="roles/secretmanager.secretAccessor"
```

Never commit the token to Git, ConfigMaps, Dockerfiles, or Kubernetes manifests.

## 5. Create an Artifact Registry repository

If you do not already have a Docker repository:

```bash
gcloud artifacts repositories create "$ARTIFACT_REPOSITORY" \
  --project="$GCP_PROJECT_ID" \
  --repository-format=docker \
  --location="$VERTEX_AI_REGION"
```

## 6. Build and deploy

The included deployment script keeps environment-specific values outside Git:

```bash
./deploy.sh
```

Or build manually:

```bash
gcloud builds submit . \
  --project="$GCP_PROJECT_ID" \
  --tag="${VERTEX_AI_REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/${ARTIFACT_REPOSITORY}/incident-agent:${IMAGE_TAG}"
```

Render the Kubernetes manifests with your own values and apply them:

```bash
kubectl apply -f <rendered-configmap>.yaml
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f <rendered-deployment>.yaml
```

## 7. Verify the deployment

```bash
kubectl -n ai-agent rollout status deployment/incident-agent --timeout=180s
kubectl -n ai-agent get pods -l app=incident-agent -o wide
kubectl -n ai-agent logs deployment/incident-agent -f
```

A healthy startup should show Google authentication, GKE MCP connection, investigation, structured evidence, an incident report, and a validated remediation plan.

## 8. How incident investigation works

The agent starts with Kubernetes evidence and then uses additional sources only when useful:

1. Identify unhealthy workloads.
2. Inspect pod/container state and Kubernetes events.
3. Inspect deployments/ReplicaSets/StatefulSets and relevant services.
4. Query Cloud Logging for application/runtime failures when appropriate.
5. Query Cloud Monitoring for resource pressure when appropriate.
6. Normalize evidence into structured records.
7. Ask Gemini to reason over observed evidence.
8. Produce a machine-readable incident report.
9. Produce a machine-readable remediation plan.
10. Validate the plan against safety rules.

The agent must never claim that evidence was collected from a source it did not actually query.

## 9. GitOps remediation

The repository includes a configurable, deterministic GitHub remediation adapter. It demonstrates the safe pattern:

```text
AI recommendation
      |
      v
Safety validation
      |
      v
Controlled GitHub adapter
      |
      v
New branch + commit
      |
      v
Pull request
      |
      v
Human review/approval
      |
      v
Argo CD sync
```

The adapter remains intentionally narrow: it only changes the configured file, inserts the configured line after the configured anchor key, and only runs for the configured workload. Set `REMEDIATION_*` values for your repository. Do not turn this into a generic model-controlled file editor.

## 10. Operational guidance

For production use:

- Use a dedicated Google service account.
- Keep Kubernetes RBAC read-only.
- Do not grant Secret access unless a specific diagnostic requirement exists.
- Use Workload Identity Federation rather than long-lived keys.
- Keep GitHub credentials in Secret Manager.
- Restrict GitHub tokens to one repository and minimum permissions.
- Require human approval before every remediation merge.
- Keep remediation adapters deterministic and workload-specific.
- Pin container images by immutable digest in production.
- Add resource requests/limits and a Pod Security context.
- Add alerting, audit logging, and deployment observability.
- Review model output as untrusted input; validate it before any action.

## 11. Troubleshooting

### Vertex AI authentication fails

Check Workload Identity and Google service-account IAM:

```bash
kubectl -n ai-agent describe pod -l app=incident-agent
gcloud projects get-iam-policy "$GCP_PROJECT_ID"
```

### GKE MCP access fails

Verify the Google service account has the required GKE/MCP permissions and that the cluster supports the configured MCP endpoint.

### GitHub access fails

Check the Secret Manager binding and repository permissions. Do not print the token while troubleshooting.

### No PR is created

Inspect the remediation plan first. A PR is created only when an action has:

```json
{
  "execution_method": "gitops",
  "requires_human_approval": true
}
```

Unsupported workloads are intentionally skipped by the example adapter.

## License

Add the license of your choice before publishing. No credentials or environment-specific credentials are required by this repository.
