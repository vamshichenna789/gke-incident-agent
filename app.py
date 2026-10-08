import asyncio
import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from dataclasses import dataclass, asdict
from typing import Any
import google.auth
from google.auth.transport.requests import Request
from google.cloud import logging_v2
from google.cloud import monitoring_v3
from google.genai import types
import json
import re
import uuid
from github_client import GitHubClient
from github_remediation import create_remediation_pr

from google.adk.agents import Agent
from google.adk.runners import InMemoryRunner
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import (
    StreamableHTTPConnectionParams,
)


PROJECT_ID = os.environ["GOOGLE_CLOUD_PROJECT"]
VERTEX_LOCATION = os.environ["GOOGLE_CLOUD_LOCATION"]
GKE_LOCATION = os.environ["GKE_CLUSTER_LOCATION"]
CLUSTER_NAME = os.environ["GKE_CLUSTER_NAME"]
NAMESPACE = os.environ["TARGET_NAMESPACE"]
MCP_URL = os.environ.get(
    "GKE_MCP_URL",
    "https://container.googleapis.com/mcp",
)
MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

CLUSTER_PATH = (
    f"projects/{PROJECT_ID}/locations/{GKE_LOCATION}/clusters/{CLUSTER_NAME}"
)

# Keep this intentionally narrow. Do not turn the agent into a generic
# Google Cloud API client.
ALLOWED_METRICS = {
    "kubernetes.io/container/cpu/core_usage_time",
    "kubernetes.io/container/memory/used_bytes",
    "kubernetes.io/container/memory/limit_bytes",
    "kubernetes.io/container/restart_count",
    "container.googleapis.com/container/cpu/limit_utilization",
    "container.googleapis.com/container/memory/bytes_used",
}
@dataclass
class EvidenceRecord:
    source: str
    evidence_type: str
    workload: str
    pod: Optional[str] = None
    timestamp: Optional[str] = None
    severity: Optional[str] = None
    finding: Optional[str] = None
    value: Optional[Any] = None
    raw_evidence: Optional[str] = None

    def to_dict(self):
        return asdict(self)
class EvidenceCorrelator:
    def __init__(self):
        self.records: list[EvidenceRecord] = []

    def add(self, record: EvidenceRecord) -> None:
        self.records.append(record)

    def add_many(self, records: list[EvidenceRecord]) -> None:
        self.records.extend(records)

    def get_workload_evidence(
        self,
        workload: str,
    ) -> list[EvidenceRecord]:

        return [
            record
            for record in self.records
            if record.workload == workload
        ]

    def get_by_source(
        self,
        source: str,
    ) -> list[EvidenceRecord]:

        return [
            record
            for record in self.records
            if record.source == source
        ]

    def summary(self) -> dict:
        workloads = {}

        for record in self.records:
            workloads.setdefault(record.workload, []).append(
                record.to_dict()
            )

        return workloads
@dataclass
class RemediationPlan:
    incident_id: str
    actions: list[dict]
    requires_human_approval: bool = True

    def to_dict(self) -> dict:
        return asdict(self)

def calculate_evidence_confidence(
    records: list[EvidenceRecord],
) -> float:

    if not records:
        return 0.0

    source_weights = {
        "kubernetes": 1.0,
        "cloud_logging": 0.9,
        "monitoring": 0.85,
    }

    total = 0.0

    for record in records:
        total += source_weights.get(record.source, 0.5)

    # More independent evidence increases confidence,
    # but confidence is capped at 1.0.
    return min(total / 3.0, 1.0)
def build_evidence_record(
    source: str,
    evidence_type: str,
    workload: str,
    pod: Optional[str] = None,
    timestamp: Optional[str] = None,
    severity: Optional[str] = None,
    finding: Optional[str] = None,
    value: Optional[Any] = None,
    raw_evidence: Optional[str] = None,
) -> EvidenceRecord:

    return EvidenceRecord(
        source=source,
        evidence_type=evidence_type,
        workload=workload,
        pod=pod,
        timestamp=timestamp,
        severity=severity,
        finding=finding,
        value=value,
        raw_evidence=raw_evidence,
    )
@dataclass
class IncidentReport:
    incident_id: str
    namespace: str
    affected_workloads: list[str]
    symptoms: list[str]
    root_causes: list[dict]
    recommendations: list[dict]
    investigation_sources: list[str]

    def to_dict(self) -> dict:
        return asdict(self)

def collect_base_evidence(
    workload: str,
    pod: Optional[str] = None,
) -> list[EvidenceRecord]:

    evidence = []

    if pod:
        evidence.append(
            build_evidence_record(
                source="kubernetes",
                evidence_type="workload_reference",
                workload=workload,
                pod=pod,
                finding=f"Investigating workload {workload}",
            )
        )

    return evidence
def extract_structured_evidence(text: str) -> list[EvidenceRecord]:
    """Extract the machine-readable evidence block from the agent response."""

    pattern = r"STRUCTURED_EVIDENCE_START\s*(.*?)\s*STRUCTURED_EVIDENCE_END"

    match = re.search(pattern, text, re.DOTALL)

    if not match:
        print("\nNo structured evidence block found.")
        return []

    raw_json = match.group(1).strip()

    try:
        items = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        print(f"\nFailed to parse structured evidence: {exc}")
        return []

    records = []

    for item in items:
        if not isinstance(item, dict):
            continue

        record = build_evidence_record(
            source=item.get("source", "unknown"),
            evidence_type=item.get("evidence_type", "unknown"),
            workload=item.get("workload", "unknown"),
            pod=item.get("pod"),
            timestamp=item.get("timestamp"),
            severity=item.get("severity"),
            finding=item.get("finding"),
            value=item.get("value"),
        )

        records.append(record)

    return records
def extract_incident_report(
    text: str
) -> Optional[dict]:
    """Extract the machine-readable incident report."""

    pattern = (
        r"INCIDENT[_ ]REPORT[_ ]START"
        r"\s*(.*?)\s*"
        r"INCIDENT[_ ]REPORT[_ ]END"
    )

    match = re.search(
        pattern,
        text,
        re.DOTALL | re.IGNORECASE
    )

    if not match:
        print(
            "\nNo incident report block found."
        )
        return None

    raw_json = match.group(1).strip()

    try:
        report = json.loads(raw_json)

    except json.JSONDecodeError as exc:
        print(
            f"\nFailed to parse incident report: {exc}"
        )
        return None

    if not isinstance(report, dict):
        print(
            "\nIncident report must be a JSON object."
        )
        return None

    return report
def extract_remediation_plan(
    text: str
) -> Optional[dict]:
    """Extract the machine-readable remediation plan."""

    pattern = (
        r"REMEDIATION[_ ]PLAN[_ ]START"
        r"\s*(.*?)\s*"
        r"REMEDIATION[_ ]PLAN[_ ]END"
    )

    match = re.search(
        pattern,
        text,
        re.DOTALL | re.IGNORECASE
    )

    if not match:
        print(
            "\nNo remediation plan block found."
        )
        return None

    raw_json = match.group(1).strip()

    try:
        plan = json.loads(raw_json)

    except json.JSONDecodeError as exc:
        print(
            f"\nFailed to parse remediation plan: {exc}"
        )
        return None

    if not isinstance(plan, dict):
        print(
            "\nRemediation plan must be a JSON object."
        )
        return None

    return plan
def validate_incident_report(
    report: dict
) -> bool:
    """Validate the structure of an AI-generated incident report."""

    required_fields = {
        "affected_workloads",
        "symptoms",
        "root_causes",
        "recommendations",
        "investigation_sources",
    }

    missing = (
        required_fields
        - report.keys()
    )

    if missing:
        print(
            f"\nIncident report missing fields: "
            f"{sorted(missing)}"
        )
        return False

    if not isinstance(
        report["affected_workloads"],
        list
    ):
        print(
            "\naffected_workloads must be a list."
        )
        return False

    if not isinstance(
        report["symptoms"],
        list
    ):
        print(
            "\nsymptoms must be a list."
        )
        return False

    if not isinstance(
        report["root_causes"],
        list
    ):
        print(
            "\nroot_causes must be a list."
        )
        return False

    if not isinstance(
        report["recommendations"],
        list
    ):
        print(
            "\nrecommendations must be a list."
        )
        return False

    if not isinstance(
        report["investigation_sources"],
        list
    ):
        print(
            "\ninvestigation_sources must be a list."
        )
        return False

    allowed_risks = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    for recommendation in report["recommendations"]:

        if not isinstance(
            recommendation,
            dict
        ):
            print(
                "\nEach recommendation must be an object."
            )
            return False

        if recommendation.get(
            "risk"
        ) not in allowed_risks:

            print(
                f"\nInvalid remediation risk: "
                f"{recommendation.get('risk')}"
            )
            return False

        if not isinstance(
            recommendation.get(
                "requires_approval"
            ),
            bool,
        ):
            print(
                "\nrequires_approval must be boolean."
            )
            return False

    return True
def validate_remediation_plan(
    plan: dict
) -> bool:
    """Validate remediation actions against safety policy."""

    if "actions" not in plan:
        print(
            "\nRemediation plan missing actions."
        )
        return False

    if not isinstance(
        plan["actions"],
        list
    ):
        print(
            "\nRemediation actions must be a list."
        )
        return False

    allowed_risks = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    allowed_methods = {
        "gitops",
        "manual",
        "investigate",
    }

    for action in plan["actions"]:

        if not isinstance(
            action,
            dict
        ):
            return False

        if not action.get("workload"):
            print(
                "\nRemediation action missing workload."
            )
            return False

        if not action.get("action"):
            print(
                "\nRemediation action missing action."
            )
            return False

        if action.get("risk") not in allowed_risks:
            print(
                f"\nInvalid risk: "
                f"{action.get('risk')}"
            )
            return False

        if action.get(
            "execution_method"
        ) not in allowed_methods:

            print(
                f"\nInvalid execution method: "
                f"{action.get('execution_method')}"
            )
            return False

        # Critical safety rule.
        if action.get(
            "requires_human_approval"
        ) is not True:

            print(
                "\nBLOCKED: remediation action "
                "does not require human approval."
            )
            return False

    return True
def get_google_access_token() -> str:
    """Get an ADC token using Workload Identity Federation for GKE."""
    credentials, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    credentials.refresh(Request())
    return credentials.token
async def verify_github_access() -> None:
    """Verify GitHub authentication and repository access."""

    github = GitHubClient()

    repository = await github.get_repository()

    print("\n" + "=" * 42)
    print("GITHUB ACCESS")
    print("=" * 42)

    print(f"Repository : {repository['full_name']}")
    print(f"Private    : {repository['private']}")
    print(f"Default    : {repository['default_branch']}")

def query_gke_logs(
    minutes: int = 30,
    limit: int = 10,
) -> str:
    """Return recent GKE container logs for the target namespace.

    Read-only and bounded. This deliberately does not retrieve secrets or
    arbitrary Google Cloud resources.
    """
    minutes = max(1, min(int(minutes), 30))
    limit = max(1, min(int(limit), 10))

    client = logging_v2.Client(project=PROJECT_ID)

    filter_ = (
        'resource.type="k8s_container" '
        f'AND resource.labels.namespace_name="{NAMESPACE}" '
        f'AND timestamp>="{(datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()}"'
    )

    entries = client.list_entries(
        filter_=filter_,
        order_by="timestamp desc",
        page_size=min(limit, 20),
        max_results=min(limit, 20),
    )

    output = []
    for entry in entries:
        payload = entry.payload

        if isinstance(payload, dict):
            message = payload.get("message") or str(payload)
        else:
            message = str(payload)

        output.append(
            {
                "timestamp": entry.timestamp.isoformat()
                if entry.timestamp
                else None,
                "severity": entry.severity,
                "resource": str(entry.resource),
                "message": message[:2000],
            }
        )

        if len(output) >= limit:
            break

    if not output:
        return (
            f"No GKE container logs found for namespace={NAMESPACE} "
            f"within the last {minutes} minutes."
        )

    return str(output)


def query_gke_metrics(
    metric_type: str,
    minutes: int = 30,
    limit: int = 20,
) -> str:
    """Return bounded recent Monitoring time series for an approved metric."""
    if metric_type not in ALLOWED_METRICS:
        return (
            "Rejected metric type. Allowed metric types are: "
            + ", ".join(sorted(ALLOWED_METRICS))
        )

    minutes = max(1, min(int(minutes), 120))
    limit = max(1, min(int(limit), 50))

    client = monitoring_v3.MetricServiceClient()

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=minutes)

    interval = monitoring_v3.TimeInterval(
        {
            "start_time": start_time,
            "end_time": end_time,
        }
    )

    # Namespace restriction where supported by GKE Kubernetes metrics.
    filter_ = (
        f'metric.type="{metric_type}" '
        f'AND resource.labels.namespace_name="{NAMESPACE}"'
    )

    results = client.list_time_series(
        request={
            "name": f"projects/{PROJECT_ID}",
            "filter": filter_,
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
        }
    )

    output = []
    for series in results:
        points = []
        for point in series.points[:10]:
            points.append(
                {
                    "time": point.interval.end_time.isoformat()
                    if point.interval.end_time
                    else None,
                    "value": str(point.value),
                }
            )

        output.append(
            {
                "metric": series.metric.type,
                "resource": series.resource.type,
                "labels": dict(series.resource.labels),
                "points": points,
            }
        )

        if len(output) >= limit:
            break

    if not output:
        return (
            f"No Monitoring time series found for metric={metric_type}, "
            f"namespace={NAMESPACE}, last {minutes} minutes."
        )

    return str(output)


INVESTIGATION_INSTRUCTION = f"""
You are an AI-powered Kubernetes incident triage agent.

Environment:
- GCP project: {PROJECT_ID}
- GKE cluster: {CLUSTER_PATH}
- Target namespace: {NAMESPACE}
- Vertex AI region: {VERTEX_LOCATION}

MISSION
Investigate Kubernetes incidents using evidence, not guesses.

AVAILABLE EVIDENCE SOURCES
1. GKE Remote MCP:
   - pods
   - pod logs
   - services
   - endpoints/endpointslices
   - events
   - deployments
   - replicasets
   - statefulsets
2. query_gke_logs:
   - recent Cloud Logging evidence for the target namespace
3. query_gke_metrics:
   - approved Cloud Monitoring metrics

IMPORTANT SECURITY BOUNDARIES
- You are READ-ONLY.
- Do not attempt to modify, delete, patch, update, exec into, or restart resources.
- Do not retrieve Kubernetes Secrets.
- Do not request permissions that are not available.
- Do not invent evidence.
- If a tool fails, explicitly report that limitation.
- Distinguish observed facts from hypotheses.
- Never claim a specific root cause unless evidence supports it.

INVESTIGATION METHOD
1. Discover unhealthy workloads in {NAMESPACE}.
2. Identify affected pods and their owning workloads.
3. Inspect pod state and Kubernetes events.
4. Inspect relevant pod logs when containers have started.
5. Use Cloud Logging for additional recent evidence when useful.
6. Use Cloud Monitoring only when metrics can help establish resource pressure,
   restarts, or another measurable contributing factor.
7. Correlate evidence across sources.
8. Produce a concise incident report.

EVIDENCE NORMALIZATION

For every important finding, internally classify the evidence using:

- source
- evidence_type
- workload
- pod
- timestamp
- severity
- finding
- confidence

Use these evidence types where applicable:

- pod_status
- container_status
- kubernetes_event
- deployment_status
- pod_log
- cloud_log
- metric
- configuration_reference
- image_reference

Do not invent fields when the evidence is unavailable.

For every root cause, identify the specific evidence items that support it.
INVESTIGATION ORDER

Always begin with Kubernetes/GKE evidence.

Use the GKE MCP tools first to inspect:

- unhealthy pods
- pod/container states
- deployment status
- ReplicaSets
- Services
- EndpointSlices
- Kubernetes events
- relevant workload configuration visible through allowed tools


CLOUD LOGGING POLICY

Use Cloud Logging when application/runtime logs are likely to help
determine the root cause.

Examples:

- CrashLoopBackOff
- container startup failure
- application exceptions
- HTTP/application errors
- unexpected application behavior
- repeated application failures

When querying Cloud Logging:

- restrict queries to the target namespace
- restrict queries to the affected workload or pod when possible
- use a recent time window
- request only a small number of results
- do not perform broad project-wide log searches

Do NOT query Cloud Logging when Kubernetes evidence already directly
explains the failure, such as:

- missing ServiceAccount
- missing ConfigMap key
- missing Secret
- ImagePullBackOff with an explicit image-not-found error
- scheduling failure with an explicit Kubernetes reason


CLOUD MONITORING POLICY

Use Cloud Monitoring when resource or infrastructure metrics may
explain the incident.

Examples:

- OOMKilled
- high memory utilization
- high CPU utilization
- CPU throttling
- resource saturation
- node/workload resource pressure

When querying Cloud Monitoring:

- restrict the query to the affected workload where possible
- use a recent time window
- request only relevant metrics
- do not query unrelated metrics
- do not perform broad project-wide metric searches


MULTI-SOURCE CORRELATION

Use additional evidence sources only when they can materially
increase confidence in the diagnosis.

For example:

CrashLoopBackOff
    -> inspect Kubernetes events
    -> query Cloud Logging
    -> query Monitoring only if resource pressure is suspected

OOMKilled
    -> inspect Kubernetes events
    -> query memory metrics
    -> query logs for application context if useful

ImagePullBackOff
    -> inspect Kubernetes events
    -> if explicit image NotFound/authentication error exists,
       Kubernetes evidence is sufficient


IMPORTANT RCA RULES

Do not assume that multiple unhealthy workloads have the same root cause.

Do not transfer a root cause from one workload to another without
direct evidence.

Distinguish:

- observed evidence
- inferred hypothesis
- confirmed root cause

If evidence is insufficient, explicitly state that further
investigation is required.

Never claim that Cloud Logging or Cloud Monitoring was queried
unless the corresponding tool was actually used.

Never invent log entries, metrics, timestamps, errors, or values.


OBSERVABILITY INVESTIGATION POLICY

Start every investigation with Kubernetes/GKE evidence.

Use Cloud Logging only when Kubernetes evidence indicates that
application logs can help determine the cause, such as:

- CrashLoopBackOff
- application startup failure
- HTTP/application errors
- container crashes
- unexpected application behavior

Use Cloud Monitoring when resource or platform metrics can help
determine the cause, such as:

- OOMKilled
- high memory usage
- high CPU usage
- CPU throttling
- resource saturation
- node or workload resource pressure

Do not query Cloud Logging or Cloud Monitoring unnecessarily.

Keep observability queries narrowly scoped to:

- target namespace
- affected workload/pod
- recent time window
- relevant metric or log severity

Never query unrestricted project-wide logs or metrics.

Use evidence from Cloud Logging and Cloud Monitoring only when
actually returned by the tools.

Do not claim that logs or metrics were checked if they were not queried.

STRUCTURED EVIDENCE OUTPUT

After investigating the incident, produce a machine-readable evidence
section before the human-readable report.

Use exactly this format:

STRUCTURED_EVIDENCE_START

[
  {{
    "source": "kubernetes",
    "evidence_type": "pod_status",
    "workload": "example",
    "pod": "example-pod",
    "severity": "ERROR",
    "finding": "ImagePullBackOff",
    "confidence": 1.0
  }}
]

STRUCTURED_EVIDENCE_END

Rules:

- Only include evidence actually observed from tools.
- Never invent evidence.
- Include EVERY significant independent piece of evidence that contributed
  to the root-cause determination.
- Do not summarize multiple independent findings into one record.
- Include deployment conditions when relevant.
- Include pod/container states when relevant.
- Include Kubernetes events when relevant.
- Include image pull errors when relevant.
- Include configuration errors when directly observed.
- Include service account errors when directly observed.
- Include ConfigMap or Secret errors only when directly observed.
- Include Cloud Logging evidence when actually queried.
- Include Cloud Monitoring evidence when actually queried.
- Use "kubernetes" for GKE MCP evidence.
- Use "cloud_logging" for Cloud Logging evidence.
- Use "monitoring" for Cloud Monitoring evidence.
- Keep each finding concise and factual.
- Do not include recommendations as evidence.
- Do not include assumptions as evidence.
- If evidence was not observed, do not include it.
- If a field is unavailable, omit it.

INCIDENT REPORT OUTPUT

After the structured evidence section, produce a machine-readable
incident report.

Use exactly this format:

INCIDENT_REPORT_START

{{
  "affected_workloads": [
    "example"
  ],
  "symptoms": [
    "Observed symptom from the investigation"
  ],
  "root_causes": [
    {{
      "workload": "example",
      "cause": "Root cause determined from observed evidence",
      "supporting_evidence": [
        "Evidence supporting this conclusion"
      ]
    }}
  ],
  "recommendations": [
    {{
      "workload": "example",
      "action": "Recommended remediation",
      "risk": "MEDIUM",
      "requires_approval": true
    }}
  ],
  "investigation_sources": [
    "kubernetes"
  ]
}}

INCIDENT_REPORT_END

Rules:

- Derive the report only from evidence actually observed during the
  investigation.
- Do not invent evidence.
- Do not invent logs, metrics, events, configuration, or resource state.
- Do not assume that multiple unhealthy workloads have the same root cause.
- Each root cause must identify the workload it applies to.
- Every root cause must have supporting evidence.
- If the evidence is insufficient to determine a root cause, explicitly
  state that the root cause is undetermined.
- Recommendations must be based on the observed root cause.
- Do not execute remediation.
- Do not claim that remediation was performed.
- Every recommendation must include:
  - workload
  - action
  - risk
  - requires_approval
- Use only these risk values:
  LOW
  MEDIUM
  HIGH
  CRITICAL
- investigation_sources must contain only sources actually used.

REPORT FORMAT

INCIDENT SUMMARY

AFFECTED WORKLOADS

OBSERVED EVIDENCE
- Kubernetes state
- Events
- Logs
- Metrics, if available

HYPOTHESES
- Clearly label hypotheses that are not proven.

ROOT CAUSE
- Workload:
- Root Cause:
- Supporting Evidence:
- Confidence: VERY HIGH / HIGH / MEDIUM / LOW

CONTRIBUTING FACTORS

RECOMMENDED REMEDIATION
- Read-only recommendations only.
- Do not execute remediation.

EVIDENCE → CONCLUSION
Show the evidence chain for each major root cause.
REMEDIATION PLANNING

After generating the incident report, generate a remediation plan.

Use exactly this format:

REMEDIATION_PLAN_START

{{
  "actions": [
    {{
      "workload": "example",
      "action": "Describe the proposed remediation",
      "risk": "MEDIUM",
      "requires_human_approval": true,
      "execution_method": "gitops"
    }}
  ]
}}

REMEDIATION_PLAN_END

Rules:

- Generate recommendations only from observed incident evidence.
- Never execute remediation.
- Never claim remediation was performed.
- Every action must require human approval.
- Do not generate kubectl commands intended for direct execution.
- Do not directly modify Kubernetes resources.
- Prefer GitOps-based remediation.
- execution_method must be one of:
  - gitops
  - manual
  - investigate
- Use risk values only:
  - LOW
  - MEDIUM
  - HIGH
  - CRITICAL
- If the root cause is uncertain, use "investigate".
- If remediation could cause service disruption, classify the risk appropriately.

If evidence is insufficient, say:
"Root cause could not be conclusively determined from available evidence."
Do not fill the gap with speculation.
"""


async def investigate() -> None:
    print("=" * 42)
    print("AI Kubernetes Incident Triage Agent")
    print("=" * 42)
    print(f"Project       : {PROJECT_ID}")
    print(f"Vertex Region : {VERTEX_LOCATION}")
    print(f"GKE Location  : {GKE_LOCATION}")
    print(f"Cluster       : {CLUSTER_NAME}")
    print(f"Cluster Path  : {CLUSTER_PATH}")
    print(f"MCP Endpoint  : {MCP_URL}")
    print()

    print("Obtaining Google OAuth access token...")
    token = get_google_access_token()
    print("Successfully obtained Google OAuth access token.")

    print("\nConnecting to GKE Remote MCP...")

    gke_mcp = McpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=MCP_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "x-goog-user-project": PROJECT_ID,
            },
            timeout=30,
            sse_read_timeout=60,
        )
    )

    print("GKE MCP connection configured.")
    await verify_github_access()
    APP_NAME = "incident_triage"
    USER_ID = "incident-engineer"

    agent = Agent(
        name="incident_triage_agent",
        model=MODEL,
        instruction=INVESTIGATION_INSTRUCTION,
        tools=[
            gke_mcp,
            query_gke_logs,
            query_gke_metrics,
        ],
    )

    runner = InMemoryRunner(agent=agent,app_name=APP_NAME,)

    print("\nCreating ADK session...")
    session = await runner.session_service.create_session(
        app_name=APP_NAME,
        user_id=USER_ID,
    )
    print(f"Session created: {session.id}")

    message = types.Content(
        role="user",
        parts=[
            types.Part.from_text(
                text=(
                    f"Investigate the current incident in namespace "
                    f"{NAMESPACE}. Identify unhealthy workloads and determine "
                    f"root causes using the available evidence sources."
                )
            )
        ],
    )

    print("\n" + "=" * 42)
    print("Starting Incident Investigation")
    print("=" * 42)

    try:
        response_text = []

        async for event in runner.run_async(
            user_id=USER_ID,
            session_id=session.id,
            new_message=message,
        ):
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if getattr(part, "text", None):
                        text = part.text

                        print(text)

                        response_text.append(text)
        # ==========================================================
        # STRUCTURED EVIDENCE EXTRACTION
        # ==========================================================

        full_response = "\n".join(response_text)

        # ==========================================================
        # STRUCTURED EVIDENCE
        # ==========================================================

        evidence_records = extract_structured_evidence(
            full_response
        )

        correlator = EvidenceCorrelator()

        correlator.add_many(evidence_records)

        print("\n" + "=" * 42)
        print("STRUCTURED EVIDENCE")
        print("=" * 42)

        for record in evidence_records:
            print(
                json.dumps(
                    record.to_dict(),
                    indent=2
                )
            )

        print(
            f"\nEvidence records: {len(evidence_records)}"
        )

        # ==========================================================
        # EVIDENCE CONFIDENCE
        # ==========================================================

        workloads = sorted(
            {
                record.workload
                for record in evidence_records
            }
        )

        for workload in workloads:

            workload_records = (
                correlator.get_workload_evidence(
                    workload
                )
            )

            confidence = calculate_evidence_confidence(
                workload_records
            )

            print(
                f"{workload}: "
                f"{len(workload_records)} evidence records, "
                f"confidence={confidence:.2f}"
            )

        # ==========================================================
        # AI INCIDENT REPORT
        # ==========================================================

        incident_report = extract_incident_report(
            full_response
        )

        print("\n" + "=" * 42)
        print("AI INCIDENT REPORT")
        print("=" * 42)

        if incident_report is None:

            print(
                "No incident report generated."
            )

        else:

            if validate_incident_report(
                incident_report
            ):

                incident_report["incident_id"] = (
                    f"INC-{uuid.uuid4().hex[:8].upper()}"
                )

                incident_report["namespace"] = (
                    NAMESPACE
                )

                print(
                    json.dumps(
                        incident_report,
                        indent=2
                    )
                )

            else:

                print(
                    "Incident report validation failed."
                )
        # ==========================================================
        # REMEDIATION PLAN
        # ==========================================================

        remediation_plan = extract_remediation_plan(
            full_response
        )

        print("\n" + "=" * 42)
        print("REMEDIATION PLAN")
        print("=" * 42)

        if remediation_plan is None:

            print(
                "No remediation plan generated."
            )

        elif validate_remediation_plan(
            remediation_plan
        ):
            incident_id = incident_report.get(
                "incident_id",
                f"INC-{uuid.uuid4().hex[:8].upper()}",
            )

            remediation_plan["incident_id"] = incident_id

            print(
                json.dumps(
                    remediation_plan,
                    indent=2
                )
            )

            # ==========================================================
            # GITHUB GITOPS REMEDIATION
            # ==========================================================

            print("\n" + "=" * 42)
            print("GITHUB GITOPS REMEDIATION")
            print("=" * 42)

            print(
                "Creating Pull Requests for eligible "
                "GitOps remediation actions..."
            )

            try:
                pr_results = await create_remediation_pr(
                    incident_id=incident_id,
                    remediation_plan=remediation_plan,
                )

                if not pr_results:
                    print(
                        "\nNo automated GitOps remediation "
                        "was eligible."
                    )

                for result in pr_results:
                    print(
                        "\n" + "=" * 42
                    )
                    print(
                        "REMEDIATION PR CREATED"
                    )
                    print(
                        "=" * 42
                    )

                    print(
                        f"Incident       : "
                        f"{result['incident_id']}"
                    )

                    print(
                        f"Branch         : "
                        f"{result['branch']}"
                    )

                    print(
                        f"PR Number      : "
                        f"{result['pull_request_number']}"
                    )

                    print(
                        f"Pull Request   : "
                        f"{result['pull_request_url']}"
                    )

                    print(
                        "\nACTION REQUIRED:"
                    )

                    print(
                        "Review and approve the PR "
                        "before merging."
                    )

            except Exception as exc:
                print(
                    "\nGitHub remediation failed:"
                )
                print(exc)

        else:

            print(
                "Remediation plan BLOCKED "
                "by safety validation."
            )

    finally:
        try:
            await gke_mcp.close()
        except Exception as exc:
            print(f"MCP close warning: {exc}")

    print("\nAgent investigation completed.")
    print("Agent process will remain alive for Kubernetes Deployment health.")


async def main() -> None:
    # The agent currently runs one investigation at startup.
    # Keeping the process alive prevents Kubernetes from repeatedly restarting
    # a successfully completed container.
    await investigate()

    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())