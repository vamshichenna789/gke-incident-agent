import base64
import json
import os
import re
from typing import Optional

import aiohttp
from google.cloud import secretmanager

PROJECT_ID = os.environ["GOOGLE_CLOUD_PROJECT"]
GITHUB_OWNER = os.environ["GITHUB_OWNER"]
GITHUB_REPO = os.environ["GITHUB_REPOSITORY"]
GITHUB_TOKEN_SECRET = os.environ["GITHUB_TOKEN_SECRET"]
GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
BASE_BRANCH = os.environ.get("GITHUB_BASE_BRANCH", "main")

# The adapter is intentionally deterministic. These values describe one
# known-safe GitOps transformation for the target environment.
REMEDIATION_WORKLOAD = os.environ["GITHUB_REMEDIATION_WORKLOAD"]
REMEDIATION_FILE = os.environ["GITHUB_REMEDIATION_FILE"]
REMEDIATION_ANCHOR_KEY = os.environ["GITHUB_REMEDIATION_ANCHOR_KEY"]
REMEDIATION_INSERT_LINE = os.environ["GITHUB_REMEDIATION_INSERT_LINE"]


class GitHubRemediationClient:
    """Controlled GitHub client for AI-generated GitOps remediation."""

    def __init__(self):
        self.owner = GITHUB_OWNER
        self.repo = GITHUB_REPO
        self.base_url = GITHUB_API

    def _get_token(self) -> str:
        client = secretmanager.SecretManagerServiceClient()
        secret_name = (
            f"projects/{PROJECT_ID}/secrets/{GITHUB_TOKEN_SECRET}/versions/latest"
        )
        response = client.access_secret_version(request={"name": secret_name})
        return response.payload.data.decode("utf-8").strip()

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        }

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        url = f"{self.base_url}{path}"
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method, url, headers=self._headers(), **kwargs
            ) as response:
                text = await response.text()
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    data = {"raw": text}
                if response.status >= 400:
                    raise RuntimeError(
                        f"GitHub API {response.status}: {json.dumps(data)}"
                    )
                return data

    async def get_repository(self) -> dict:
        return await self._request("GET", f"/repos/{self.owner}/{self.repo}")

    async def get_branch(self, branch: str) -> dict:
        return await self._request(
            "GET", f"/repos/{self.owner}/{self.repo}/branches/{branch}"
        )

    async def create_branch(self, branch_name: str) -> dict:
        base = await self.get_branch(BASE_BRANCH)
        return await self._request(
            "POST",
            f"/repos/{self.owner}/{self.repo}/git/refs",
            json={
                "ref": f"refs/heads/{branch_name}",
                "sha": base["commit"]["sha"],
            },
        )

    async def get_file(self, path: str, branch: str) -> tuple[str, str]:
        data = await self._request(
            "GET",
            f"/repos/{self.owner}/{self.repo}/contents/{path}",
            params={"ref": branch},
        )
        content = base64.b64decode(
            data["content"].replace("\n", "")
        ).decode("utf-8")
        return content, data["sha"]

    async def update_file(
        self,
        path: str,
        branch: str,
        content: str,
        sha: str,
        commit_message: str,
    ) -> dict:
        encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        return await self._request(
            "PUT",
            f"/repos/{self.owner}/{self.repo}/contents/{path}",
            json={
                "message": commit_message,
                "content": encoded,
                "sha": sha,
                "branch": branch,
            },
        )

    async def create_pull_request(
        self, branch: str, title: str, body: str
    ) -> dict:
        return await self._request(
            "POST",
            f"/repos/{self.owner}/{self.repo}/pulls",
            json={
                "title": title,
                "head": branch,
                "base": BASE_BRANCH,
                "body": body,
            },
        )

    async def remediate_config(self, incident_id: str) -> Optional[dict]:
        branch = f"remediation/{incident_id.lower()}"
        print(f"\nCreating GitHub branch: {branch}")
        await self.create_branch(branch)

        print(f"Reading GitOps file: {REMEDIATION_FILE}")
        content, sha = await self.get_file(REMEDIATION_FILE, branch)

        inserted_key = REMEDIATION_INSERT_LINE.split(":", 1)[0].strip()
        if re.search(
            rf"^\s*{re.escape(inserted_key)}\s*:",
            content,
            re.MULTILINE,
        ):
            print("Remediation key already exists. No GitHub change required.")
            return None

        pattern = rf"^(\s*{re.escape(REMEDIATION_ANCHOR_KEY)}\s*:.*)$"
        replacement = rf"\1\n{REMEDIATION_INSERT_LINE}"
        updated_content, count = re.subn(
            pattern,
            replacement,
            content,
            count=1,
            flags=re.MULTILINE,
        )

        if count != 1:
            raise RuntimeError(
                f"Could not safely locate remediation anchor "
                f"'{REMEDIATION_ANCHOR_KEY}' in {REMEDIATION_FILE}"
            )

        await self.update_file(
            path=REMEDIATION_FILE,
            branch=branch,
            content=updated_content,
            sha=sha,
            commit_message=f"fix({incident_id}): apply incident remediation",
        )

        pr_body = f"""## AI Incident Remediation

**Incident:** `{incident_id}`

**Workload:** `{REMEDIATION_WORKLOAD}`

**Proposed remediation:**

Apply the pre-configured deterministic GitOps change to `{REMEDIATION_FILE}`.

**Risk:** MEDIUM

**Approval:**

Human approval is required before merge.

This PR was created by the GKE Incident Triage Agent.
"""

        print("\nCreating GitHub Pull Request...")
        pr = await self.create_pull_request(
            branch=branch,
            title=f"[AI Remediation] {incident_id} - {REMEDIATION_WORKLOAD}",
            body=pr_body.strip(),
        )

        return {
            "incident_id": incident_id,
            "branch": branch,
            "pull_request_number": pr["number"],
            "pull_request_url": pr["html_url"],
        }


async def create_remediation_pr(
    incident_id: str, remediation_plan: dict
) -> list[dict]:
    """Convert only eligible, pre-configured actions into GitHub PRs."""
    github = GitHubRemediationClient()
    results = []

    for action in remediation_plan.get("actions", []):
        workload = action.get("workload")
        execution_method = action.get("execution_method")
        requires_approval = action.get("requires_human_approval")
        risk = action.get("risk")

        print("\n" + "-" * 42)
        print("REMEDIATION ELIGIBILITY")
        print("-" * 42)
        print(f"Workload            : {workload}")
        print(f"Execution method    : {execution_method}")
        print(f"Risk                : {risk}")
        print(f"Human approval      : {requires_approval}")

        if execution_method != "gitops":
            print("SKIPPED: execution method is not gitops.")
            continue
        if requires_approval is not True:
            print("BLOCKED: human approval is required.")
            continue
        if workload != REMEDIATION_WORKLOAD:
            print(
                "SKIPPED: no automated GitOps adapter is configured "
                f"for workload '{workload}'."
            )
            continue

        result = await github.remediate_config(incident_id)
        if result:
            results.append(result)

    return results
