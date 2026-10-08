import base64
import json
import os

import aiohttp
from google.cloud import secretmanager

PROJECT_ID = os.environ["GOOGLE_CLOUD_PROJECT"]
GITHUB_OWNER = os.environ["GITHUB_OWNER"]
GITHUB_REPO = os.environ["GITHUB_REPOSITORY"]
GITHUB_TOKEN_SECRET = os.environ["GITHUB_TOKEN_SECRET"]
GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


class GitHubClient:
    """Read-only GitHub repository client used for startup validation."""

    def __init__(self):
        self.owner = GITHUB_OWNER
        self.repo = GITHUB_REPO
        self.base_url = GITHUB_API.rstrip("/")

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

    async def get_repository(self) -> dict:
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self._headers()) as response:
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
