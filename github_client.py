import base64
import json
import os
from typing import Optional

import aiohttp
from google.cloud import secretmanager


PROJECT_ID = os.environ["GOOGLE_CLOUD_PROJECT"]

GITHUB_OWNER = "vamshichenna789"
GITHUB_REPO = "cymbal-bank-gitops"
GITHUB_TOKEN_SECRET = "github-token"


class GitHubClient:
    def __init__(self):
        self.base_url = "https://api.github.com"

    def _get_token(self) -> str:
        client = secretmanager.SecretManagerServiceClient()

        name = (
            f"projects/{PROJECT_ID}/secrets/"
            f"{GITHUB_TOKEN_SECRET}/versions/latest"
        )

        response = client.access_secret_version(
            request={"name": name}
        )

        return response.payload.data.decode("utf-8")

    def _headers(self) -> dict:
        token = self._get_token()

        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def get_repository(self) -> dict:
        url = (
            f"{self.base_url}/repos/"
            f"{GITHUB_OWNER}/{GITHUB_REPO}"
        )

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers=self._headers(),
            ) as response:

                data = await response.json()

                if response.status != 200:
                    raise RuntimeError(
                        f"GitHub API error {response.status}: "
                        f"{json.dumps(data)}"
                    )

                return data
