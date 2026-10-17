"""Small client for retrieving reports from a local MobSF instance."""

import os
from urllib.parse import urljoin

import requests


class MobSFAPIError(RuntimeError):
    """Raised when a MobSF API request fails."""


class MobSFClient:
    def __init__(self, base_url=None, api_key=None, timeout=20, session=None):
        self.base_url = (
            base_url or os.getenv("MOBSF_BASE_URL", "http://127.0.0.1:8000")
        ).rstrip("/") + "/"

        self.api_key = api_key or os.getenv("MOBSF_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Set MOBSF_API_KEY in your environment before using the client."
            )

        self.timeout = timeout
        self.session = session or requests.Session()

    def _request(self, method, endpoint, *, params=None, data=None):
        url = urljoin(self.base_url, endpoint.lstrip("/"))

        try:
            response = self.session.request(
                method,
                url,
                headers={"Authorization": self.api_key},
                params=params,
                data=data,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise MobSFAPIError(
                f"Could not connect to MobSF: {type(exc).__name__}"
            ) from exc

        if not 200 <= response.status_code < 300:
            raise MobSFAPIError(
                f"MobSF API returned HTTP {response.status_code}."
            )

        try:
            result = response.json()
        except ValueError as exc:
            raise MobSFAPIError("MobSF returned invalid JSON.") from exc

        if not isinstance(result, dict):
            raise MobSFAPIError("Expected a JSON object from MobSF.")

        return result

    def list_scans(self, page=1, page_size=10):
        """List existing scans without starting a new scan."""
        if page < 1 or page_size < 1:
            raise ValueError("page and page_size must be positive integers.")

        return self._request(
            "GET",
            "/api/v1/scans",
            params={"page": page, "page_size": page_size},
        )

    def fetch_report_json(self, scan_hash):
        """Retrieve the JSON report for an existing scan hash."""
        if not isinstance(scan_hash, str) or not scan_hash.strip():
            raise ValueError("A non-empty scan hash is required.")

        return self._request(
            "POST",
            "/api/v1/report_json",
            data={"hash": scan_hash.strip()},
        )
