import pytest
import requests

from src.mobsf_client import MobSFAPIError, MobSFClient


class FakeResponse:
    def __init__(self, status_code=200, payload=None, invalid_json=False):
        self.status_code = status_code
        self.payload = payload or {}
        self.invalid_json = invalid_json

    def json(self):
        if self.invalid_json:
            raise ValueError("Invalid JSON")
        return self.payload


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse(payload={"content": []})
        self.error = error
        self.call = None

    def request(self, method, url, **kwargs):
        self.call = (method, url, kwargs)
        if self.error:
            raise self.error
        return self.response


def test_client_requires_api_key(monkeypatch):
    monkeypatch.delenv("MOBSF_API_KEY", raising=False)

    with pytest.raises(ValueError, match="MOBSF_API_KEY"):
        MobSFClient()


def test_list_scans_uses_authenticated_get():
    session = FakeSession(
        response=FakeResponse(payload={"content": [], "count": 0})
    )
    client = MobSFClient(api_key="test-key", session=session)

    result = client.list_scans()

    method, url, kwargs = session.call
    assert method == "GET"
    assert url == "http://127.0.0.1:8000/api/v1/scans"
    assert kwargs["headers"]["Authorization"] == "test-key"
    assert kwargs["params"] == {"page": 1, "page_size": 10}
    assert result["count"] == 0


def test_fetch_report_json_posts_hash():
    session = FakeSession(
        response=FakeResponse(payload={"package_name": "example.app"})
    )
    client = MobSFClient(api_key="test-key", session=session)

    result = client.fetch_report_json("abc123")

    method, url, kwargs = session.call
    assert method == "POST"
    assert url == "http://127.0.0.1:8000/api/v1/report_json"
    assert kwargs["data"] == {"hash": "abc123"}
    assert result["package_name"] == "example.app"


def test_http_error_does_not_include_api_key():
    session = FakeSession(response=FakeResponse(status_code=401))
    client = MobSFClient(api_key="private-test-key", session=session)

    with pytest.raises(MobSFAPIError, match="401") as error:
        client.list_scans()

    assert "private-test-key" not in str(error.value)


def test_invalid_scan_hash_is_rejected():
    client = MobSFClient(api_key="test-key", session=FakeSession())

    with pytest.raises(ValueError, match="scan hash"):
        client.fetch_report_json("  ")


def test_network_error_is_handled():
    session = FakeSession(error=requests.ConnectionError("offline"))
    client = MobSFClient(api_key="test-key", session=session)

    with pytest.raises(MobSFAPIError, match="Could not connect"):
        client.list_scans()
