import json

from src import live_report


class FakeClient:
    def __init__(self, scans=None, report=None):
        self.scans = scans if scans is not None else []
        self.report = report if report is not None else {}
        self.requested_hash = None

    def list_scans(self):
        return {"content": self.scans}

    def fetch_report_json(self, scan_hash):
        self.requested_hash = scan_hash
        return self.report


def sample_scan():
    return {
        "APP_NAME": "TestApp",
        "FILE_NAME": "test.apk",
        "PACKAGE_NAME": "com.example.test",
        "MD5": "test-hash",
    }


def test_no_api_key_returns_without_running(monkeypatch):
    monkeypatch.delenv("MOBSF_API_KEY", raising=False)
    monkeypatch.setattr(live_report.getpass, "getpass", lambda _: "")

    assert live_report.main() == 1


def test_no_scans_returns_error(monkeypatch):
    monkeypatch.setenv("MOBSF_API_KEY", "test-key")
    monkeypatch.setattr(
        live_report, "MobSFClient", lambda: FakeClient()
    )

    assert live_report.main() == 1
    assert "MOBSF_API_KEY" in __import__("os").environ


def test_invalid_selection_does_not_fetch_report(monkeypatch):
    import os

    monkeypatch.setenv("MOBSF_API_KEY", "test-key")
    client = FakeClient(scans=[sample_scan()])
    monkeypatch.setattr(live_report, "MobSFClient", lambda: client)
    monkeypatch.setattr("builtins.input", lambda _: "abc")

    assert live_report.main() == 1
    assert client.requested_hash is None
    assert os.environ["MOBSF_API_KEY"] == "test-key"


def test_invalid_report_response_is_rejected(monkeypatch):
    import os

    monkeypatch.setenv("MOBSF_API_KEY", "test-key")
    client = FakeClient(
        scans=[sample_scan()],
        report=["not", "a", "JSON object"],
    )
    monkeypatch.setattr(live_report, "MobSFClient", lambda: client)
    monkeypatch.setattr("builtins.input", lambda _: "1")

    assert live_report.main() == 1
    assert client.requested_hash == "test-hash"
    assert os.environ["MOBSF_API_KEY"] == "test-key"


def test_successful_workflow_saves_report_and_runs_generator(
    monkeypatch, tmp_path
):
    import os
    from unittest.mock import Mock

    monkeypatch.setenv("MOBSF_API_KEY", "test-key")

    report = {
        "app_name": "TestApp",
        "package_name": "com.example.test",
        "manifest_analysis": {},
    }
    client = FakeClient(scans=[sample_scan()], report=report)
    monkeypatch.setattr(live_report, "MobSFClient", lambda: client)
    monkeypatch.setattr("builtins.input", lambda _: "1")

    # Keep temporary report paths inside the temporary project root,
    # because the workflow displays paths relative to ROOT.
    monkeypatch.setattr(live_report, "ROOT", tmp_path)
    raw_path = tmp_path / "samples" / "reports" / "raw.json"
    output_path = tmp_path / "reports" / "report.md"
    monkeypatch.setattr(live_report, "RAW_REPORT", raw_path)
    monkeypatch.setattr(live_report, "OUTPUT_REPORT", output_path)

    completed = Mock(returncode=0)
    run_mock = Mock(return_value=completed)
    monkeypatch.setattr(live_report.subprocess, "run", run_mock)

    assert live_report.main() == 0
    assert json.loads(raw_path.read_text(encoding="utf-8")) == report
    run_mock.assert_called_once()
    assert os.environ["MOBSF_API_KEY"] == "test-key"


def test_api_key_entered_at_prompt_is_removed_after_run(monkeypatch):
    import os

    monkeypatch.delenv("MOBSF_API_KEY", raising=False)
    monkeypatch.setattr(live_report.getpass, "getpass", lambda _: "test-key")
    monkeypatch.setattr(
        live_report, "MobSFClient", lambda: FakeClient()
    )

    assert live_report.main() == 1
    assert "MOBSF_API_KEY" not in os.environ
