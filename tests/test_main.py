import json

import pytest

from src.main import (
    build_markdown,
    extract_mobsf_findings,
    load_report,
    load_scan_report,
    normalise_finding,
    suggest_remediation,
)


def test_normalise_finding():
    result = normalise_finding({
        "title": "Test issue",
        "severity": "high",
        "evidence": "Example evidence",
    })
    assert result["title"] == "Test issue"
    assert result["severity"] == "high"
    assert result["evidence"] == "Example evidence"


def test_unknown_severity_is_normalised():
    result = normalise_finding({
        "title": "Unknown issue",
        "severity": "unexpected",
    })
    assert result["severity"] == "unknown"


def test_normalise_finding_rejects_non_dictionary():
    with pytest.raises(ValueError):
        normalise_finding("not a finding")


def test_load_scan_report_valid(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({
        "metadata": {"app_name": "Example"},
        "findings": [{"title": "Issue", "severity": "low"}],
    }), encoding="utf-8")

    metadata, findings = load_scan_report(path)
    assert metadata["app_name"] == "Example"
    assert len(findings) == 1


def test_load_scan_report_rejects_missing_findings(tmp_path):
    path = tmp_path / "report.json"
    path.write_text('{"metadata": {}}', encoding="utf-8")

    with pytest.raises(ValueError, match="findings"):
        load_scan_report(path)


def test_load_report_rejects_invalid_json(tmp_path):
    path = tmp_path / "report.json"
    path.write_text("{invalid", encoding="utf-8")

    with pytest.raises(ValueError, match="JSON"):
        load_report(path)


@pytest.mark.parametrize(
    ("title", "description", "rule", "expected"),
    [
        ("Debug configuration enabled", "", "debug_enabled", "Disable debugging"),
        ("Temporary file", "Sensitive data in temp file", "android_temp_file", "app-private storage"),
        ("Raw SQL query", "", "android_sql_raw_query", "parameterized SQLite queries"),
        ("External storage", "", "android_read_write_external", "shared external storage"),
        ("Sensitive logging", "", "android_logging", "Remove passwords"),
        ("Debug certificate", "", "certificate_analysis", "release signing"),
        ("Backup enabled", "", "allowBackup", "backup"),
        ("Exported component", "", "exported", "permissions"),
        ("Cleartext traffic", "", "network security", "HTTPS"),
    ],
)
def test_targeted_remediation(title, description, rule, expected):
    result = suggest_remediation(title, description, rule).lower()
    assert expected.lower() in result


def test_extract_mobsf_manifest_finding():
    report = {
        "manifest_analysis": {
            "manifest_findings": [{
                "title": "Debug configuration enabled",
                "severity": "high",
                "description": "Production build is debuggable.",
                "rule": "android_debuggable",
            }]
        }
    }

    findings = extract_mobsf_findings(report)
    assert len(findings) == 1
    assert "Disable debugging" in findings[0]["remediation"]


def test_build_markdown_contains_summary_and_limitations():
    report = {
        "metadata": {"app_name": "Example", "package_name": "org.example"},
        "findings": [{
            "title": "SQL injection",
            "severity": "high",
            "description": "Unsafe query.",
            "remediation": "Use parameterized queries.",
        }],
    }

    output = build_markdown(report)
    assert "# Android Application Security Assessment" in output
    assert "| High | 1 |" in output
    assert "Use parameterized queries." in output
    assert "## Limitations" in output


def test_build_markdown_handles_empty_findings():
    output = build_markdown({"metadata": {}, "findings": []})
    assert "No findings were extracted" in output

def test_json_report_quality_checks():
    import json
    from pathlib import Path

    report_path = Path("reports/security_report.json")
    if not report_path.exists():
        pytest.skip("Generate the JSON report first with: python src/main.py")

    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings = data["findings"]

    assert data["finding_count"] == len(findings)
    assert len(findings) == 14

    required_fields = {
        "title", "severity", "description", "evidence", "remediation"
    }
    for finding in findings:
        assert required_fields.issubset(finding.keys())


def test_json_report_severity_counts():
    import json
    from pathlib import Path

    report_path = Path("reports/security_report.json")
    if not report_path.exists():
        pytest.skip("Generate the JSON report first with: python src/main.py")

    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings = data["findings"]

    assert sum(f["severity"] == "high" for f in findings) == 5
    assert sum(f["severity"] == "warning" for f in findings) == 7
    assert sum(f["severity"] == "info" for f in findings) == 2


def test_main_exports_top_level_mobsf_metadata(tmp_path, monkeypatch):
    import json
    import sys
    from pathlib import Path
    from src.main import main

    root = Path(__file__).resolve().parents[1]
    source = root / "samples" / "reports" / "live_mobsf_report.json"

    if not source.exists():
        pytest.skip("Live MobSF report is not available locally.")

    output = tmp_path / "assessment.md"
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", str(source), str(output)],
    )

    assert main() == 0

    exported = json.loads(output.with_suffix(".json").read_text())
    assert exported["application"] == "Diva"
    assert exported["package_name"] == "jakhar.aseem.diva"


def test_build_markdown_uses_defaults_for_missing_metadata():
    output = build_markdown({
        "findings": [{
            "title": "Example finding",
            "severity": "high",
            "description": "Example description",
        }]
    })

    assert "**Application:** Not provided" in output
    assert "**Package:** Not provided" in output
    assert "### 1. Example finding" in output


def test_build_markdown_counts_unknown_severity_correctly():
    output = build_markdown({
        "metadata": {"app_name": "Test"},
        "findings": [{
            "title": "Unclassified issue",
            "severity": "unexpected-value",
        }]
    })

    assert "### 1. Unclassified issue" in output
    assert "- **Severity:** Unknown" in output
    assert "| Unknown | 1 |" in output


def test_build_markdown_generates_fallback_remediation():
    output = build_markdown({
        "findings": [{
            "title": "Debug configuration enabled",
            "severity": "high",
        }]
    })

    assert "**Suggested remediation**" in output
    assert "Disable debugging in production builds" in output
