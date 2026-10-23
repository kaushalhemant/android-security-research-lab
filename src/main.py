import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT / "samples" / "reports" / "mobsf_report.json"
DEFAULT_OUTPUT = ROOT / "reports" / "security_report.md"

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "warning": 2,
    "low": 3,
    "info": 4,
    "secure": 5,
    "unknown": 6,
}


def normalise_finding(finding):
    """Normalize a finding into a consistent internal format."""
    if not isinstance(finding, dict):
        raise ValueError("Each finding must be a JSON object.")

    title = finding.get("title") or finding.get("name") or "Untitled finding"
    raw_severity = str(finding.get("severity", "unknown")).strip().lower()
    severity = raw_severity if raw_severity in SEVERITY_ORDER else "unknown"

    return {
        "title": str(title),
        "severity": severity,
        "source_severity": raw_severity,
        "description": str(finding.get("description") or ""),
        "evidence": str(finding.get("evidence") or ""),
        "confidence": str(finding.get("confidence") or "Not provided"),
        "remediation": str(finding.get("remediation") or ""),
        "status": str(finding.get("status") or "Needs review"),
    }


def load_scan_report(path):
    """Load the simple custom JSON format used by the original tests."""
    try:
        with Path(path).open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not load JSON report: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("The report must be a JSON object.")

    findings = data.get("findings")
    if not isinstance(findings, list):
        raise ValueError("'findings' must be a JSON list.")

    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    return metadata, findings


def load_report(path):
    """Load either a custom findings report or a MobSF JSON report."""
    try:
        with Path(path).open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not load JSON report: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("The report must be a JSON object.")

    if "findings" in data:
        if not isinstance(data["findings"], list):
            raise ValueError("'findings' must be a JSON list.")
        return data

    mobsf_sections = {
        "manifest_analysis",
        "code_analysis",
        "certificate_analysis",
        "network_security",
    }
    if mobsf_sections.intersection(data):
        return data

    raise ValueError(
        "Unrecognized report format: expected 'findings' or MobSF sections."
    )


def suggest_remediation(title, description="", rule=""):
    """Provide starting-point remediation for recognized Android findings."""
    text = f"{title} {description} {rule}".lower()

    if any(term in text for term in (
        "debuggable", "debug configuration enabled", "debug_enabled"
    )):
        return (
            "Disable debugging in production builds. Use a release build "
            "variant, inspect the final merged manifest, and verify that "
            "debug-only settings are absent from the distributed APK."
        )

    if any(term in text for term in (
        "temp file", "temporary file", "android_temp_file"
    )):
        return (
            "Avoid writing sensitive information to temporary files. If "
            "temporary files are necessary, use app-private storage, restrict "
            "access, minimize retention, and remove files when no longer needed."
        )

    if any(term in text for term in (
        "sql", "raw query", "injection", "cwe-89"
    )):
        return (
            "Use parameterized SQLite queries or selection arguments instead "
            "of concatenating untrusted input into SQL. Review affected "
            "database queries and content-provider operations."
        )

    if any(term in text for term in (
        "external storage", "read_write_external", "android_read_write_external"
    )):
        return (
            "Avoid storing sensitive application data in shared external "
            "storage. Prefer app-private internal storage or another suitable "
            "protected storage mechanism."
        )

    if any(term in text for term in (
        "logging", "logcat", "android_logging", "cwe-532",
        "sensitive information into log"
    )):
        return (
            "Remove passwords, authentication tokens, personal information, "
            "and other sensitive values from logs. Disable verbose logging in "
            "production and review the affected logging statements."
        )

    if any(term in text for term in (
        "debug certificate", "signed with debug", "certificate_analysis"
    )):
        return (
            "Verify the release APK signing configuration. Use the intended "
            "release signing process, protect signing credentials, and confirm "
            "the certificate and signature schemes meet release requirements."
        )

    if any(term in text for term in (
        "allowbackup", "android:allowbackup", "backup"
    )):
        return (
            "Review whether application data needs backup. Configure Android "
            "backup and data-extraction rules for supported Android versions, "
            "and test backup and restore behaviour."
        )

    if any(term in text for term in (
        "exported", "not protected", "incorrect default permissions",
        "cwe-276"
    )):
        return (
            "Review whether the component or file must be accessible to other "
            "apps. Restrict access where appropriate, enforce permissions, "
            "and validate incoming intents and data."
        )

    if any(term in text for term in (
        "cleartext", "network security", "http traffic"
    )):
        return (
            "Prefer HTTPS and disable cleartext traffic where feasible. Review "
            "the network security configuration against the app's actual "
            "communication requirements."
        )

    if any(term in text for term in (
        "minimum sdk", "minsdk", "vulnerable_os_version", "unpatched android"
    )):
        return (
            "Review the minimum supported Android API level against security "
            "and compatibility requirements. Raise it when justified, test "
            "supported devices, and document any legacy support exceptions."
        )

    return (
        "Review the finding and affected code, verify whether the issue "
        "applies to the release build, and implement a fix appropriate to "
        "the application's architecture."
    )


def _as_text(value):
    """Convert simple values to readable text without failing on JSON types."""
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def extract_mobsf_findings(report):
    """Extract findings from common MobSF JSON report sections."""
    findings = []

    def add(title, severity, description="", evidence="", remediation=""):
        finding = normalise_finding({
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "remediation": remediation,
        })
        if not finding["remediation"]:
            finding["remediation"] = suggest_remediation(
                finding["title"], finding["description"], finding["evidence"]
            )
        findings.append(finding)

    # Manifest findings
    manifest = report.get("manifest_analysis", {})
    if isinstance(manifest, dict):
        for item in manifest.get("manifest_findings", []):
            if not isinstance(item, dict):
                continue
            title = item.get("title") or item.get("name") or "Manifest finding"
            description = _as_text(item.get("description"))
            rule = _as_text(item.get("rule"))
            component = item.get("component", [])
            evidence = f"Rule: {rule or 'N/A'}"
            if component:
                evidence += f"; Component: {_as_text(component)}"
            add(
                title,
                item.get("severity", "info"),
                description,
                evidence,
                suggest_remediation(title, description, rule),
            )

    # Code analysis findings
    code_analysis = report.get("code_analysis", {})
    if isinstance(code_analysis, dict):
        code_findings = code_analysis.get("findings", {})

        if isinstance(code_findings, dict):
            for rule_name, details in code_findings.items():
                if not isinstance(details, dict):
                    continue

                metadata = details.get("metadata", {})
                if not isinstance(metadata, dict):
                    metadata = {}

                title = (
                    metadata.get("title")
                    or str(rule_name).replace("_", " ").capitalize()
                )
                description = _as_text(metadata.get("description"))
                severity = metadata.get("severity", "info")

                evidence_lines = [f"Rule: {rule_name}"]
                files = details.get("files", {})

                if isinstance(files, dict):
                    evidence_lines.append("Affected files and lines:")
                    for filename, line_numbers in files.items():
                        evidence_lines.append(
                            f"- {filename}: {_as_text(line_numbers)}"
                        )
                elif isinstance(files, list):
                    evidence_lines.append("Affected files and lines:")
                    for entry in files:
                        evidence_lines.append(f"- {_as_text(entry)}")

                for key in ("cwe", "owasp-mobile", "masvs", "cvss", "ref"):
                    if metadata.get(key):
                        evidence_lines.append(
                            f"{key}: {_as_text(metadata[key])}"
                        )

                evidence = "\n".join(evidence_lines)

                add(
                    title,
                    severity,
                    description,
                    evidence,
                    suggest_remediation(title, description, rule_name),
                )

    # Certificate findings may be dictionaries or MobSF-style lists.
    certificate = report.get("certificate_analysis", {})
    if isinstance(certificate, dict):
        cert_findings = certificate.get("certificate_findings", [])
        if isinstance(cert_findings, list):
            for item in cert_findings:
                if isinstance(item, dict):
                    title = item.get("title") or item.get("name") or "Certificate finding"
                    severity = item.get("severity", "info")
                    description = _as_text(item.get("description"))
                    evidence = _as_text(item.get("evidence"))
                    add(
                        title, severity, description, evidence,
                        suggest_remediation(title, description, "certificate_analysis"),
                    )
                elif isinstance(item, (list, tuple)):
                    values = list(item) + ["", "", ""]
                    severity, description, title = values[:3]
                    title = title or "Certificate finding"
                    add(
                        title, severity or "info", _as_text(description), "",
                        suggest_remediation(title, _as_text(description), "certificate_analysis"),
                    )

    # Network security findings
    network = report.get("network_security", {})
    if isinstance(network, dict):
        network_findings = network.get("network_findings", [])
        if isinstance(network_findings, list):
            for item in network_findings:
                if not isinstance(item, dict):
                    continue
                title = item.get("title") or item.get("name") or "Network security finding"
                description = _as_text(item.get("description"))
                rule = _as_text(item.get("rule"))
                add(
                    title,
                    item.get("severity", "info"),
                    description,
                    f"Rule: {rule or 'N/A'}",
                    suggest_remediation(title, description, rule),
                )

    return findings


def _markdown_text(value):
    """Keep generated Markdown readable and avoid accidental raw HTML blocks."""
    return _as_text(value).replace("\r\n", "\n").strip()




def find_duplicate_candidates(findings):
    """Return possible duplicate finding pairs for human review."""
    import re
    from difflib import SequenceMatcher

    def normalize(value):
        value = str(value or "").lower()
        value = re.sub(r"[^a-z0-9]+", " ", value)
        return " ".join(value.split())

    def components(title):
        # Capture Android component class names such as APICredsActivity.
        pattern = r"\b[A-Za-z_$][A-Za-z0-9_$]*(?:Activity|Service|Receiver|Provider)\b"
        return set(re.findall(pattern, str(title or "")))

    normalized = []
    for finding in findings:
        item = normalise_finding(finding)
        normalized.append({
            "title": normalize(item["title"]),
            "description": normalize(item["description"]),
            "components": components(item["title"]),
        })

    candidates = []
    for i, first in enumerate(normalized):
        for j in range(i + 1, len(normalized)):
            second = normalized[j]

            same_title = first["title"] == second["title"]
            similar_title = (
                SequenceMatcher(None, first["title"], second["title"]).ratio()
                >= 0.90
            )
            same_description = (
                bool(first["description"])
                and first["description"] == second["description"]
            )

            different_components = (
                bool(first["components"])
                and bool(second["components"])
                and first["components"].isdisjoint(second["components"])
            )

            if different_components:
                continue

            if same_title or similar_title or same_description:
                candidates.append({
                    "first_index": i,
                    "second_index": j,
                    "first_title": (
                        findings[i].get("title")
                        or findings[i].get("name")
                        or "Untitled finding"
                    ),
                    "second_title": (
                        findings[j].get("title")
                        or findings[j].get("name")
                        or "Untitled finding"
                    ),
                    "reason": (
                        "same normalized title" if same_title
                        else "very similar titles" if similar_title
                        else "same normalized description"
                    ),
                    "review_required": True,
                })

    return candidates


def build_markdown(report):
    """Build a Markdown security report from a custom or MobSF JSON report."""
    if "findings" in report:
        metadata = report.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        findings = [normalise_finding(item) for item in report["findings"]]
    else:
        metadata = {
            "app_name": report.get("app_name") or report.get("file_name") or "Unknown app",
            "package_name": report.get("package_name") or "Not provided",
        }
        findings = extract_mobsf_findings(report)

    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 99),
            item["title"].lower(),
        )
    )

    lines = [
        "# Android Application Security Assessment",
        "",
        f"- **Application:** {_markdown_text(metadata.get('app_name') or metadata.get('application') or 'Not provided')}",
        f"- **Package:** {_markdown_text(metadata.get('package_name') or 'Not provided')}",
        f"- **Assessment status:** Draft; findings require validation",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]

    for severity in SEVERITY_ORDER:
        count = sum(1 for item in findings if item["severity"] == severity)
        if count:
            lines.append(f"| {severity.title()} | {count} |")

    lines.extend(["", "## Findings", ""])

    if not findings:
        lines.extend(["No findings were extracted from the supplied report.", ""])

    for index, item in enumerate(findings, start=1):
        lines.extend([
            f"### {index}. {_markdown_text(item['title'])}",
            "",
            f"- **Severity:** {item['severity'].title()}",
            f"- **Status:** {_markdown_text(item['status'])}",
            f"- **Confidence:** {_markdown_text(item['confidence'])}",
            "",
        ])

        if item["description"]:
            lines.extend(["**Description**", "", _markdown_text(item["description"]), ""])

        if item["evidence"]:
            lines.extend([
                "**Evidence**",
                "",
                "```text",
                _markdown_text(item["evidence"]),
                "```",
                "",
            ])

        lines.extend([
            "**Suggested remediation**",
            "",
            _markdown_text(item["remediation"] or suggest_remediation(
                item["title"], item["description"], item["evidence"]
            )),
            "",
            "---",
            "",
        ])

    lines.extend([
        "## Limitations",
        "",
        "- Automated findings may contain false positives or miss vulnerabilities.",
        "- Validate findings against source code, application behaviour, and the release APK.",
        "- Confirm remediation with retesting before marking an issue as resolved.",
        "- Suggested remediation is a starting point, not a substitute for developer review.",
        "",
    ])

    return "\n".join(lines)


def main():
    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUTPUT

    try:
        report = load_report(input_path)
        markdown = build_markdown(report)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8")

        json_output_path = output_path.with_suffix(".json")
        metadata = report.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        if "findings" in report and isinstance(report["findings"], list):
            findings = [
                normalise_finding(item)
                for item in report["findings"]
                if isinstance(item, dict)
            ]
        else:
            findings = extract_mobsf_findings(report)

        findings.sort(
            key=lambda item: (
                SEVERITY_ORDER.get(item["severity"], 99),
                item["title"].lower(),
            )
        )

        json_data = {
            "application": (
                metadata.get("app_name")
                or metadata.get("application")
                or report.get("app_name")
                or report.get("APP_NAME")
                or "Not provided"
            ),
            "package_name": (
                metadata.get("package_name")
                or report.get("package_name")
                or report.get("PACKAGE_NAME")
                or "Not provided"
            ),
            "assessment_status": "Draft; findings require validation",
            "finding_count": len(findings),
            "findings": findings,
        }
        json_output_path.write_text(
            json.dumps(json_data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Report generated: {output_path}")
    print(f"Input: {input_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
