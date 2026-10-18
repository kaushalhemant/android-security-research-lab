"""Retrieve an existing MobSF scan and generate assessment reports."""

import getpass
import json
import os
import subprocess
import sys
from pathlib import Path

from src.mobsf_client import MobSFAPIError, MobSFClient


ROOT = Path(__file__).resolve().parent.parent
RAW_REPORT = ROOT / "samples" / "reports" / "live_mobsf_report.json"
OUTPUT_REPORT = ROOT / "reports" / "live_security_report.md"


def main():
    # Keep the API key in this process only; never print or save it.
    original_api_key = os.environ.get("MOBSF_API_KEY")
    if not os.getenv("MOBSF_API_KEY"):
        key = getpass.getpass("MobSF API key: ")
        if not key:
            print("No API key entered.", file=sys.stderr)
            return 1
        os.environ["MOBSF_API_KEY"] = key

    try:
        client = MobSFClient()
        result = client.list_scans()
        if not isinstance(result, dict):
            print("MobSF returned an invalid scan-list response.", file=sys.stderr)
            return 1

        scans = result.get("content", [])

        if not isinstance(scans, list) or not scans:
            print("No existing scans found in MobSF.")
            return 1

        print(f"\nExisting scans: {len(scans)}")
        for index, scan in enumerate(scans, 1):
            if not isinstance(scan, dict):
                print(f"{index}. Unrecognized scan record")
                continue

            app = scan.get("APP_NAME") or "Unknown app"
            filename = scan.get("FILE_NAME") or "Unknown file"
            package = scan.get("PACKAGE_NAME") or "Unknown package"
            print(f"{index}. {app} | {filename} | {package}")

        choice = input("\nSelect a scan number: ").strip()
        if not choice.isdigit() or not 1 <= int(choice) <= len(scans):
            print("Invalid scan selection.", file=sys.stderr)
            return 1

        selected = scans[int(choice) - 1]
        if not isinstance(selected, dict):
            print("Selected scan record is invalid.", file=sys.stderr)
            return 1

        scan_hash = selected.get("MD5")
        if not isinstance(scan_hash, str) or not scan_hash.strip():
            print("Selected scan has no usable MD5 identifier.", file=sys.stderr)
            return 1

        print("\nRetrieving report from MobSF...")
        report = client.fetch_report_json(scan_hash)
        if not isinstance(report, dict):
            print("MobSF returned an invalid report response.", file=sys.stderr)
            return 1

        expected_sections = {
            "manifest_analysis",
            "code_analysis",
            "certificate_analysis",
            "network_security",
        }
        if not expected_sections.intersection(report):
            print("Response lacks expected MobSF report sections.")
            return 1

        RAW_REPORT.parent.mkdir(parents=True, exist_ok=True)
        RAW_REPORT.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        print("Generating Markdown and JSON reports...")
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "src" / "main.py"),
                str(RAW_REPORT),
                str(OUTPUT_REPORT),
            ],
            cwd=ROOT,
            check=False,
        )

        if completed.returncode != 0:
            print("Report generation failed.", file=sys.stderr)
            return completed.returncode

        print("\nWorkflow completed.")
        print(f"Markdown: {OUTPUT_REPORT.relative_to(ROOT)}")
        print(f"JSON: {OUTPUT_REPORT.with_suffix('.json').relative_to(ROOT)}")
        print("Review all findings before treating them as confirmed.")

        return 0

    except (MobSFAPIError, ValueError, OSError) as exc:
        print(f"Workflow failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if original_api_key is None:
            os.environ.pop("MOBSF_API_KEY", None)
        else:
            os.environ["MOBSF_API_KEY"] = original_api_key


if __name__ == "__main__":
    raise SystemExit(main())
