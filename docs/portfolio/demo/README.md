# Android Security Report Automation — Lab Demonstration

## Purpose
This demonstration shows a Python workflow that converts a MobSF-style
Android security scan report into a structured Markdown assessment report.

## Test application
DIVA — an intentionally vulnerable Android application used for security
training. This is a lab demonstration, not a client assessment.

## What the workflow demonstrates
- Extraction and normalization of scanner findings
- Severity summaries and structured evidence
- Draft remediation guidance
- A report format suitable for review by a security assessor

## Important limitations
- Scanner output can contain false positives and false negatives.
- Similar findings are not necessarily duplicates or independently
  exploitable vulnerabilities.
- Remediation suggestions require technical review.
- This report does not establish exploitability or certify application
  security.
- No client application or client report should be used in this demo.

## Reproduce locally
From the project root, run:

    python src/main.py samples/reports/mobsf_report.json reports/security_report.md

The generated Markdown report is written to reports/security_report.md.

## Project status
Research prototype. This demonstration illustrates report processing;
it is not a substitute for manual mobile application penetration testing.
