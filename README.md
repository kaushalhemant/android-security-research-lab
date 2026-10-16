# Android Research Lab

A local Python tool for normalising Android application security scan
findings and generating Markdown and JSON assessment reports.

## Project goals

- Import authorised Android security scanner reports.
- Normalise findings into a consistent structure.
- Preserve severity, evidence, descriptions, and remediation guidance.
- Generate human-readable Markdown and machine-readable JSON reports.
- Use automated tests to improve report reliability.

## Current capabilities

- MobSF-style report parsing.
- Finding extraction and severity sorting.
- Suggested remediation for common Android security issues.
- Markdown report generation.
- JSON report export.
- Automated tests for parsing, remediation, and report quality.

## Requirements

- Python 3.10 or newer.
- The Python packages used by the project tests.
- An authorised scanner report in a supported format.

The project can generate reports from its included sample scan data without
running a new APK scan.

## Setup

Clone or copy this repository, then enter the project directory:

```bash
cd ~/android-research-lab
```

Activate the existing virtual environment:

```bash
source .venv/bin/activate
```

Run the automated tests:

```bash
python -m pytest -q
```

## Usage

Generate reports using the included MobSF-style sample:

```bash
python src/main.py
```

Default input:

`samples/reports/mobsf_report.json`

Default Markdown output:

`reports/security_report.md`

Default JSON output:

`reports/security_report.json`

To specify a different input report and Markdown output path:

```bash
python src/main.py path/to/input_report.json reports/custom_report.md
```

The JSON output is written to the same output path with a `.json` extension.

Validate the JSON output:

```bash
python -m json.tool reports/security_report.json
```

## Project layout

```text
android-research-lab/
├── docs/
├── reports/
├── samples/
│   ├── apk/
│   └── reports/
├── src/
│   └── main.py
├── tests/
│   └── test_main.py
└── README.md
```

## Limitations

- Automated scanner findings can contain false positives and false negatives.
- Suggested remediation is guidance, not proof that a vulnerability is fixed.
- Findings must be validated against the application, evidence, and relevant
  source code or runtime behaviour.
- A generated report is a draft until reviewed by a qualified assessor.
- The current tool does not replace a complete mobile application security
  assessment.

## Responsible use

- Test only applications you own or have explicit permission to assess.
- Use intentionally vulnerable applications only in an isolated lab.
- Protect APKs, scan reports, credentials, and client evidence.
- Do not claim exploitability without appropriate validation.

## Development status

Research prototype. Report extraction, remediation, and output quality are
being improved iteratively.

## License

No license has been specified yet. Do not assume the project is licensed for
redistribution or commercial reuse until a license is added.
