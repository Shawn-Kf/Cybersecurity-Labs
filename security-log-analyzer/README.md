# Python Security Log Analyzer & IOC Detection Tool

A Python-based security log analysis tool that parses authentication events, detects suspicious login patterns, extracts indicators of compromise (IOCs), and generates a JSON security report.

This project demonstrates foundational SOC Analyst skills, including log parsing, detection logic, input validation, automated testing, and structured reporting.

## Features

- **JSON log parsing:** Loads authentication events from a JSON file.
- **Input validation:** Checks required fields, timestamps, data types, non-empty usernames and statuses, and valid IP addresses.
- **Brute-force detection:** Identifies repeated failed login attempts from the same source IP against a single account within a configurable time window.
- **Password-spraying detection:** Identifies a source IP attempting to access multiple distinct accounts within a configurable time window.
- **Severity classification:** Assigns severity levels to detected alerts.
- **IOC extraction:** Records relevant source IP addresses as potential indicators of compromise.
- **JSON reporting:** Saves detection results to a structured report.
- **Automated tests:** Uses Python's built-in `unittest` framework to test detection, parsing, and reporting behavior.

## Project Structure

    security-log-analyzer/
    ├── data/
    │   └── authentication_events.json
    ├── reports/
    │   └── security_report.json
    ├── screenshots/
    ├── src/
    │   ├── analyzer.py
    │   ├── detector.py
    │   ├── models.py
    │   ├── parser.py
    │   ├── reporting.py
    │   └── spray_detector.py
    ├── tests/
    │   ├── test_detector.py
    │   ├── test_parser.py
    │   └── test_reporting.py
    ├── .gitignore
    └── README.md

## Requirements

- Python 3.10 or later recommended.
- No third-party Python packages are required by the core project.

## Setup

1. Open a terminal in the project directory.
2. Create a virtual environment:

       python -m venv .venv

3. Activate the environment in PowerShell:

       .\.venv\Scripts\Activate.ps1

If PowerShell prevents activation because of the execution policy, you can run the project's interpreter directly without activating the environment:

    .\.venv\Scripts\python.exe src/parser.py

## Run the Analyzer

From the `security-log-analyzer` directory, run:

    $env:PYTHONPATH = "src"
    .\.venv\Scripts\python.exe src/parser.py

The program loads the events from `data/authentication_events.json`, validates them, analyzes suspicious authentication patterns, prints detected alerts, and saves the report to `reports/security_report.json`.

## Run Automated Tests

Run the test suite from the project directory:

    $env:PYTHONPATH = "src"
    .\.venv\Scripts\python.exe -m unittest discover -s tests -v

The tests cover detection logic, event parsing and validation, and report generation. A successful run should show all discovered tests passing.

## Detection Logic

### Brute-force detection

The detector groups failed authentication events by source IP and username. By default, it flags four or more failed attempts for the same account within a 60-second window.

### Password-spraying detection

The detector looks for a source IP attempting authentication against five or more distinct accounts within a 60-second window. This can indicate password spraying, where an attacker tries a small number of passwords across multiple accounts.

The detection thresholds and time windows are rule-based and can be adjusted in the code.

### Severity and IOCs

Detected alerts are assigned severity levels by the analyzer. In the sample dataset, the brute-force alert is classified as medium severity and the password-spraying alert as high severity. The source IP associated with each alert is recorded as a potential IOC.

## Example Results

With the included sample dataset, the analyzer is expected to identify two patterns:

- **Brute force:** Source IP `192.168.1.25` targets the account `john` with four failed attempts in the configured time window.
- **Password spraying:** Source IP `192.168.1.75` targets five distinct accounts in the configured time window.

The generated report includes a generation timestamp, the total number of alerts, and the alert details. Exact output may vary if the sample data or detection rules are changed.

## Limitations

- The included authentication events are synthetic sample data, not live production logs.
- Detection is based on fixed, rule-based thresholds and may produce false positives or miss activity that falls outside those thresholds.
- The tool is a learning project and is not a replacement for a production SIEM or endpoint detection platform.
- An IP address identified by a rule is a potential IOC for investigation, not proof of malicious activity.

## Future Improvements

- Ingest additional log formats and real-world datasets.
- Add configurable detection thresholds and time windows.
- Enrich IOCs with trusted threat-intelligence sources.
- Add more detailed alert context and summary statistics.
- Integrate the analyzer with a SIEM such as Wazuh.
- Expand test coverage for edge cases and malformed input.

## Security and Data Notice

Use authorized logs and datasets only. Avoid committing sensitive authentication records, credentials, tokens, or personally identifiable information to the repository. The included sample data is intended for demonstration and testing.

## Learning Objectives

This project provides practical experience with:

- Parsing and validating structured security events.
- Implementing time-window-based detection rules.
- Identifying potential indicators of compromise.
- Producing machine-readable security reports.
- Writing automated tests for security-analysis code.
- Documenting a small security tool for a portfolio.
