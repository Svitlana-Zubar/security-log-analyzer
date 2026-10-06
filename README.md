# Security Log Analyzer

A Python-based security monitoring tool that parses SSH authentication logs and detects suspicious login activity using rule-based detection.

The analyzer identifies brute-force attacks, successful logins following repeated authentication failures, and attempts to target multiple user accounts from the same IP address. Detected events are assigned severity levels and exported as a structured JSON security report.

## Features

- Parses SSH authentication logs into structured security events
- Detects brute-force login attempts within defined time windows
- Identifies successful logins following repeated authentication failures
- Detects attempts to access multiple user accounts from a single IP address
- Assigns severity levels to detected security events
- Generates structured JSON security reports
- Includes automated tests for detection logic and edge cases
- Maps applicable detections to MITRE ATT&CK techniques
- Supports command-line arguments for custom input and output files

## Detection Rules

| Detection | Condition | Severity |
|---|---|---|
| Brute Force | 5 failed login attempts from the same IP within 2 minutes | HIGH |
| Successful Login After Failures | 3 or more failed attempts followed by a successful login within 5 minutes | HIGH |
| Multiple Accounts Targeted | Failed login attempts against 3 or more unique accounts from the same IP within 5 minutes | MEDIUM |

## Project Structure

```text
security_log_analyzer/
├── main.py                 # Application entry point
├── parser.py               # Parses SSH authentication logs
├── detector.py             # Security detection rules
├── reporter.py             # Aggregates alerts and generates JSON reports
├── logs/
│   └── sample_auth.log     # Synthetic SSH authentication log data
├── reports/
│   └── .gitkeep
├── test/
│   └── test_detector.py    # Automated tests for detection rules
├── .gitignore
├── requirements.txt
└── README.md
```
## Installation

Clone the repository:

```bash
git clone git@github.com:Svitlana-Zubar/security-log-analyzer.git
cd security-log-analyzer
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

## Usage

Run the analyzer by providing the path to an SSH authentication log file:

```bash id="hzc1q6"
python main.py logs/sample_auth.log
```

By default, the generated security report is saved to:

```text id="92tb5x"
reports/security_report.json
```

To specify a custom output file, use the `--output` option:

```bash id="sq2b9y"
python main.py logs/sample_auth.log --output reports/custom_report.json
```

To view the available command-line options:

```bash id="j2o35k"
python main.py --help
```

After analysis, the CLI displays the number of detected security alerts and the location of the generated report.

```bash
python main.py
```

The analyzer reads the sample SSH authentication log from:

```text
logs/sample_auth.log
```

Detected security events are written to:

```text
reports/security_report.json
```

## Testing

Run the automated test suite with:

```bash
python -m pytest
```

The test suite covers positive and negative detection scenarios, including threshold and time-window edge cases.

## Example Alert

```json
{
    "type": "brute_force",
    "severity": "HIGH",
    "ip_address": "192.168.1.50",
    "attempts": 5,
    "start_time": "2026-09-29 10:05:12",
    "end_time": "2026-09-29 10:06:04",
    "mitre_attack": {
      "technique_id": "T1110",
      "technique": "Brute Force"
    }
}
```

## Future Improvements

- Make detection thresholds and time windows configurable
- Support additional authentication log formats
- Add logging and improved error handling
- Expand automated test coverage