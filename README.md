# LogSentinel

LogSentinel is a personal Python project for analysing Linux SSH authentication logs and detecting suspicious activity through configurable, rule-based detection.

The project provides a hands-on environment for exploring Linux log processing, detection engineering, automated testing, containerisation, and software reliability.

> **Status:** v0.1 — Functional prototype with two detection rules, a command-line interface, automated tests, Docker support, and GitHub Actions CI.

## Current Features

- Parse SSH authentication logs containing successful and failed password attempts.
- Convert valid log entries into structured `SecurityEvent` objects.
- Validate IPv4 and IPv6 source addresses.
- Skip malformed or unsupported log entries.
- Group failed authentication attempts by source IP.
- Detect suspicious activity using configurable thresholds and sliding time windows.
- Generate alerts through two detection rules: **LS-001** and **LS-002**.
- Produce summary reports of authentication activity.
- Analyse log files through a command-line interface (CLI).
- Run automated tests with pytest.
- Execute the application in a Docker container.
- Run automated tests automatically through GitHub Actions.

## Detection Rules

### LS-001 — Multi-Account Targeting

Detects failed SSH authentication attempts targeting multiple unique user accounts from the same source IP within a configurable time window.

**Default configuration:**
- Minimum unique users: **3**
- Time window: **60 seconds**

**Example:**

```text
10:00:00  203.0.113.42  admin  FAILED
10:00:10  203.0.113.42  root   FAILED
10:00:20  203.0.113.42  guest  FAILED
```

This activity meets the default LS-001 detection threshold.

### LS-002 — Repeated Failed Logins

Detects repeated failed SSH authentication attempts originating from the same source IP within a configurable time window.

**Default configuration:**
- Minimum failed attempts: **5**
- Time window: **60 seconds**

Unlike LS-001, this rule does not require attempts against multiple user accounts.

> **Note:** Both rules identify potentially suspicious behaviour. An alert does not, by itself, confirm an attack or system compromise.

## Architecture

```text
SSH Authentication Logs
          |
          v
      Log Parser
          |
          v
    SecurityEvent
          |
          +------------------+
          |                  |
          v                  v
   Detection Engine     Reporting
      /       \              |
     v         v             v
  LS-001     LS-002     Summary Report
     \         /
      v       v
   SecurityAlert
          |
          v
      CLI Output
```

The application separates log parsing, event models, detection rules, configuration, reporting, and CLI execution into individual Python modules.

## Project Structure

```text
logsentinel/
├── .github/
│   └── workflows/
│       └── tests.yml
├── data/
│   └── security.log
├── src/
│   └── logsentinel/
│       ├── __init__.py
│       ├── config.py
│       ├── detection.py
│       ├── main.py
│       ├── models.py
│       ├── parser.py
│       └── reporting.py
├── tests/
│   ├── test_cli.py
│   ├── test_config.py
│   ├── test_detection.py
│   └── test_parser.py
├── .dockerignore
├── .gitignore
├── Dockerfile
└── README.md
```

## Running LogSentinel

### Requirements

- Python 3.11 (used in CI)
- pytest for automated testing
- Docker (optional)

### Local Execution

From the project root, create and activate a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the test dependency:

```bash
python -m pip install pytest
```

Run LogSentinel using the included sample data:

```bash
python -m src.logsentinel.main
```

Or specify an input log file:

```bash
python -m src.logsentinel.main --input data/security.log
```

Display available CLI options:

```bash
python -m src.logsentinel.main --help
```

## Example Output

Running LogSentinel with the included sample dataset produces:

```text
Detected alerts:

SecurityAlert(rule_id='LS-001', source_ip='203.0.113.42', ...)
SecurityAlert(rule_id='LS-002', source_ip='203.0.113.42', ...)

================================
       LOGSENTINEL v0.1
================================

Total events: 15
Failed logins: 13
Successful logins: 2
```

The report also includes failed authentication counts by targeted username and source IP.

## Automated Testing

LogSentinel uses **pytest** to validate parsing, detection, configuration, and CLI behaviour.

Run the test suite:

```bash
python -m pytest -q
```

**Current test results: 25 tests passing.**

The test suite covers:

- SSH authentication log parsing.
- Invalid and malformed input handling.
- IPv4 and IPv6 validation.
- Detection thresholds and time windows.
- Configuration validation.
- CLI execution and input handling.

## Continuous Integration (CI)

GitHub Actions automatically executes the test suite on:

- Every push.
- Every pull request.

The workflow uses:

- Ubuntu (`ubuntu-latest`)
- Python 3.11
- pytest

**Workflow:** `.github/workflows/tests.yml`

## Docker

LogSentinel can be executed inside a Docker container.

### Build the Image

```bash
docker build -t logsentinel:0.1 .
```

### Run the Container

```bash
docker run --rm logsentinel:0.1
```

The Docker image uses **Python 3.14-slim** and includes the application source code and sample dataset.

## Current Limitations

LogSentinel is an early-stage engineering project with several known limitations:

- SSH log parsing supports a limited set of password authentication formats.
- The parser currently assigns the year **2024** to timestamps.
- Unsupported and malformed log entries are skipped rather than stored for further inspection.
- Detection thresholds are configurable in Python code but are not yet exposed through external configuration files or CLI arguments.
- Alerts are printed locally rather than exported as structured records.
- Log ingestion is file-based rather than continuous or real-time.
- The project is not a distributed monitoring system.

## Roadmap

Planned improvements include:

1. More robust SSH log parsing and timestamp handling.
2. External configuration for detection rules.
3. Additional authentication detection rules.
4. Structured alert output and operational metrics.
5. Improved Linux log ingestion.
6. Statistical anomaly detection.
7. Further packaging and deployment improvements.

## Engineering Focus

LogSentinel is an evolving security engineering project used to explore:

- Linux systems and authentication logs.
- Security monitoring and detection engineering.
- Python software development.
- Automated testing and continuous integration.
- Containerisation and reproducible execution.
- Software reliability and observability.
- Statistical approaches to anomaly detection.