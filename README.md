# LogSentinel

LogSentinel is a Linux security monitoring and anomaly detection project focused on analysing authentication logs and identifying suspicious behaviour.

The project is being developed as a hands-on security engineering platform, with an emphasis on Linux systems, detection engineering, software quality, testing, and observability.

> **Status:** Early development — current functionality focuses on SSH authentication log analysis and rule-based detection.

## Current Features

- Parse SSH authentication log entries.
- Transform raw log lines into structured security events.
- Distinguish successful and failed authentication attempts.
- Group failed authentication activity by source IP.
- Detect multi-account targeting from a single source IP.
- Apply configurable unique-user and time-window thresholds.
- Analyse activity using a sliding time window.
- Validate detection behaviour with automated pytest tests.

## Detection Rules

### LS-001 — Multi-Account Targeting

Detects a source IP generating failed authentication attempts against multiple unique user accounts within a configurable time window.

Example:

```text
10:00:00  203.0.113.42  admin   FAILED
10:00:10  203.0.113.42  root    FAILED
10:00:20  203.0.113.42  guest   FAILED
```

With a threshold of 3 unique users within 60 seconds, this activity generates an `LS-001` security alert.

The rule identifies suspicious behaviour but does not by itself prove that an attack or compromise occurred.

## Architecture

```text
Authentication Logs
        |
        v
     Parsing
        |
        v
 SecurityEvent
        |
        v
 Detection Engine
        |
        v
  SecurityAlert
        |
        v
 Report / Output
```

Current detection flow:

```text
Failed authentication events
        |
        v
Group by source IP
        |
        v
Sort chronologically
        |
        v
Sliding time window
        |
        v
Count unique targeted users
        |
        v
Threshold reached?
   |            |
   No           Yes
   |             |
 Ignore      LS-001 Alert
```

## Project Structure

```text
logsentinel/
├── data/
│   └── security.log
├── src/
│   └── logsentinel.py
├── tests/
│   └── test_detection.py
├── .gitignore
└── README.md
```

## Running LogSentinel

Create and activate a Python virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the current test dependency:

```bash
python -m pip install pytest
```

Run LogSentinel from the project root:

```bash
python src/logsentinel.py
```

## Running Tests

```bash
python -m pytest
```

The current test suite validates:

- detection of multi-account targeting;
- behaviour below the unique-user threshold;
- behaviour outside the configured time window;
- detection of suspicious clusters despite later unrelated activity.

## Current Limitations

LogSentinel is currently an early-stage project.

Current limitations include:

- SSH log parsing is based on a controlled sample format.
- Log timestamps do not currently contain explicit year information.
- Detection configuration is currently defined in code.
- Alerts are currently printed locally.
- The project does not yet perform real-time log ingestion.

## Roadmap

Planned engineering work includes:

- external configuration for detection rules;
- additional authentication detection rules;
- improved Linux log ingestion;
- structured alert output;
- statistical anomaly detection;
- packaging and dependency management;
- CI/CD;
- containerisation with Docker;
- metrics and observability;
- API integration;
- deployment and orchestration experiments.

## Engineering Focus

LogSentinel is designed as an evolving security engineering project rather than a single-purpose script.

The project is being used to explore the intersection of:

- Linux systems;
- security monitoring;
- detection engineering;
- Python software engineering;
- automated testing;
- statistics and anomaly detection;
- DevOps and observability.
