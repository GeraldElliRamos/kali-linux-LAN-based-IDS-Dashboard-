# LAN-Based IDS Dashboard

TIP-Quezon City, College of Computer Studies  
Bachelor of Science in Information Technology

Course: Information Assurance and Security (IT001)

## Project Overview

This project implements a LAN-Based Intrusion Detection System (IDS) Dashboard for centralized
network monitoring and real-time alert visibility. The system ingests live packet telemetry via
Scapy and Snort alert output (when available), then presents actionable telemetry in a web
dashboard for faster incident response.

The current implementation focuses on:

- Real-time LAN packet capture and anomaly detection.
- Signature-driven alert ingestion from Snort-style fast logs.
- Real-time dashboard updates over Socket.IO.
- Host risk/status profiling based on observed alert severity.
- Protocol and source-origin aggregation for traffic awareness.

## Statement of the Problem

Many institutional LAN environments still lack centralized, real-time security monitoring for
internal traffic. This creates visibility gaps where reconnaissance, unauthorized access, and
abnormal traffic behavior may remain undetected until after operational impact.

This project addresses that gap by providing continuous monitoring and immediate alert surfacing
through a unified dashboard.

## Scope

The prototype in this repository covers:

- Real-time ingestion of IDS alert events.
- Live dashboard visualization of threats and host state.
- Alert history view through API and UI.
- Local testing support when live Snort logs are not available.

Planned/academic scope from the project document also includes broader institutional deployment,
simulation exercises, and policy alignment.

## Objectives

- Build a functional IDS monitoring pipeline for LAN alerts.
- Deliver an actionable dashboard usable by security administrators.
- Support integration recommendations for continuous monitoring operations.

## Risk and Threat Focus

The dashboard is designed to help monitor events associated with:

- Unauthorized access attempts.
- Port scanning and reconnaissance activity.
- Denial-of-Service style traffic spikes.
- Suspicious internal traffic anomalies.

Threat modeling and security design in the paper are based on STRIDE and the CIA triad.

## Current Implementation Architecture

- Backend: Flask + Flask-SocketIO (`backend.py`).
- Frontend: single-page dashboard (`ids_dashboard_ui.html`).
- Data source: live packet capture (Scapy) + Snort fast alert log tailing.
- APIs: `/api/health`, `/api/stats`, `/api/alerts`.

Note: The manuscript references Snort plus Elastic Stack for institutional-scale visualization.
This repository currently implements a lightweight Flask dashboard prototype suitable for demo,
testing, and course project validation.

## Team

- Abdul Rahman Noor
- Gabriel Ellis Muega
- Gerald Elli Ramos
- Jarl Valiant Robelo
- Neo Ynigo Regalado

Section: IT32S6  
Adviser: Prof. Allan Antonio Burgos  
Project Date: April 8, 2026

## Setup

Requirements:

- Python 3.10+
- Root/sudo privileges for packet capture mode
- Snort alert output (default candidates include `/var/log/snort/alert_fast.log`)

Install dependencies:

```bash
pip install -r requirements.txt
```

Run backend:

```bash
sudo python backend.py
```

Open dashboard:

- http://127.0.0.1:5000/

## Runtime Options

Use custom Snort log path:

```bash
SNORT_ALERT_LOG=/path/to/alert_fast.log sudo python backend.py
```

Choose capture interface:

```bash
IDS_INTERFACE=eth0 sudo python backend.py
```

Fallback mode (development only when live capture/Snort are unavailable):

- Disabled by default: `IDS_ENABLE_FALLBACK=0`
- Enable with: `IDS_ENABLE_FALLBACK=1`

Example:

```bash
IDS_ENABLE_FALLBACK=1 python backend.py
```

## API Endpoints

- `GET /api/health` - backend runtime and log source status.
- `GET /api/stats` - full dashboard state payload.
- `GET /api/alerts` - latest alerts list.

Quick verification:

```bash
curl -s http://127.0.0.1:5000/api/health
curl -s http://127.0.0.1:5000/api/stats
```

## Compliance and References

The full project document maps implementation goals to:

- Republic Act No. 10175 (Cybercrime Prevention Act of 2012)
- NIST SP 800-94 (Guide to Intrusion Detection and Prevention Systems)

Core references in the manuscript include Snort, Suricata, Scapy, and network security
monitoring literature.
