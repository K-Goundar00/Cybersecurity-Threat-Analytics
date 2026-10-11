# Cybersecurity Threat & Incident Analytics Dashboard

A Python-based cybersecurity analytics dashboard for exploring security events, identifying incident patterns, and visualizing potential areas for investigation through an interactive GUI.

## Overview

This project demonstrates how Python and data analytics can support cybersecurity monitoring and incident investigation. It uses Pandas to process security event data, Plotly to create interactive visualizations, and Streamlit to provide a browser-based dashboard.

The initial version uses synthetic security events for development and testing. It also supports uploading CSV files that follow the required data format.

## Features

- **Security Metrics:** View total events, high/critical severity events, failed logins, and open or ongoing investigations.
- **Severity Analysis:** Visualize the distribution of events by severity.
- **Event Classification:** Identify the most frequently recorded event types.
- **Time-Based Analysis:** Examine daily event volumes and changes in activity.
- **Source IP Analysis:** Identify source IP addresses associated with the highest event counts.
- **Interactive Filters:** Filter records by severity, event type, and date range.
- **Event Explorer:** Inspect and sort individual security event records.
- **CSV Import:** Upload compatible security event datasets.
- **Data Export:** Download filtered events for further analysis.
- **Initial Findings:** Display basic observations based on the selected data.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Application logic and data analysis |
| Pandas | Data cleaning and manipulation |
| NumPy | Synthetic data generation |
| Plotly | Interactive data visualization |
| Streamlit | Dashboard GUI |
| VS Code | Development environment |

## Project Structure

```text
cybersecurity-threat-analytics/
├── app.py
├── requirements.txt
├── data/
├── src/
├── reports/
├── screenshots/
├── .gitignore
└── README.md
```

- `app.py` — Main dashboard application.
- `requirements.txt` — Python dependencies.
- `data/` — Location for datasets and data documentation.
- `src/` — Additional analysis modules as the project develops.
- `reports/` — Analysis reports and exported findings.
- `screenshots/` — Dashboard screenshots for documentation.

## Getting Started

### Prerequisites

- Windows, macOS, or Linux
- Python 3.13
- Visual Studio Code (recommended)

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/cybersecurity-threat-analytics.git
cd cybersecurity-threat-analytics
```

Replace `YOUR-USERNAME` with your GitHub username.

Alternatively, download the repository as a ZIP file and open the extracted folder in VS Code.

### 2. Create a virtual environment

On Windows, open the VS Code terminal and run:

```powershell
py -3.13 -m venv .venv
```

### 3. Install dependencies

If PowerShell activation is unavailable, install packages using the environment's Python executable directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 4. Run the dashboard

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open the local URL displayed in the terminal, normally:

`http://localhost:8501`

## Dataset

The initial version generates 1,500 synthetic security events for demonstration purposes.

The generated records include:

- Event timestamps
- Event types
- Source IP addresses
- Usernames
- Severity levels
- Investigation statuses

The synthetic dataset enables dashboard development without requiring access to confidential organizational logs.

### Using a CSV Dataset

The current dashboard expects the following columns:

| Column | Description |
|---|---|
| `timestamp` | Date and time of the event |
| `event_type` | Type of security event |
| `source_ip` | Source IP address |
| `username` | Associated account |
| `severity` | Event severity |
| `status` | Investigation status |

Public datasets may use different schemas and require preprocessing before they can be analyzed by this dashboard.

## Planned Improvements

- Integrate a real public cybersecurity dataset, such as CIC-IDS2017.
- Build a dedicated data-cleaning and preprocessing pipeline.
- Add attack-category and network-traffic analysis.
- Improve anomaly detection and investigation prioritization.
- Generate downloadable security analysis reports.
- Separate data processing, analysis, and dashboard components into modules.
- Add automated tests and data validation.
- Improve the dashboard layout and visual design.

## Security and Limitations

- Synthetic events are not real security incidents.
- A high event count does not automatically indicate malicious activity.
- Frequent source IP addresses should not automatically be classified as attackers.
- Analysis results depend on data quality, labeling, and preprocessing.
- Only upload datasets you are authorized to use.
- Do not publish confidential logs, credentials, or sensitive organizational information.

This project is intended for educational purposes and portfolio development. It is not a replacement for a production SIEM or a fully operational security monitoring system.

## Author

**Kaushik Goundar**

IT Security Engineer | Cybersecurity | Network & Systems Security
