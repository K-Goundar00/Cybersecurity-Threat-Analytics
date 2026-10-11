# Cybersecurity Threat Analytics 🛡️

### Interactive Cybersecurity Threat & Incident Analytics Dashboard

Cybersecurity Threat Analytics is an interactive dashboard built with Python, Streamlit, Pandas, NumPy, and Plotly. The project focuses on analysing security event data, identifying potentially suspicious activity, and visualising security trends through an interactive graphical interface.

Developed as a cybersecurity and data analytics portfolio project, it demonstrates how security logs and event records can be transformed into meaningful insights to support threat monitoring and incident investigation.

> **Disclaimer:** This project uses synthetic security event data for educational and demonstration purposes. Findings are not verified real-world security incidents.

## ✨ Features

- **Security Metrics:** View total events, high-severity events, failed logins, and open investigations.
- **Interactive Charts:** Visualise security event distributions, trends, and patterns.
- **Event Filtering:** Filter events by severity, event type, and date.
- **Event Investigation:** Explore security event records and potentially suspicious activity.
- **CSV Export:** Export filtered event data for further analysis.
- **Synthetic Data Generation:** Generate sample security events locally for testing.
- **CSV Import:** Support for analysing external security event datasets as the project develops.

## 🧰 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| Streamlit | Interactive dashboard interface |
| Pandas | Data cleaning and analysis |
| NumPy | Synthetic data generation |
| Plotly | Interactive data visualisation |
| Git & GitHub | Version control and project hosting |

## 🚀 Getting Started

### Prerequisites

- Python installed on Windows
- Visual Studio Code
- Git (optional)

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/cybersecurity-threat-analytics.git
cd cybersecurity-threat-analytics
```

Replace `YOUR-USERNAME` with your GitHub username.

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Alternatively, use Command Prompt:

```cmd
.venv\Scripts\activate.bat
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run the dashboard

```bash
python -m streamlit run app.py
```

Open the local URL displayed in the terminal, usually:

http://localhost:8501

## 📁 Project Structure

```text
cybersecurity-threat-analytics/
├── app.py
├── requirements.txt
├── data/
├── src/
├── reports/
├── .gitignore
└── README.md
```

| File or folder | Description |
|---|---|
| `app.py` | Main Streamlit dashboard |
| `requirements.txt` | Project dependencies |
| `data/` | Security event datasets |
| `src/` | Supporting analysis modules |
| `reports/` | Exported analysis and reports |
| `.gitignore` | Excludes virtual environments and sensitive files |
| `README.md` | Project documentation |

## 🔐 Data Security

- Uses synthetic security events for initial development.
- Runs locally by default.
- Does not require live network scanning or offensive security tools.
- Uses only authorised datasets for analysis.
- Excludes confidential logs, credentials, and sensitive information from public repositories.

This project is intended for learning and portfolio demonstration. It is not a replacement for an enterprise Security Information and Event Management (SIEM) platform.

## 🔮 Future Improvements

- Import and validate external security event datasets.
- Detect repeated failed logins and unusual event patterns.
- Analyse suspicious source IP addresses and event frequency.
- Add configurable severity thresholds and detection rules.
- Generate downloadable incident summary reports.
- Add investigation status tracking.
- Expand automated testing and data validation.

## 🎯 Learning Objectives

This project explores:

- Python programming and data analytics
- Cybersecurity event monitoring
- Threat analysis and incident investigation
- Data cleaning and visualisation
- Interactive dashboard development
- Git and GitHub version control

## 👨‍💻 Author

**Kaushik Goundar**

---

*Turning security event data into actionable insights.*
