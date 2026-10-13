# CyberShield AI

**AI-Based Log Analyzer for SOC Monitoring**

CyberShield AI is a self-contained Flask web application that helps a Security Operations Center (SOC) analyst review log files. It parses logs, detects threats, shows a threat analysis table with AI summary and recommendations, visualizes the data in a dashboard, and generates PDF reports.

## Features

- **Log parsing:** reads log files from the `logs/` folder and stores the parsed entries in a SQLite database
- **Threat detection:** flags suspicious activity and lists it in a Threat Analysis table (`/threats`)
- **AI summary and recommendations:** security summary and suggested actions (`/ai_summary`)
- **Dashboard:** multiple charts that visualize threat data
- **PDF reports:** consolidated report generation
- **Login-protected access** to the dashboard
- **Rescan Logs:** add new log files to `logs/` and re-import them from the Upload page, no restart needed

## Tech Stack

Python 3.12 · Flask · SQLite · HTML · CSS · JavaScript · Chart.js · ReportLab

## Getting Started

**Requirements:** Python 3.12

```bash
# 1. Clone the repository
git clone https://github.com/MahammadSaleem12/cybershield-AI.git
cd cybershield-AI

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the app
python app.py
```

On first run the app creates the SQLite database `cybershield.db`, generates sample logs in `logs/`, and parses them.

**Demo login** (for local testing only, change it before any real use):

- Username: `admin`
- Password: `adminpass`

## Usage

1. Log in with the demo credentials.
2. Open the dashboard to see the charts.
3. Visit `/threats` for the Threat Analysis table.
4. Visit `/ai_summary` for the AI summary and recommendations.
5. To analyze your own logs, copy them into the `logs/` folder and click **Rescan Logs** on the Upload page.
6. Generate the consolidated PDF report from the dashboard.

## Project Structure

```
cybershield-AI/
├── app.py            # Flask application
├── generate_logs.py  # Sample log generator
├── templates/        # HTML templates
├── static/           # CSS / JS assets
├── logs/             # Log files to analyze
└── requirements.txt  # Python dependencies
```

## Author

**Achukatla Mahammad Saleem**
B.Tech Computer Science Engineering, Madanapalle Institute of Technology & Science
[GitHub](https://github.com/MahammadSaleem12) · [LinkedIn](https://linkedin.com/in/mahammad-saleem-29a346358)
