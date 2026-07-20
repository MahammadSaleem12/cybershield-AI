# CyberShield AI

AI-Based Log Analyzer for SOC Monitoring — a minimal, self-contained Flask app that parses log files, detects threats, generates summaries and PDF reports, and visualizes threat data.

Requirements
- Python 3.12
- Install dependencies: `pip install -r requirements.txt`

Run

```powershell
pip install -r requirements.txt
python app.py
```

Default credentials
- username: `admin`
- password: `adminpass`

Notes
- On first run the app creates the SQLite database `cybershield.db`, populates sample logs in `logs/`, and parses them.
- You can add more log files to the `logs/` folder and click "Rescan Logs" on the Upload page to import them without restarting the app.
- Visit `/threats` for the Threat Analysis table and `/ai_summary` for AI recommendations.
- The dashboard includes multiple charts and a consolidated PDF report generator.
