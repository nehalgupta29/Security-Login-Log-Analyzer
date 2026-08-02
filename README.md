# Security Login Simulator & Log Analyzer

A beginner-friendly cybersecurity project built with Python and Streamlit that simulates user authentication, records security events, detects suspicious login attempts, classifies user risk levels, and visualizes security analytics through an interactive dashboard.

----

## Features

- User Registration
- User Login Authentication
- Admin-only Dashboard
- Authentication Event Logging
- Failed Login Detection
- Suspicious User Detection
- Risk Classification (Medium, High, Critical)
- Authentication Report Generation
- Suspicious User Report Generation
- Authentication Activity Bar Chart
- Failed Login Trend Line Chart
- User Risk Analysis Chart
- Event Distribution Heatmap Chart
- Download Authentication Report
- Download Suspicious User Report

---

## Tech Stack

- pandas
- streamlit
- plotly 

---

## Project Structure

```
Log-Analyzer/
│
├── app.py
├── requirements.txt
├── README.md
├── LICENSE.txt
├── users.csv
├── authentication_report.csv
├── suspicious_report.csv
│
├── screenshots/
│   ├── login.png
│   ├── dashboard.png
│   └── suspicious_users.png
```

---

## How to Run

--Click On the live demo: [Security Login Simulator & Log Analyzer] https://cybersecurity-log-analyzer.streamlit.app/

---

## How It Works

1. Register a new user.
2. Login using valid credentials.
3. Every authentication event is stored in "authentication_report.csv".
4. Failed login attempts are continuously monitored.
5. Users with multiple failed login attempts are classified into different risk levels.
6. Suspicious users are stored in "suspicious_report.csv".
7. The admin dashboard visualizes authentication statistics and security analytics.

---

## Risk Classification

| Failed Attempts | Risk Level |
|-----------------|------------|
| 3-5 | Medium |
| 6–10 | High |
| More than 10 | Critical |

---

## Dashboard

The dashboard provides:

- Total Events
- Successful Logins
- Failed Logins
- Successful Registrations
- Most Active User
- Suspicious Accounts
- Authentication Activity Graph
- Failed Login Trend
- User Risk Analysis
- Event Distribution
- Downloadable Reports

---

## Author

Nehal Gupta

BCA Student

Cybersecurity Enthusiast
