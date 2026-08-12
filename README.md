# 🛡️ CyberShield AI

### AI-Powered Phishing Detection Platform

CyberShield AI is a web-based phishing detection platform that analyzes website URLs using **machine learning, rule-based security analysis, and Google Safe Browsing** to identify potential phishing threats.

The system converts URL characteristics into machine-learning features, uses a trained Random Forest model to estimate phishing probability, checks for suspicious URL patterns, and verifies the URL against Google Safe Browsing.

---

## 🚀 Features

- 🤖 **Random Forest Machine Learning**
  - Trained on phishing and legitimate URL data
  - Produces a phishing probability for each scanned URL
  - Current model accuracy: **87%** on the project's test split

- 🔎 **Rule-Based Phishing Detection**
  - Detects HTTP usage
  - Checks for multiple hyphens
  - Detects suspicious keywords
  - Detects IP-based URLs
  - Checks for suspicious URL characteristics

- 🛡️ **Google Safe Browsing Integration**
  - Checks whether Google identifies the URL as a known unsafe resource
  - Displays known threat information when available

- 📊 **Risk Scoring**
  - Produces a risk score from **0 to 10**
  - Classifies results as:
    - LOW RISK
    - MEDIUM RISK
    - HIGH RISK

- 📈 **Security Dashboard**
  - Total scans
  - Safe websites
  - Phishing detections
  - Recent scan activity
  - Detection summary

- 📄 **Automated Security Reports**
  - Generates downloadable PDF reports
  - Includes AI probability
  - Rule-based findings
  - Google Safe Browsing result
  - Overall risk assessment

- 🕒 **Scan History**
  - Stores previous scan results
  - Displays recent scanning activity

---

## 🧠 How CyberShield AI Works

```text
                    User enters URL
                           │
                           ▼
                    Flask Application
                           │
                           ▼
                    Detection Engine
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        AI Model      Rule-Based    Google Safe
        Analysis       Analysis      Browsing
              │            │            │
              └────────────┼────────────┘
                           ▼
                     Risk Assessment
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
        Web Dashboard             PDF Report