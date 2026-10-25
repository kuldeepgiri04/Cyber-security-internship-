# Threat Intelligence Aggregator 🛡️

A Python-based Cybersecurity tool built with Streamlit that aggregates real-time Indicator of Compromise (IoC) data from multiple Threat Intelligence feeds (**VirusTotal** and **AlienVault OTX**).

## 📌 Project Overview
Security Operations Center (SOC) analysts often have to manually check multiple platforms to analyze IP addresses, domains, or file hashes. This tool consolidates data from premier threat intelligence APIs into a single interactive dashboard, reducing incident response time.

## ✨ Features
- **Multi-Source Aggregation:** Fetches data simultaneously from VirusTotal and AlienVault OTX APIs.
- **Multiple IoC Support:** Accepts IP addresses, Domain names, and File Hashes (MD5/SHA256).
- **Interactive Visualizations:** Displays detection ratios using Plotly interactive charts.
- **Severity Score & Summary:** Evaluates overall risk level (High/Medium/Low) based on combined intelligence feeds.
- **Fallback Demonstration Mode:** Includes realistic mock data response if live API keys are not provided.

## 🛠️ Installation & Setup Guide

### 1. Prerequisites
- Python 3.8 or higher installed on your system.

### 2. Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/threat-intelligence-aggregator.git
cd threat-intelligence-aggregator
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
streamlit run app.py
```

## 🔐 API Configuration (Optional)
Enter your free API keys in the sidebar of the app:
- **VirusTotal API Key:** [Get VirusTotal API Key](https://www.virustotal.com/)
- **AlienVault OTX API Key:** [Get AlienVault OTX Key](https://otx.alienvault.com/)

*(Note: The app will run using demo mode if no API keys are entered).*