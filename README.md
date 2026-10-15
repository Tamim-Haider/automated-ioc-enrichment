# Automated IOC Enrichment and Threat Intelligence Analysis System

## 1. Project Overview

The **Automated IOC Enrichment and Threat Intelligence Analysis System** is a cybersecurity tool designed to automate the collection, enrichment, correlation, and risk assessment of **IP-based Indicators of Compromise (IOCs)**.

The system reduces the manual effort required to investigate suspicious IP addresses by collecting threat intelligence from multiple sources and presenting the results in a structured format.

The project focuses primarily on IP addresses and integrates **VirusTotal**, **AbuseIPDB**, and **Feodo Tracker** to collect and analyze threat intelligence.

---

## 2. Problem Statement

Security analysts often need to investigate suspicious IP addresses using multiple threat intelligence platforms. Manually checking each indicator across different services can be time-consuming and makes it difficult to correlate information from multiple sources.

This project addresses the problem by providing an automated workflow that collects IP-based IOCs, validates them, enriches them using multiple threat intelligence sources, correlates the results, calculates a risk score, and presents the findings through structured reports and a web interface.

---

## 3. Objectives

The main objectives of the project are:

- Automate IP-based IOC collection.
- Detect and validate IOC types.
- Enrich IP addresses using multiple threat intelligence sources.
- Correlate intelligence from different sources.
- Calculate a project-defined risk score.
- Generate structured JSON and CSV results.
- Provide a web-based interface for IOC analysis.
- Reduce the manual effort required for initial IOC investigation.
- Provide an automated threat intelligence feed processing workflow.

---

## 4. Key Features

### IOC Detection

The system identifies the type of submitted IOC and currently focuses on IP addresses.

### IP Validation

IP addresses are validated before being sent to external threat intelligence services.

### VirusTotal Enrichment

VirusTotal is used to retrieve information such as:

- Country
- ASN
- AS owner
- Network
- Reputation
- Tags
- Malicious detections
- Suspicious detections
- Harmless detections
- Undetected results

### AbuseIPDB Enrichment

AbuseIPDB is used to retrieve information related to reported abusive activity and confidence scores.

### Automated IOC Collection

The system uses the Feodo Tracker threat intelligence feed to automatically collect malicious IP indicators.

### Threat Analysis

Information obtained from multiple sources is analyzed to identify relevant threat intelligence findings.

### Source Correlation

Results from VirusTotal and AbuseIPDB are correlated to provide a combined view of the indicator.

### Risk Scoring

A project-defined risk scoring methodology is used to prioritize indicators based on multiple threat intelligence factors.

### Report Generation

Results can be exported into structured formats including:

- JSON
- CSV
- Text-based reports

### Web Dashboard

A Flask-based web interface allows users to submit IP addresses and view enrichment, analysis, correlation, and risk information.

---

## 5. System Architecture

The overall processing workflow is:

```text
                    IOC Input
                       │
                       ▼
                IOC Type Detection
                       │
                       ▼
                  IP Validation
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
         VirusTotal         AbuseIPDB
              │                 │
              └────────┬────────┘
                       │
                       ▼
                Threat Analysis
                       │
                       ▼
                Source Correlation
                       │
                       ▼
                  Risk Scoring
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
          JSON / CSV        Web Dashboard
```

For automated processing:

```text
Feodo Tracker
      │
      ▼
Malicious IP Collection
      │
      ▼
IP Validation
      │
      ▼
VirusTotal + AbuseIPDB
      │
      ▼
Analysis + Correlation
      │
      ▼
Risk Score
      │
      ▼
JSON / CSV Results
```

---

## 6. Technologies Used

### Programming Language

- Python 3

### Web Framework

- Flask

### Threat Intelligence Sources

- VirusTotal
- AbuseIPDB
- Feodo Tracker

### Data Formats

- JSON
- CSV

### Development Environment

- Linux / Kali Linux
- Python Virtual Environment

---

## 7. Project Structure

```text
Automated-IOC-Enrichment/
│
├── analyzer/
│   ├── correlation.py
│   ├── dashboard_stats.py
│   ├── report_generator.py
│   ├── risk_analyzer.py
│   ├── risk_score.py
│   └── summary.py
│
├── collectors/
│   ├── abuseipdb.py
│   ├── abuseipdb_parser.py
│   ├── feodo_tracker.py
│   ├── virustotal.py
│   └── virustotal_parser.py
│
├── utils/
│   ├── csv_exporter.py
│   ├── ioc_detector.py
│   ├── ioc_reader.py
│   └── validator.py
│
├── web/
│   ├── app.py
│   └── templates/
│
├── input/
│   └── iocs.txt
│
├── output/
│
├── testing/
│
├── config/
│
├── main.py
├── feed_processor.py
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 8. Installation

Clone or copy the project:

```bash
git clone <repository-url>
cd Automated-IOC-Enrichment
```

Create a Python virtual environment:

```bash
python3 -m venv .venv
```

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

## 9. Configuration

The project requires API credentials for the external threat intelligence services.

The API keys should be stored securely using environment variables or a `.env` configuration file.

Example:

```text
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

**Never commit API keys or other sensitive credentials to GitHub.**

---

## 10. Running the System

### Manual IOC Analysis

Run the web application:

```bash
python3 -m web.app
```

Open the application in a browser:

```text
http://127.0.0.1:5000
```

Enter an IP address to perform enrichment and analysis.

---

## 11. Automated IOC Feed Processing

The system can automatically retrieve malicious IP addresses from Feodo Tracker.

Run:

```bash
python3 feed_processor.py
```

The system will:

1. Retrieve malicious IP addresses.
2. Select the configured number of indicators.
3. Detect the IOC type.
4. Validate the IP address.
5. Query VirusTotal.
6. Query AbuseIPDB.
7. Analyze the collected intelligence.
8. Correlate information from both sources.
9. Calculate the risk score.
10. Export the results.

The generated files are stored in:

```text
output/
```

Example:

```text
output/automated_feed_results.json
output/automated_feed_results.csv
```

---

## 12. Risk Scoring Methodology

The system uses a project-defined heuristic risk score to prioritize IP addresses.

The current score considers:

- VirusTotal malicious detections
- VirusTotal suspicious detections
- AbuseIPDB confidence score

Conceptually:

```text
Risk Score =
Malicious Detection Contribution
+
Suspicious Detection Contribution
+
Abuse Confidence Contribution
```

The final score is normalized to a range from **0 to 100**.

The current classification is:

| Score | Risk Level |
|---:|---|
| 0–29 | Low |
| 30–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

The scoring model is intentionally transparent and interpretable. It is a **project-specific heuristic** and is not an official VirusTotal or AbuseIPDB score.

The purpose of the score is to help prioritize indicators for further investigation rather than provide a definitive determination of maliciousness.

---

## 13. Testing

The system is tested at both the module and complete-system levels.

Testing includes:

- Valid IP addresses
- Invalid IP addresses
- IOC type detection
- VirusTotal enrichment
- VirusTotal response parsing
- AbuseIPDB enrichment
- AbuseIPDB response parsing
- Feodo Tracker feed collection
- Threat analysis
- Source correlation
- Risk scoring
- JSON export
- CSV export
- Web dashboard
- Automated feed processing

Example test commands:

```bash
python3 test_validator.py
python3 test_virustotal.py
python3 test_parser.py
python3 test_abuseipdb.py
python3 test_abuseipdb_parser.py
python3 test_analysis.py
python3 test_correlation.py
python3 test_csv_exporter.py
python3 test_report.py
python3 test_feodo.py
```

The complete automated pipeline can be tested with:

```bash
python3 feed_processor.py
```

---

## 14. Example VirusTotal Test Result

A test using the IP address `8.8.8.8` successfully returned structured information including:

```text
Country: US
ASN: 15169
AS Owner: Google LLC
Network: 8.8.8.0/24
Reputation: 562
Tags: suspicious-udp
Malicious: 0
Suspicious: 0
Harmless: 53
Undetected: 38
```

This demonstrates that the system can retrieve the raw VirusTotal response and convert it into structured information for further analysis.

---

## 15. Automated Feed Testing

The Feodo Tracker integration was tested successfully.

Example output:

```text
Number of IPs retrieved: 5

162.243.103.246
178.62.3.223
27.133.154.218
34.204.119.63
50.16.16.211
```

These IP addresses can then be passed automatically through the enrichment and analysis pipeline.

---

## 16. Limitations

The current implementation has several limitations:

1. The main enrichment workflow currently focuses on IP addresses.
2. Other IOC types such as domains, URLs, and file hashes are not yet fully supported.
3. The system depends on external APIs and threat intelligence feeds.
4. API rate limits and service availability can affect processing.
5. The risk score is a project-defined heuristic rather than an industry-standard threat score.
6. The current evaluation dataset is relatively small.
7. Threat intelligence results can change over time as external sources update their databases.

---

## 17. Comparison with Existing Solutions

Existing threat intelligence platforms provide valuable information about IP addresses, but analysts may need to manually consult multiple sources to obtain and compare different types of information.

This project provides a lightweight automated workflow that combines information from multiple sources into a single analysis process.

The key differences include:

- Automated IOC collection.
- Multi-source enrichment.
- Automatic source correlation.
- Transparent project-defined risk scoring.
- Automated JSON and CSV reporting.
- Web-based analysis.
- Modular architecture for future expansion.

The project is not intended to replace commercial threat intelligence platforms. Instead, it provides a focused and customizable workflow for IP-based IOC investigation.

---

## 18. Future Work

Potential future improvements include:

- Support for additional IOC types.
- Integration with additional threat intelligence platforms.
- Larger-scale IOC evaluation.
- Improved risk-scoring calibration using a larger labeled dataset.
- Advanced visualization.
- SIEM integration.
- Real-time IOC monitoring.
- Additional automated threat feeds.
- Improved API failure and rate-limit handling.

---

## 19. Project Outcome

The completed system provides an automated workflow for collecting and analyzing IP-based Indicators of Compromise.

The system can:

```text
Collect IOC
     ↓
Identify IOC Type
     ↓
Validate IP
     ↓
Enrich with VirusTotal
     ↓
Enrich with AbuseIPDB
     ↓
Correlate Results
     ↓
Analyze Threat
     ↓
Calculate Risk
     ↓
Generate Reports
     ↓
Display Results
```

The project demonstrates the practical application of **Cyber Threat Intelligence, IOC enrichment, API integration, threat analysis, risk assessment, automation, and web-based security tooling**.
