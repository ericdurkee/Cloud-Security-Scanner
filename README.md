# Cloud Security Scanner

An automated Python-based cloud security auditing tool designed to evaluate AWS environments against security benchmarks, identify infrastructure misconfigurations, and generate executive-ready reports (Terminal tables, JSON exports, and styled HTML dashboards).

---

## Features

- **S3 Bucket Auditing:** Inspects public accessibility, default encryption, bucket versioning, and server access logging.
- **IAM User Governance:** Audits console access, multi-factor authentication (MFA) enforcement, active access key counts, and administrative privilege escalation risks.
- **Network & Compute Security:** Evaluates security group rules for exposed sensitive ports (SSH/RDP) and inspects RDS database instances for public accessibility.
- **Governance & Auditing:** Checks CloudTrail status and multi-region logging configuration.
- **Multi-Format Reporting:** 
  - Styled ASCII terminal tables using `tabulate`.
  - Structured JSON scan output for automation pipelines.
  - Multi-section HTML executive dashboards complete with severity metric summary cards and responsive tables.

---

## Prerequisites

- **Python 3.8+**
- **AWS CLI** configured with appropriate IAM read permissions (`AmazonS3ReadOnlyAccess`, `IAMReadOnlyAccess`, `AmazonRDSReadOnlyAccess`, etc.).

---

## Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/cloud-security-scanner.git
   cd cloud-security-scanner
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure AWS Credentials:**
   Ensure your environment is authenticated via AWS CLI or environment variables:
   ```bash
   aws configure
   ```

---

## Usage

Run the scanner directly from your terminal:

```bash
python scanner.py
```

Generated HTML executive dashboards will automatically be saved to the `reports/` directory with timestamped filenames (e.g., `reports/cloud_security_report_YYYYMMDD_HHMMSS.html`).

---

## Severity Tiers

- **Critical:** Public S3 buckets/bucket policies, exposed SSH/RDP ports, public RDS instances.
- **High:** CloudTrail disabled, root access keys present, root MFA disabled, missing password policy.
- **Medium:** Missing console MFA, administrative privileges, keys >90 days old, multiple active access keys.
- **Low:** Missing S3 versioning/logging/lifecycle policies, weak password complexity rules.

---

## Project Structure

```text
Cloud-Security-Scanner/
├── checks/             # Modularized security evaluation checks (S3, IAM, RDS, SG, etc.)
├── reports/            # Generated HTML executive dashboards & JSON logs
├── reporter.py         # Multi-format report exporter (JSON, Tabulate, HTML)
├── scanner.py          # Core orchestration script
├── requirements.txt    # Project dependencies
└── README.md           # Documentation
```

---
