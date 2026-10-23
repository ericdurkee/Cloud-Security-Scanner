#CIS AWS Foundations & SOC 2
COMPLIANCE_STANDARDS = {
    "S3 Public Access": {
        "cis": "CIS AWS 2.1.1",
        "soc2": "CC6.1 (Logical Access)",
        "description": "Ensure S3 buckets are not publicly accessible"
    },
    "S3 Encryption": {
        "cis": "CIS AWS 2.2",
        "soc2": "CC6.7 (Data Transmission/Storage Protection)",
        "description": "Ensure S3 buckets have default encryption enabled"
    },
    "S3 Versioning": {
        "cis": "CIS AWS 2.1.2",
        "soc2": "A1.2 (Backup & Recovery)",
        "description": "Ensure S3 bucket versioning is enabled"
    },
    "S3 Logging": {
        "cis": "CIS AWS 3.6",
        "soc2": "CC7.2 (Monitoring & Logging)",
        "description": "Ensure S3 access logging is enabled"
    },
    "SG Sensitive Ports Public": {
        "cis": "CIS AWS 5.2",
        "soc2": "CC6.6 (Boundary Protection)",
        "description": "Ensure no security groups allow ingress from 0.0.0.0/0 to sensitive ports"
    },
    "RDS Publicly Accessible": {
        "cis": "CIS AWS 4.1",
        "soc2": "CC6.1 (Database Isolation)",
        "description": "Ensure RDS databases are not publicly accessible"
    }
}

def evaluate_compliance(flat_findings_list):
    """Calculates compliance scores for CIS and SOC 2 based on scan findings."""
    framework_stats = {
        "CIS AWS Benchmark": {"total": 0, "passed": 0},
        "SOC 2": {"total": 0, "passed": 0}
    }

    for f in flat_findings_list:
        check_name = f.get("check_name")
        status = f.get("status")

        mapping = COMPLIANCE_STANDARDS.get(check_name)
        if mapping:
            framework_stats["CIS AWS Benchmark"]["total"] += 1
            if status == "PASS":
                framework_stats["CIS AWS Benchmark"]["passed"] += 1

            framework_stats["SOC 2"]["total"] += 1
            if status == "PASS":
                framework_stats["SOC 2"]["passed"] += 1

    scores = {}
    for fw, stats in framework_stats.items():
        total = stats["total"]
        passed = stats["passed"]
        score = int((passed / total) * 100) if total > 0 else 100
        scores[fw] = {"score": score, "passed": passed, "total": total}

    return scores