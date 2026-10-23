import json
import os
from datetime import datetime, timezone
from colorama import init, Fore, Style
init(autoreset=True)
from tabulate import tabulate 

def print_risk_table(total_passes, critical_fails, high_fails, medium_fails, low_fails, total_info, regions_count):
    print("\n========================================")
    print(f"{Fore.CYAN}Cloud Security Risk Assessment Summary{Style.RESET_ALL}")
    print("========================================")
    print(f"Regions Scanned: {regions_count}\n")

    table_data = [
        [f"{Fore.GREEN}Passed Checks{Style.RESET_ALL}", total_passes, "Compliant against security benchmarks"],
        [f"{Fore.RED}Critical Findings{Style.RESET_ALL}", critical_fails, "Immediate public exposure or severe risk"],
        [f"{Fore.RED}High Findings{Style.RESET_ALL}", high_fails, "Major architectural or logging gaps"],
        [f"{Fore.YELLOW}Medium Findings{Style.RESET_ALL}", medium_fails, "Identity, access, or encryption weaknesses"],
        [f"{Fore.YELLOW}Low Findings{Style.RESET_ALL}", low_fails, "Secondary hardening & hygiene best practices"],
        [f"{Fore.BLUE}Informational{Style.RESET_ALL}", total_info, "Non-actionable or informational logs"]
    ]

    headers = ["Risk Tier / Status", "Count", "Description"]
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
    print("\n")
    
    print("\nScan Risk Summary:")
    print(tabulate(table_data, headers=["Risk Level", "Count"], tablefmt="grid"))

def save_scan_report(scan_results):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(current_dir, "reports")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"cloud_scan_report_{timestamp}.json")
    report_data = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "results": scan_results
    }
    with open(filename, "w") as f:
        json.dump(report_data, f, indent=4)
    print(f"\n[{Fore.BLUE}INFO{Style.RESET_ALL}] Scan report successfully saved to {filename}")

def save_html_report(scan_results, totals_dict, filename_prefix="reports/cloud_security_report"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{timestamp}.html"
    
    # Calculate overall risk scores or fetch stats
    passes = totals_dict.get("passes", 0)
    critical = totals_dict.get("critical", 0)
    high = totals_dict.get("high", 0)
    medium = totals_dict.get("medium", 0)
    low = totals_dict.get("low", 0)

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cloud Security Executive Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }}
            .container {{ max-width: 1100px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }}
            h2 {{ color: #34495e; margin-top: 30px; }}
            .summary-cards {{ display: flex; gap: 15px; margin-bottom: 30px; }}
            .card {{ flex: 1; background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; border-left: 5px solid #bdc3c7; }}
            .card.pass {{ border-left-color: #2ecc71; }}
            .card.critical {{ border-left-color: #e74c3c; }}
            .card.high {{ border-left-color: #d35400; }}
            .card.medium {{ border-left-color: #f1c40f; }}
            .card.low {{ border-left-color: #3498db; }}
            .card h3 {{ margin: 0; font-size: 14px; color: #7f8c8d; }}
            .card p {{ margin: 10px 0 0 0; font-size: 24px; font-weight: bold; color: #2c3e50; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; margin-bottom: 20px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ecf0f1; font-size: 14px; }}
            th {{ background-color: #f8f9fa; color: #2c3e50; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Cloud Security Executive Dashboard</h1>
            <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            
            <div class="summary-cards">
                <div class="card pass"><h3>Passed</h3><p>{passes}</p></div>
                <div class="card critical"><h3>Critical</h3><p>{critical}</p></div>
                <div class="card high"><h3>High</h3><p>{high}</p></div>
                <div class="card medium"><h3>Medium</h3><p>{medium}</p></div>
                <div class="card low"><h3>Low</h3><p>{low}</p></div>
            </div>
    """

    # --- IAM Users Section ---
    html_content += """
            <h2>IAM Users Audit</h2>
            <table>
                <tr><th>Username</th><th>Console Access</th><th>MFA Enabled</th><th>Active Keys</th><th>Admin Access</th></tr>
    """
    for user in scan_results.get("iam_users", []):
        html_content += f"""
                <tr>
                    <td>{user.get('username')}</td>
                    <td>{str(user.get('console_access'))}</td>
                    <td>{str(user.get('mfa_enabled'))}</td>
                    <td>{user.get('active_access_keys')}</td>
                    <td>{str(user.get('admin_access'))}</td>
                </tr>
        """
    html_content += "</table>"

    # --- S3 Buckets Section ---
    html_content += """
            <h2>S3 Storage Security</h2>
            <table>
                <tr><th>Bucket Name</th><th>Public</th><th>Versioning</th><th>Encryption</th><th>Logging</th></tr>
    """
    for bucket in scan_results.get("s3_buckets", []):
        html_content += f"""
                <tr>
                    <td>{bucket.get('bucket_name')}</td>
                    <td>{str(bucket.get('is_public'))}</td>
                    <td>{str(bucket.get('versioning_enabled'))}</td>
                    <td>{str(bucket.get('encryption_enabled'))}</td>
                    <td>{str(bucket.get('logging_enabled'))}</td>
                </tr>
        """
    html_content += "</table>"

    # --- Security Groups Section ---
    html_content += """
            <h2>Security Groups (Inbound Risk)</h2>
            <table>
                <tr><th>Security Group Name</th><th>Exposes SSH/RDP</th></tr>
    """
    for sg in scan_results.get("security_groups", []):
        html_content += f"""
                <tr>
                    <td>{sg.get('group_name')}</td>
                    <td>{str(sg.get('sensitive_port_public'))}</td>
                </tr>
        """
    html_content += "</table>"

    # --- RDS Databases Section ---
    html_content += """
            <h2>RDS Database Instances</h2>
            <table>
                <tr><th>Database Identifier</th><th>Publicly Accessible</th></tr>
    """
    for rds in scan_results.get("rds_instances", []):
        html_content += f"""
                <tr>
                    <td>{rds.get('db_identifier')}</td>
                    <td>{str(rds.get('publicly_accessible'))}</td>
                </tr>
        """
    html_content += "</table>"

    html_content += """
        </div>
    </body>
    </html>
    """

    with open(filename, "w") as f:
        f.write(html_content)
    
    print(f"[INFO] HTML Executive Dashboard saved to: {filename}")