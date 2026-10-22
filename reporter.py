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

def save_html_report(scan_results, totals):
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_filename = f"reports/cloud_security_report_{timestamp}.html"

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cloud Security Risk Assessment</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f6f9; color: #333; }}
            .container {{ max-width: 1000px; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
            h1 {{ color: #007acc; }}
            h2 {{ color: #333; border-bottom: 2px solid #007acc; padding-bottom: 5px; margin-top: 30px; }}
            .summary-box {{ display: flex; gap: 15px; margin-bottom: 25px; }}
            .card {{ flex: 1; padding: 15px; border-radius: 6px; color: white; text-align: center; font-weight: bold; }}
            .pass {{ background-color: #28a745; }}
            .critical {{ background-color: #dc3545; }}
            .high {{ background-color: #e83e8c; }}
            .medium {{ background-color: #fd7e14; }}
            .low {{ background-color: #ffc107; color: #333; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 20px; }}
            th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 14px; }}
            th {{ background-color: #007acc; color: white; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Cloud Security Risk Assessment</h1>
            <p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            
            <div class="summary-box">
                <div class="card pass">Passed<br>{totals['passes']}</div>
                <div class="card critical">Critical<br>{totals['critical']}</div>
                <div class="card high">High<br>{totals['high']}</div>
                <div class="card medium">Medium<br>{totals['medium']}</div>
                <div class="card low">Low<br>{totals['low']}</div>
            </div>

            <h2>S3 Buckets Evaluated</h2>
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

    html_content += """
            </table>

            <h2>IAM Users Evaluated</h2>
            <table>
                <tr><th>Username</th><th>Console Access</th><th>MFA Enabled</th><th>Active Keys</th><th>Admin Access</th></tr>
    """

    for user in scan_results.get("iam_users", []):
        html_content += f"""
                <tr>
                    <td>{user.get('username')}</td>
                    <td>{str(user.get('console_access'))}</td>
                    <td>{str(user.get('mfa_enabled'))}</td>
                    <td>{str(user.get('active_access_keys'))}</td>
                    <td>{str(user.get('admin_access'))}</td>
                </tr>
        """

    html_content += """
            </table>

            <h2>Security Groups Evaluated</h2>
            <table>
                <tr><th>Group Name</th><th>Exposes Sensitive Port (SSH/RDP)</th></tr>
    """

    sg_list = scan_results.get("security_groups", [])
    if sg_list:
        for sg in sg_list:
            html_content += f"""
                <tr>
                    <td>{sg.get('group_name')}</td>
                    <td>{str(sg.get('sensitive_port_public'))}</td>
                </tr>
        """
    else:
        html_content += "<tr><td colspan='2' style='text-align: center; color: #777;'>No security groups evaluated</td></tr>"

    html_content += """
            </table>

            <h2>RDS Databases Evaluated</h2>
            <table>
                <tr><th>DB Identifier</th><th>Publicly Accessible</th></tr>
    """

    rds_list = scan_results.get("rds_instances", [])
    if rds_list:
        for rds in rds_list:
            html_content += f"""
                    <tr>
                        <td>{rds.get('db_identifier')}</td>
                        <td>{str(rds.get('publicly_accessible'))}</td>
                    </tr>
            """
    else:
        html_content += "<tr><td colspan='2' style='text-align: center; color: #777;'>No RDS databases found</td></tr>"

    trail = scan_results.get("cloudtrail", {})
    html_content += f"""
            </table>

            <h2>CloudTrail Status</h2>
            <table>
                <tr><th>Status</th><th>Multi-Region</th><th>Details</th></tr>
                <tr>
                    <td>{str(trail.get('Enabled', False))}</td>
                    <td>{str(trail.get('MultiRegion', False))}</td>
                    <td>{str(trail.get('Reason', 'Active and logging'))}</td>
                </tr>
            </table>
        </div>
    </body>
    </html>
    """

    with open(html_filename, "w") as f:
        f.write(html_content)
    print(f"[INFO] HTML executive dashboard saved to {html_filename}")