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

def save_html_report(scan_results, totals_dict, compliance_scores=None, filename_prefix="reports/cloud_security_report"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{timestamp}.html"
    
    # Calculate overall risk scores or fetch stats
    passes = totals_dict.get("passes", 0)
    critical = totals_dict.get("critical", 0)
    high = totals_dict.get("high", 0)
    medium = totals_dict.get("medium", 0)
    low = totals_dict.get("low", 0)

    compliance_html = ""
    if compliance_scores:
        compliance_html = """
        <div style="background: #1e293b; border: 1px solid #334155;padding: 24px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 20px rgba(0,0,0,0.4);">
            <div style="display: flex; align-items: center; margin-bottom: 16px;">
                <span style="font-size: 20px; margin-right: 8px;"></span>
                <h3 style="margin: 0; color: #38bdf8; font-size: 18px; font-weight: 600; letter-spacing: 0.5px;">Regulatory Compliance Posture</h3>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px;">
        """
        for framework, data in compliance_scores.items():
            score = data["score"]
            passed = data["passed"]
            total = data["total"]
            color = "#22c55e" if score >= 80 else "#eab308" if score >= 50 else "#ef4444"
            
            compliance_html += f"""
                <div style="background: #0f172a; border: 1px solid #1e293b; padding: 18px; border-radius: 8px; border-left: 4px solid {color};">
                    <div style="font-size: 13px; font-weight: 500; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px;">{framework}</div>
                    <div style="display: flex; align-items: baseline; justify-content: space-between;">
                        <div style="font-size: 28px; font-weight: 700; color: {color};">{score}%</div>
                        <div style="font-size: 12px; color: #64748b;">{passed}/{total} Controls</div>
                    </div>
                </div>
            """
        compliance_html += """
            </div>
        </div>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Cloud Security Executive Dashboard</title>
        <style>
            :root {{
                --bg-main: #0b0f19;
                --bg-card: #1e293b;
                --bg-table: #0f172a;
                --border-color: #334155;
                --text-main: #f8fafc;
                --text-muted: #94a3b8;
            }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                background-color: var(--bg-main);
                color: var(--text-main);
                margin: 0;
                padding: 40px 20px;
                line-height: 1.5;
            }}
            .container {{
                max-width: 1200px;
                margin: auto;
                background: var(--bg-card);
                border: 1px solid var(--border-color);
                padding: 40px;
                border-radius: 16px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            }}
            .header {{
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                border-bottom: 1px solid var(--border-color);
                padding-bottom: 20px;
                margin-bottom: 30px;
            }}
            h1 {{ margin: 0; color: #f8fafc; font-size: 26px; font-weight: 700; }}
            .timestamp {{ color: var(--text-muted); font-size: 13px; margin-top: 6px; }}
            
            .summary-cards {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                gap: 15px;
                margin-bottom: 30px;
            }}
            .card {{
                background: var(--bg-table);
                border: 1px solid var(--border-color);
                padding: 20px;
                border-radius: 10px;
                text-align: center;
                position: relative;
                overflow: hidden;
            }}
            .card::before {{
                content: '';
                position: absolute;
                top: 0; left: 0; width: 4px; height: 100%;
            }}
            .card.pass::before {{ background: #22c55e; }}
            .card.critical::before {{ background: #ef4444; }}
            .card.high::before {{ background: #f97316; }}
            .card.medium::before {{ background: #eab308; }}
            .card.low::before {{ background: #38bdf8; }}
            
            .card h3 {{ margin: 0; font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}
            .card p {{ margin: 10px 0 0 0; font-size: 28px; font-weight: 700; color: #f8fafc; }}

            h2 {{ color: #38bdf8; font-size: 18px; font-weight: 600; margin-top: 40px; margin-bottom: 15px; border-left: 3px solid #38bdf8; padding-left: 10px; }}
            
            table {{
                width: 100%;
                border-collapse: collapse;
                background: var(--bg-table);
                border-radius: 8px;
                overflow: hidden;
                border: 1px solid var(--border-color);
                margin-bottom: 20px;
            }}
            th, td {{
                padding: 14px 18px;
                text-align: left;
                border-bottom: 1px solid var(--border-color);
                font-size: 13.5px;
            }}
            th {{
                background-color: #111827;
                color: #cbd5e1;
                font-weight: 600;
                text-transform: uppercase;
                font-size: 11px;
                letter-spacing: 0.8px;
            }}
            tr:last-child td {{ border-bottom: none; }}
            tr:hover {{ background-color: rgba(255, 255, 255, 0.02); }}
            
            .badge {{
                display: inline-block;
                padding: 4px 10px;
                border-radius: 6px;
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
            }}
            .badge.pass {{ background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); }}
            .badge.fail {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <h1>Cloud Security Executive Dashboard</h1>
                    <div class="timestamp">Automated Infrastructure Assessment & Compliance Report</div>
                </div>
                <div class="timestamp" style="text-align: right;">
                    Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}
                </div>
            </div>
            
            {compliance_html}
            
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