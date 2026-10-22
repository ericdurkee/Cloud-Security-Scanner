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
    