import os
import urllib.request
import json

def send_discord_alert(webhook_url, scan_summary):
    """
    Sends a formatted Discord embed notification with scan results.
    """
    if not webhook_url:
        print("[-] No Discord webhook URL provided. Skipping notification.")
        return

    has_criticals = scan_summary.get("critical", 0) > 0 or scan_summary.get("high", 0) > 0
    embed_color = 15158332 if has_criticals else 3066993

    raw_total = scan_summary.get("total")
    if raw_total is None:
        raw_total = (
            scan_summary.get("passed", 0) +
            scan_summary.get("critical", 0) +
            scan_summary.get("high", 0) +
            scan_summary.get("medium", 0) +
            scan_summary.get("low", 0)
        )
    total_checked = str(raw_total)
    passed_count = str(scan_summary.get("passed", 0))
    critical_count = str(scan_summary.get("critical", 0))
    high_count = str(scan_summary.get("high", 0))
    medium_count = str(scan_summary.get("medium", 0))
    low_count = str(scan_summary.get("low", 0))

    payload = {
        "username": "Cloud Security Scanner",
        "embeds": [
            {
                "title": "Cloud Security Audit Completed",
                "color": embed_color,
                "fields": [
                    {"name": "Total Checked", "value": str(scan_summary.get("total, 0")), "inline": True},
                    {"name": "Critical / High", "value": f"{scan_summary.get('critical', 0)} / {scan_summary.get('high', 0)}", "inline": True},
                    {"name": "Medium / Low", "value": f"{scan_summary.get('medium', 0)} / {scan_summary.get('low', 0)}", "inline": True},
                    {"name": "Passed", "value": str(scan_summary.get('passed', 0)), "inline": True}
                ],
                "footer": {
                    "text": "Automated SecOps Pipeline - Github Actions CI"
                }
            }
        ]
    }

    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "SecurityScannerBot"}
    )

    try:
        with urllib.request.urlopen(req) as response:
            if response.status == 204:
                print("[+] Discord alert sent successfully!")
            else:
                print("[-] Failed to send Discord alert. Status code: {response.status}")
    except Exception as e:
        print(f"[-] Error sending Discord webhook: {e}")