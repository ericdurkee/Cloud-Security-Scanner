import sqlite3
from datetime import datetime, timezone

DB_NAME = "security_history.db"

def init_db():
    """Initializes the SQLite database and tables if they don't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            total_passes INTEGER,
            critical INTEGER,
            high INTEGER,
            medium INTEGER,
            low INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            findings_id INTEGER PRIMARY KEY AUTOINCREMENT, 
            scan_id INTEGER,
            resource_name TEXT,
            check_name TEXT,
            status TEXT,
            severity TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
        )
    """)

    conn.commit()
    conn.close()

def save_scan_to_db(totals_dict, findings_list):
    """Saves the current scan run and its findings to the database."""
    init_db()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    timestamp = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
        INSERT INTO scans (timestamp, total_passes, critical, high, medium, low)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        totals_dict.get("passes", 0),
        totals_dict.get("critical", 0),
        totals_dict.get("high", 0),
        totals_dict.get("medium", 0),
        totals_dict.get("low", 0),
    ))

    scan_id = cursor.lastrowid

    for f in findings_list:
        cursor.execute("""
            INSERT INTO findings (scan_id, resource_name, check_name, status, severity)
            VALUES (?, ?, ?, ?, ?)
        """, (
            scan_id,
            f.get("resource", "Unknown"),
            f.get("check_name", "Unknown"),
            f.get("status", "UNKNOWN"),
            f.get("severity", "INFO")
        ))

        conn.commit()
        conn.close()
        return scan_id

def get_previous_scan_findings():
    """Retrieves findings from the most recent previous scan."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT 1")
    last_scan = cursor.fetchone()

    if not last_scan:
        conn.close()
        return {}
    
    prev_scan_id = last_scan[0]

    cursor.execute("""
        SELECT resource_name, check_name, status, severity
        FROM findings WHERE scan_id = ?
    """, (prev_scan_id,))

    prev_findings = {row[0] + ":" + row[1]: row[2] for row in cursor.fetchall()}
    conn.close()
    return prev_findings

def calculate_drift(current_findings):
    """Compares current scan against previous scan to find security drift."""
    prev_findings = get_previous_scan_findings()
    if not prev_findings:
        print("[INFO] No historical scan data found for drift comparison. Establishing baseline.")
        return None

    regressions = []
    resolutions = []

    for f in current_findings:
        key = f.get("resource", "Unknown") + ":" + f.get("check_name", "Unknown")
        current_status = f.get("status")

        previous_status = prev_findings.get(key)

        if previous_status:
            if previous_status == "PASS" and current_status == "FAIL":
                regressions.append(f)
            elif previous_status == "FAIL" and current_status == "PASS":
                resolutions.append(f)
    return {"regressions": regressions, "resolutions": resolutions}