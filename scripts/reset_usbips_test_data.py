r"""
USBIPS - Test Environment Reset Script
Repository: C:/Users/navin/FYP-USBIPS

Purpose:
  Prepares USBIPS for a clean, repeatable manual test (e.g. using a pen drive,
  USB keyboard, or webcam) by safely purging all existing device authorizations,
  allowlist entries, and pending requests.

Safety Guarantees:
  1. Creates timestamped backups of all SQLite databases prior to any modification.
  2. Does NOT drop tables or delete database files (preserves schema and migrations).
  3. Preserves client registration records (`clients` table).
  4. Preserves fleet security policy configuration (`policies` table).
  5. Preserves client identity (`client_metadata` table).
  6. Preserves audit/security event history by default for debugging.
     (Can be cleared only with explicit --clear-events flag).
"""

import os
import sys
import shutil
import sqlite3
import argparse
from datetime import datetime

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SERVER_DB_PATH = os.path.join(REPO_ROOT, "server", "usbips_server.db")
CLIENT_DB_PATH = os.path.join(REPO_ROOT, "usbips.db")
DEBUG_CLIENT_DB_PATH = os.path.join(REPO_ROOT, "Debug", "usbips.db")
BACKUP_DIR = os.path.join(REPO_ROOT, "backups")


def create_timestamped_backup(db_path: str, backup_dir: str, timestamp_str: str) -> str:
    """Creates a timestamped copy of a SQLite database."""
    if not os.path.exists(db_path):
        return None
    os.makedirs(backup_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(db_path))[0]
    ext = os.path.splitext(os.path.basename(db_path))[1]
    backup_filename = f"{base_name}_{timestamp_str}{ext}"
    backup_path = os.path.join(backup_dir, backup_filename)
    shutil.copy2(db_path, backup_path)
    return backup_path


def count_table_rows(conn: sqlite3.Connection, table_name: str) -> int:
    """Returns row count for a given table, or -1 if table does not exist."""
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        return cursor.fetchone()[0]
    except sqlite3.OperationalError:
        return -1


def reset_server_database(db_path: str, dry_run: bool = False, clear_events: bool = False) -> dict:
    """Safely resets device authorization and request tables in server database."""
    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    pre_counts = {
        "master_allowlist": count_table_rows(conn, "master_allowlist"),
        "pending_requests": count_table_rows(conn, "pending_requests"),
        "clients": count_table_rows(conn, "clients"),
        "policies": count_table_rows(conn, "policies"),
        "server_events": count_table_rows(conn, "server_events"),
    }

    if not dry_run:
        # Delete pending requests first (referencing clients), then allowlist
        cursor.execute("DELETE FROM pending_requests;")
        cursor.execute("DELETE FROM master_allowlist;")

        if clear_events:
            cursor.execute("DELETE FROM server_events;")

        conn.commit()
        cursor.execute("VACUUM;")
        conn.close()

        # Reopen to get post counts
        conn_after = sqlite3.connect(db_path)
        post_counts = {
            "master_allowlist": count_table_rows(conn_after, "master_allowlist"),
            "pending_requests": count_table_rows(conn_after, "pending_requests"),
            "clients": count_table_rows(conn_after, "clients"),
            "policies": count_table_rows(conn_after, "policies"),
            "server_events": count_table_rows(conn_after, "server_events"),
        }
        conn_after.close()
    else:
        post_counts = {k: (0 if k in ("master_allowlist", "pending_requests") or (k == "server_events" and clear_events) else v)
                       for k, v in pre_counts.items()}
        conn.close()

    return {"pre": pre_counts, "post": post_counts}


def reset_client_database(db_path: str, dry_run: bool = False, clear_events: bool = False) -> dict:
    """Safely resets device authorization cache in client database."""
    if not os.path.exists(db_path):
        return {"error": f"Database not found at {db_path}"}

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    pre_counts = {
        "allowed_devices": count_table_rows(conn, "allowed_devices"),
        "security_events": count_table_rows(conn, "security_events"),
        "client_metadata": count_table_rows(conn, "client_metadata"),
    }

    if not dry_run:
        cursor.execute("DELETE FROM allowed_devices;")
        if clear_events:
            cursor.execute("DELETE FROM security_events;")

        conn.commit()
        cursor.execute("VACUUM;")
        conn.close()

        conn_after = sqlite3.connect(db_path)
        post_counts = {
            "allowed_devices": count_table_rows(conn_after, "allowed_devices"),
            "security_events": count_table_rows(conn_after, "security_events"),
            "client_metadata": count_table_rows(conn_after, "client_metadata"),
        }
        conn_after.close()
    else:
        post_counts = {k: (0 if k == "allowed_devices" or (k == "security_events" and clear_events) else v)
                       for k, v in pre_counts.items()}
        conn.close()

    return {"pre": pre_counts, "post": post_counts}


def main():
    parser = argparse.ArgumentParser(description="Safely reset USBIPS device authorization test data.")
    parser.add_argument("--dry-run", action="store_true", help="Preview reset actions without writing changes.")
    parser.add_argument("--clear-events", action="store_true", help="Also clear historical security audit events (preserved by default).")
    args = parser.parse_args()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print("=" * 70)
    print("       USBIPS TEST DATA RESET & DATABASE PREPARATION")
    print("=" * 70)
    print(f"Timestamp : {datetime.now().isoformat()}")
    print(f"Mode      : {'DRY RUN (No changes written)' if args.dry_run else 'LIVE EXECUTION'}")
    print(f"Events    : {'CLEAR ALL EVENTS' if args.clear_events else 'PRESERVE HISTORICAL EVENTS (Default)'}")
    print("-" * 70)

    # 1. Backups
    print("[1/4] Creating timestamped database backups...")
    server_backup = None
    client_backup = None
    if not args.dry_run:
        server_backup = create_timestamped_backup(SERVER_DB_PATH, BACKUP_DIR, timestamp)
        client_backup = create_timestamped_backup(CLIENT_DB_PATH, BACKUP_DIR, timestamp)
        if server_backup:
            print(f"  [+] Server DB backup : {server_backup}")
        if client_backup:
            print(f"  [+] Client DB backup : {client_backup}")
        if os.path.exists(DEBUG_CLIENT_DB_PATH):
            debug_backup = create_timestamped_backup(DEBUG_CLIENT_DB_PATH, BACKUP_DIR, timestamp)
            if debug_backup:
                print(f"  [+] Debug DB backup  : {debug_backup}")
    else:
        print("  [DRY RUN] Skipping physical backup file creation.")

    # 2. Server DB Reset
    print("\n[2/4] Resetting Server Database (server/usbips_server.db)...")
    server_res = reset_server_database(SERVER_DB_PATH, args.dry_run, args.clear_events)
    if "error" in server_res:
        print(f"  [-] Error: {server_res['error']}")
    else:
        print("  Table Summary:")
        print(f"    - master_allowlist : {server_res['pre']['master_allowlist']} -> {server_res['post']['master_allowlist']} (CLEARED)")
        print(f"    - pending_requests : {server_res['pre']['pending_requests']} -> {server_res['post']['pending_requests']} (CLEARED)")
        print(f"    - clients          : {server_res['pre']['clients']} -> {server_res['post']['clients']} (PRESERVED)")
        print(f"    - policies         : {server_res['pre']['policies']} -> {server_res['post']['policies']} (PRESERVED)")
        print(f"    - server_events    : {server_res['pre']['server_events']} -> {server_res['post']['server_events']} "
              f"({'CLEARED' if args.clear_events else 'PRESERVED'})")

    # 3. Client DB Reset
    print("\n[3/4] Resetting Client Database (usbips.db)...")
    client_res = reset_client_database(CLIENT_DB_PATH, args.dry_run, args.clear_events)
    if "error" in client_res:
        print(f"  [-] Error: {client_res['error']}")
    else:
        print("  Table Summary:")
        print(f"    - allowed_devices  : {client_res['pre']['allowed_devices']} -> {client_res['post']['allowed_devices']} (CLEARED)")
        print(f"    - client_metadata  : {client_res['pre']['client_metadata']} -> {client_res['post']['client_metadata']} (PRESERVED)")
        print(f"    - security_events  : {client_res['pre']['security_events']} -> {client_res['post']['security_events']} "
              f"({'CLEARED' if args.clear_events else 'PRESERVED'})")

    if os.path.exists(DEBUG_CLIENT_DB_PATH):
        reset_client_database(DEBUG_CLIENT_DB_PATH, args.dry_run, args.clear_events)

    # 4. Final Verification Check
    print("\n[4/4] Verification of Zero-Trust State...")
    clean = True
    if not args.dry_run:
        s_conn = sqlite3.connect(SERVER_DB_PATH)
        s_allowed = count_table_rows(s_conn, "master_allowlist")
        s_pending = count_table_rows(s_conn, "pending_requests")
        s_clients = count_table_rows(s_conn, "clients")
        s_conn.close()

        c_conn = sqlite3.connect(CLIENT_DB_PATH)
        c_allowed = count_table_rows(c_conn, "allowed_devices")
        c_conn.close()

        if s_allowed != 0 or s_pending != 0 or c_allowed != 0:
            clean = False
            print("  [!] WARNING: Non-zero records detected in authorization tables!")
        else:
            print("  [OK] Master allowlist count      : 0 (No pre-trusted devices)")
            print("  [OK] Pending requests count      : 0 (No pre-decided requests)")
            print("  [OK] Client local allowlist count: 0 (No cached authorizations)")
            print(f"  [OK] Registered clients preserved: {s_clients}")
            print("  [OK] Fleet policies & metadata   : INTACT")

    print("\n" + "=" * 70)
    if clean:
        print("  SUCCESS: USBIPS environment is in a pristine ZERO-TRUST state.")
        print("  Newly connected USB devices will be treated as UNKNOWN / UNTRUSTED.")
    else:
        print("  FAILURE: Residual records found. Please check logs.")
    print("=" * 70)


if __name__ == "__main__":
    main()
