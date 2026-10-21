import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime, timezone
import uuid

def get_db_path():
    path = os.environ.get("USBIPS_SERVER_DB", os.path.join(os.path.dirname(__file__), "..", "..", "usbips_server.db"))
    return os.path.abspath(path)

_initialized_paths = set()

def get_connection():
    path = get_db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def get_db():
    path = get_db_path()
    if path not in _initialized_paths:
        _initialized_paths.add(path)
        init_db()

    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    path = get_db_path()
    _initialized_paths.add(path)
    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        # 1. Clients Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                hostname TEXT,
                ip_address TEXT,
                os_version TEXT,
                agent_version TEXT,
                registered_at TEXT,
                last_heartbeat TEXT,
                status TEXT DEFAULT 'ONLINE'
            );
        """)

        # 2. Master Allowlist Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS master_allowlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vendor_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                serial_number TEXT NOT NULL,
                device_type TEXT,
                description TEXT,
                manufacturer TEXT,
                status TEXT DEFAULT 'APPROVED',
                created_at TEXT,
                updated_at TEXT,
                UNIQUE(vendor_id, product_id, serial_number)
            );
        """)

        # 3. Pending Requests Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pending_requests (
                request_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                vendor_id TEXT NOT NULL,
                product_id TEXT NOT NULL,
                serial_number TEXT NOT NULL,
                device_type TEXT,
                description TEXT,
                device_path TEXT,
                status TEXT DEFAULT 'PENDING',
                requested_at TEXT,
                decided_at TEXT,
                decision_by TEXT
            );
        """)

        # 4. Server Events Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS server_events (
                event_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                timestamp TEXT,
                event_type TEXT,
                vendor_id TEXT,
                product_id TEXT,
                serial_number TEXT,
                device_id TEXT,
                device_type TEXT,
                description TEXT,
                decision TEXT,
                reason TEXT,
                received_at TEXT
            );
        """)

        # 5. Central Security Policies Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                strict_allowlist_matching INTEGER DEFAULT 1,
                fail_closed_when_server_offline INTEGER DEFAULT 1,
                require_captcha_for_hid INTEGER DEFAULT 1,
                captcha_timeout_seconds INTEGER DEFAULT 30,
                captcha_max_attempts INTEGER DEFAULT 3,
                iki_burst_threshold_cps INTEGER DEFAULT 30,
                iki_min_variance_ms REAL DEFAULT 2.0,
                hid_surveillance_window_seconds INTEGER DEFAULT 15,
                block_unauthorized_composite INTEGER DEFAULT 1,
                allow_composite_mouse_keyboard INTEGER DEFAULT 1,
                protected_directory TEXT DEFAULT 'C:\\USBIPS_Protected',
                block_storage_execution INTEGER DEFAULT 1,
                auto_terminate_storage_processes INTEGER DEFAULT 1,
                max_reconnects_per_minute INTEGER DEFAULT 3,
                flap_window_seconds INTEGER DEFAULT 15,
                evasion_risk_threshold INTEGER DEFAULT 70,
                updated_at TEXT
            );
        """)

        # Migration for existing database instances: ensure captcha_max_attempts column exists
        cursor.execute("PRAGMA table_info(policies);")
        policy_cols = [row[1] if isinstance(row, tuple) else row["name"] for row in cursor.fetchall()]
        if "captcha_max_attempts" not in policy_cols:
            cursor.execute("ALTER TABLE policies ADD COLUMN captcha_max_attempts INTEGER DEFAULT 3;")

        # Insert default policy if not present
        cursor.execute("SELECT COUNT(*) FROM policies WHERE id = 1;")
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                INSERT INTO policies (id, updated_at) VALUES (1, datetime('now'));
            """)

        # 6. Protected Folder Policies Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS protected_folder_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_path TEXT NOT NULL UNIQUE,
                description TEXT DEFAULT '',
                is_enabled INTEGER DEFAULT 1,
                created_at TEXT,
                updated_at TEXT
            );
        """)

        # Seed default protected folder if table is empty
        cursor.execute("SELECT COUNT(*) FROM protected_folder_policies;")
        if cursor.fetchone()[0] == 0:
            default_now = utc_now_iso()
            cursor.execute("""
                INSERT INTO protected_folder_policies (folder_path, description, is_enabled, created_at, updated_at)
                VALUES ('C:\\USBIPS_Protected', 'Default Sentinel Quarantine Folder', 1, ?, ?);
            """, (default_now, default_now))

        # Migrations for pending_requests
        cursor.execute("PRAGMA table_info(pending_requests);")
        req_cols = [row[1] if isinstance(row, tuple) else row["name"] for row in cursor.fetchall()]
        pending_migrations = [
            ("session_id", "TEXT"),
            ("captcha_challenge_id", "TEXT"),
            ("captcha_result", "TEXT"),
            ("verification_method", "TEXT"),
            ("verification_start", "TEXT"),
            ("verification_completed", "TEXT"),
            ("attempt_count", "INTEGER DEFAULT 0"),
            ("verification_score", "INTEGER DEFAULT 0"),
            ("verification_duration_seconds", "REAL DEFAULT 0.0"),
            ("temp_release_applied", "INTEGER DEFAULT 0"),
            ("temp_release_duration_seconds", "REAL DEFAULT 0.0"),
            ("re_quarantine_result", "TEXT"),
            ("current_enforcement_state", "TEXT"),
            ("total_risk_score", "INTEGER DEFAULT 0"),
            ("severity", "TEXT"),
            ("recommendation", "TEXT"),
            ("assessment_summary", "TEXT"),
            ("algorithms_json", "TEXT"),
            ("duration_minutes", "INTEGER"),
            ("expires_at", "TEXT"),
            ("decision_reason", "TEXT")
        ]
        for col_name, col_type in pending_migrations:
            if col_name not in req_cols:
                cursor.execute(f"ALTER TABLE pending_requests ADD COLUMN {col_name} {col_type};")

        # Migrations for master_allowlist
        cursor.execute("PRAGMA table_info(master_allowlist);")
        allow_cols = [row[1] if isinstance(row, tuple) else row["name"] for row in cursor.fetchall()]
        allow_migrations = [
            ("duration_minutes", "INTEGER"),
            ("expires_at", "TEXT"),
            ("decision_reason", "TEXT")
        ]
        for col_name, col_type in allow_migrations:
            if col_name not in allow_cols:
                cursor.execute(f"ALTER TABLE master_allowlist ADD COLUMN {col_name} {col_type};")

        # Indices
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_req_status ON pending_requests(status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_allowlist_tuple ON master_allowlist(vendor_id, product_id, serial_number);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON server_events(timestamp);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_client ON server_events(client_id);")
        conn.commit()
    finally:
        conn.close()

def utc_now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
