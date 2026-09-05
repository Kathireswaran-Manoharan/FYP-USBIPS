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
