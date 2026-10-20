import sqlite3
import json

conn = sqlite3.connect('server/usbips_server.db')
conn.row_factory = sqlite3.Row
c = conn.cursor()

print("=== ALL MASTER ALLOWLIST ENTRIES ===")
rows = [dict(r) for r in c.execute('SELECT id, vendor_id, product_id, serial_number, device_type, status, duration_minutes, expires_at, decision_reason FROM master_allowlist').fetchall()]
print(json.dumps(rows, indent=2))

print("\n=== ALL PENDING REQUESTS ENTRIES ===")
reqs = [dict(r) for r in c.execute('SELECT request_id, vendor_id, product_id, serial_number, device_type, status, requested_at, decided_at, decision_by, decision_reason, captcha_result, verification_method, duration_minutes, expires_at FROM pending_requests').fetchall()]
print(json.dumps(reqs, indent=2))
