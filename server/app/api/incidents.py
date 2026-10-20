import uuid
from fastapi import APIRouter, HTTPException, status
from ..models.schemas import PolicyViolationIncidentRequest
from ..database.db import get_db, utc_now_iso

router = APIRouter(prefix="/api/incidents", tags=["Security Incidents & Policy Violations"])

@router.post("/policy-violation", response_model=dict, status_code=status.HTTP_200_OK)
def report_policy_violation(data: PolicyViolationIncidentRequest):
    """
    Handle confirmed or suspected protected-folder policy violations reported by clients.
    If attribution_tier == 'DEFINITIVE', immediately revoke and block the device.
    If attribution_tier is 'UNCERTAIN' or 'PROBABILISTIC', record high-severity incident telemetry without falsely revoking device.
    """
    now = utc_now_iso()
    vid = data.vendor_id.upper()
    pid = data.product_id.upper()
    serial = data.serial_number or ""

    with get_db() as conn:
        cursor = conn.cursor()

        if data.attribution_tier == "DEFINITIVE":
            revocation_reason = (
                f"Policy violation: Confirmed unauthorized {data.operation} on protected folder "
                f"'{data.folder_path}'. Evidence: {data.attribution_evidence}"
            )

            # 1. Purge from master allowlist
            cursor.execute("""
                DELETE FROM master_allowlist
                WHERE vendor_id = ? AND product_id = ? AND serial_number = ?;
            """, (vid, pid, serial))
            purged = cursor.rowcount > 0

            # 2. Update existing requests or insert revoked request
            cursor.execute("""
                UPDATE pending_requests
                SET status = 'REVOKED',
                    decided_at = ?,
                    decision_by = 'System Policy Enforcement',
                    decision_reason = ?
                WHERE vendor_id = ? AND product_id = ? AND serial_number = ?;
            """, (now, revocation_reason, vid, pid, serial))

            if cursor.rowcount == 0:
                req_id = str(uuid.uuid4())
                cursor.execute("""
                    INSERT INTO pending_requests (
                        request_id, client_id, vendor_id, product_id, serial_number,
                        device_type, description, device_path, status, requested_at,
                        decided_at, decision_by, decision_reason, recommendation, severity,
                        total_risk_score, assessment_summary
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'REVOKED', ?, ?, 'System Policy Enforcement', ?, 'REJECT', 'CRITICAL', 100, ?);
                """, (
                    req_id, data.client_id, vid, pid, serial,
                    data.device_type or "STORAGE", data.description or "USB Storage Peripheral",
                    data.device_id or "", now, now, revocation_reason, revocation_reason
                ))

            # 3. Insert DEVICE_BLOCKED event in central audit log
            event_id_block = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO server_events (
                    event_id, client_id, timestamp, event_type,
                    vendor_id, product_id, serial_number, device_id,
                    device_type, description, decision, reason, received_at
                ) VALUES (?, ?, ?, 'DEVICE_BLOCKED', ?, ?, ?, ?, ?, ?, 'BLOCK', ?, ?);
            """, (
                event_id_block, data.client_id, now, vid, pid, serial,
                data.device_id or "", data.device_type or "STORAGE", data.description or "",
                f"Device revoked & disabled following confirmed protected folder violation: {data.folder_path}", now
            ))

            # 4. Insert detailed INCIDENT_POLICY_VIOLATION event
            incident_event_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO server_events (
                    event_id, client_id, timestamp, event_type,
                    vendor_id, product_id, serial_number, device_id,
                    device_type, description, decision, reason, received_at
                ) VALUES (?, ?, ?, 'PROTECTED_FILE_ACCESS', ?, ?, ?, ?, ?, ?, 'ALERT', ?, ?);
            """, (
                incident_event_id, data.client_id, now, vid, pid, serial,
                data.device_id or "", data.device_type or "STORAGE", data.description or "",
                revocation_reason, now
            ))

            return {
                "status": "success",
                "action_taken": "DEVICE_REVOKED_AND_BLOCKED",
                "attribution_tier": "DEFINITIVE",
                "device_revoked": True,
                "allowlist_purged": purged,
                "message": f"Device {vid}:{pid} permanently revoked and blocked for confirmed policy violation.",
                "timestamp": now
            }
        else:
            # Uncertain or probabilistic correlation: Log alert without disabling
            alert_reason = (
                f"Suspicious activity: {data.operation} observed in protected folder '{data.folder_path}'. "
                f"Attribution uncertain ({data.attribution_tier}). Evidence: {data.attribution_evidence}"
            )
            incident_event_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO server_events (
                    event_id, client_id, timestamp, event_type,
                    vendor_id, product_id, serial_number, device_id,
                    device_type, description, decision, reason, received_at
                ) VALUES (?, ?, ?, 'PROTECTED_FILE_ACCESS', ?, ?, ?, ?, ?, ?, 'ALERT', ?, ?);
            """, (
                incident_event_id, data.client_id, now, vid, pid, serial,
                data.device_id or "", data.device_type or "STORAGE", data.description or "",
                alert_reason, now
            ))

            return {
                "status": "success",
                "action_taken": "ALERT_RECORDED_ONLY",
                "attribution_tier": data.attribution_tier,
                "device_revoked": False,
                "message": "Attribution uncertain; high-severity incident telemetry recorded without altering device authorization.",
                "timestamp": now
            }
