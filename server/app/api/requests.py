from fastapi import APIRouter, HTTPException, Query, Body
from typing import List, Optional
from datetime import datetime, timezone, timedelta
import uuid
from ..models.schemas import (
    PendingRequestResponse,
    ApproveRequestPayload,
    DeclineRequestPayload
)
from ..database.db import get_db, utc_now_iso

router = APIRouter(prefix="/api/requests", tags=["Authorization Requests"])

def _row_to_response(r) -> PendingRequestResponse:
    return PendingRequestResponse(
        request_id=r["request_id"],
        client_id=r["client_id"],
        vendor_id=r["vendor_id"],
        product_id=r["product_id"],
        serial_number=r["serial_number"],
        device_type=r["device_type"] or "OTHER",
        description=r["description"] or "",
        device_path=r["device_path"] or "",
        status=r["status"],
        requested_at=r["requested_at"] or "",
        decided_at=r["decided_at"],
        decision_by=r["decision_by"],
        decision_reason=r["decision_reason"] if "decision_reason" in r.keys() else None,
        session_id=r["session_id"] if "session_id" in r.keys() else "",
        captcha_challenge_id=r["captcha_challenge_id"] if "captcha_challenge_id" in r.keys() else "",
        captcha_result=r["captcha_result"] if "captcha_result" in r.keys() else "NOT_COMPLETED",
        verification_method=r["verification_method"] if "verification_method" in r.keys() else "NONE",
        verification_start=r["verification_start"] if "verification_start" in r.keys() else "",
        verification_completed=r["verification_completed"] if "verification_completed" in r.keys() else "",
        attempt_count=r["attempt_count"] if "attempt_count" in r.keys() else 0,
        verification_score=r["verification_score"] if "verification_score" in r.keys() else 0,
        verification_duration_seconds=r["verification_duration_seconds"] if "verification_duration_seconds" in r.keys() else 0.0,
        temp_release_applied=bool(r["temp_release_applied"]) if "temp_release_applied" in r.keys() else False,
        temp_release_duration_seconds=r["temp_release_duration_seconds"] if "temp_release_duration_seconds" in r.keys() else 0.0,
        re_quarantine_result=r["re_quarantine_result"] if "re_quarantine_result" in r.keys() else "",
        current_enforcement_state=r["current_enforcement_state"] if "current_enforcement_state" in r.keys() else "QUARANTINED",
        total_risk_score=r["total_risk_score"] if "total_risk_score" in r.keys() else 0,
        severity=r["severity"] if "severity" in r.keys() else "LOW",
        recommendation=r["recommendation"] if "recommendation" in r.keys() else "REVIEW",
        assessment_summary=r["assessment_summary"] if "assessment_summary" in r.keys() else "",
        algorithms_json=r["algorithms_json"] if "algorithms_json" in r.keys() else "{}",
        duration_minutes=r["duration_minutes"] if "duration_minutes" in r.keys() else None,
        expires_at=r["expires_at"] if "expires_at" in r.keys() else None
    )

@router.get("", response_model=List[PendingRequestResponse])
def list_all_requests(status_filter: Optional[str] = Query(None, alias="status")):
    requests = []
    with get_db() as conn:
        cursor = conn.cursor()
        if status_filter:
            cursor.execute("""
                SELECT * FROM pending_requests
                WHERE status = ?
                ORDER BY requested_at DESC;
            """, (status_filter.upper(),))
        else:
            cursor.execute("""
                SELECT * FROM pending_requests
                ORDER BY requested_at DESC;
            """)
            
        rows = cursor.fetchall()
        for r in rows:
            requests.append(_row_to_response(r))
            
    return requests

@router.get("/pending", response_model=List[PendingRequestResponse])
def list_pending_requests():
    return list_all_requests(status_filter="PENDING")

@router.get("/{request_id}", response_model=PendingRequestResponse)
def get_request_by_id(request_id: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_requests WHERE request_id = ?;", (request_id,))
        r = cursor.fetchone()
        if not r:
            raise HTTPException(status_code=404, detail="Request not found")
            
        return _row_to_response(r)

@router.post("/{request_id}/approve", response_model=dict)
def approve_request(
    request_id: str,
    payload: Optional[ApproveRequestPayload] = Body(default=None)
):
    admin_user = payload.admin_user if payload and payload.admin_user else "Admin"
    decision_reason = payload.decision_reason if payload and payload.decision_reason else "Approved by Administrator"
    duration_minutes = payload.duration_minutes if payload else None
    override_critical = payload.override_critical if payload else False

    now = utc_now_iso()
    expires_at = None
    if duration_minutes and duration_minutes > 0:
        expires_dt = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        expires_at = expires_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Fetch request details
        cursor.execute("""
            SELECT client_id, vendor_id, product_id, serial_number, device_type, description,
                   total_risk_score, severity, recommendation
            FROM pending_requests
            WHERE request_id = ?;
        """, (request_id,))
        req = cursor.fetchone()
        
        if not req:
            raise HTTPException(status_code=404, detail="Request not found")

        # 2. Safety Rule: Cannot approve CRITICAL security violations without explicit override
        rec = req["recommendation"] or ""
        sev = req["severity"] or ""
        if (rec == "REJECT" or sev == "CRITICAL") and not override_critical:
            raise HTTPException(
                status_code=400,
                detail="Security policy blocks approval: Device has CRITICAL risk severity or REJECT recommendation."
            )
            
        # 3. Update request status to APPROVED
        cursor.execute("""
            UPDATE pending_requests
            SET status = 'APPROVED', decided_at = ?, decision_by = ?,
                decision_reason = ?, duration_minutes = ?, expires_at = ?
            WHERE request_id = ?;
        """, (now, admin_user, decision_reason, duration_minutes, expires_at, request_id))
        
        # 4. Add to master_allowlist
        cursor.execute("""
            INSERT INTO master_allowlist (
                vendor_id, product_id, serial_number, device_type, description,
                manufacturer, status, created_at, updated_at,
                duration_minutes, expires_at, decision_reason
            ) VALUES (?, ?, ?, ?, ?, ?, 'APPROVED', ?, ?, ?, ?, ?)
            ON CONFLICT(vendor_id, product_id, serial_number) DO UPDATE SET
                status = 'APPROVED',
                device_type = excluded.device_type,
                description = excluded.description,
                updated_at = excluded.created_at,
                duration_minutes = excluded.duration_minutes,
                expires_at = excluded.expires_at,
                decision_reason = excluded.decision_reason;
        """, (
            req["vendor_id"], req["product_id"], req["serial_number"],
            req["device_type"], req["description"], "Approved Device",
            now, now, duration_minutes, expires_at, decision_reason
        ))
        
    return {
        "status": "success",
        "message": f"Device request approved (Duration: {duration_minutes or 'Permanent'} mins, Expires: {expires_at or 'Never'})",
        "request_id": request_id,
        "expires_at": expires_at
    }

@router.post("/{request_id}/decline", response_model=dict)
def decline_request(
    request_id: str,
    payload: Optional[DeclineRequestPayload] = Body(default=None)
):
    admin_user = payload.admin_user if payload and payload.admin_user else "Admin"
    decision_reason = payload.decision_reason if payload and payload.decision_reason else "Declined by Administrator"
    now = utc_now_iso()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE pending_requests
            SET status = 'DECLINED', decided_at = ?, decision_by = ?, decision_reason = ?
            WHERE request_id = ?;
        """, (now, admin_user, decision_reason, request_id))
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Request not found")
            
    return {
        "status": "success",
        "message": "Device request declined. Device will remain quarantined on client.",
        "request_id": request_id
    }

@router.delete("/{request_id}", response_model=dict)
def delete_request(request_id: str):
    """
    Delete / dismiss an authorization request and permanently remove the device from master_allowlist.
    If the device connects again, it will be evaluated cleanly under standard zero-trust policy (new authorization required).
    """
    now = utc_now_iso()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT vendor_id, product_id, serial_number, device_type, description FROM pending_requests WHERE request_id = ?;", (request_id,))
        req = cursor.fetchone()
        if not req:
            raise HTTPException(status_code=404, detail="Request not found")

        # 1. Purge from master_allowlist so the device is no longer allowlisted or silently auto-approved
        cursor.execute("""
            DELETE FROM master_allowlist
            WHERE vendor_id = ? AND product_id = ? AND serial_number = ?;
        """, (req["vendor_id"], req["product_id"], req["serial_number"]))

        # 2. Delete the request
        cursor.execute("DELETE FROM pending_requests WHERE request_id = ?;", (request_id,))

        # 3. Log permanent removal audit event
        event_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO server_events (
                event_id, client_id, timestamp, event_type, vendor_id, product_id,
                serial_number, device_id, device_type, description, decision, reason, received_at
            ) VALUES (?, 'CENTRAL_SERVER', ?, 'DEVICE_REMOVED', ?, ?, ?, '', ?, ?, 'REMOVED', 'Device record permanently removed from dashboard queue and allowlist', ?);
        """, (
            event_id, now, req["vendor_id"], req["product_id"], req["serial_number"],
            req["device_type"] or "OTHER", req["description"] or "", now
        ))
            
    return {
        "status": "success",
        "message": f"Request record {request_id} removed from dashboard queue",
        "request_id": request_id
    }

