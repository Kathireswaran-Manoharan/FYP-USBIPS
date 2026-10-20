from fastapi import APIRouter, HTTPException, status, Query
from typing import List, Optional
import uuid
from ..models.schemas import (
    AllowlistDeviceCreate,
    AllowlistDeviceUpdate,
    AllowlistDeviceResponse,
    DeviceCheckRequest,
    DeviceCheckResponse,
    DeviceRecoveryRequest
)
from ..database.db import get_db, utc_now_iso

router = APIRouter(prefix="/api/devices", tags=["Devices & Master Allowlist"])

@router.get("", response_model=List[AllowlistDeviceResponse])
def get_master_allowlist(
    search: Optional[str] = Query(None, description="Search by VID, PID, serial, description or manufacturer"),
    device_type: Optional[str] = Query(None, description="Filter by device class (HID, STORAGE, NETWORK, OTHER)")
):
    """
    Task 9: GET /api/devices - List allowlisted devices with optional search & filter.
    """
    devices = []
    with get_db() as conn:
        cursor = conn.cursor()
        
        query = """
            SELECT id, vendor_id, product_id, serial_number, device_type, description, manufacturer, status, created_at, updated_at,
                   duration_minutes, expires_at, decision_reason
            FROM master_allowlist
            WHERE status = 'APPROVED'
        """
        params = []

        if device_type:
            query += " AND UPPER(device_type) = ?"
            params.append(device_type.upper())

        if search:
            query += " AND (vendor_id LIKE ? OR product_id LIKE ? OR serial_number LIKE ? OR description LIKE ? OR manufacturer LIKE ?)"
            term = f"%{search}%"
            params.extend([term, term, term, term, term])

        query += " ORDER BY id DESC;"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        now = utc_now_iso()
        for r in rows:
            # Check expiry
            exp = r["expires_at"] if "expires_at" in r.keys() else None
            dev_status = r["status"]
            if exp and exp < now:
                cursor.execute("UPDATE master_allowlist SET status = 'EXPIRED' WHERE id = ?;", (r["id"],))
                continue

            devices.append(AllowlistDeviceResponse(
                id=r["id"],
                vendor_id=r["vendor_id"],
                product_id=r["product_id"],
                serial_number=r["serial_number"],
                device_type=r["device_type"] or "OTHER",
                description=r["description"] or "",
                manufacturer=r["manufacturer"] or "",
                status=dev_status,
                created_at=r["created_at"] or "",
                updated_at=r["updated_at"],
                duration_minutes=r["duration_minutes"] if "duration_minutes" in r.keys() else None,
                expires_at=exp,
                decision_reason=r["decision_reason"] if "decision_reason" in r.keys() else None
            ))
    return devices

@router.post("", response_model=dict, status_code=status.HTTP_201_CREATED)
def add_device_to_allowlist(device: AllowlistDeviceCreate):
    """
    Task 9: POST /api/devices - Add an allowlist record.
    """
    now = utc_now_iso()
    with get_db() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO master_allowlist (vendor_id, product_id, serial_number, device_type, description, manufacturer, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'APPROVED', ?, ?)
                ON CONFLICT(vendor_id, product_id, serial_number) DO UPDATE SET
                    status = 'APPROVED',
                    device_type = excluded.device_type,
                    description = excluded.description,
                    manufacturer = excluded.manufacturer,
                    updated_at = excluded.created_at;
            """, (
                device.vendor_id.upper(),
                device.product_id.upper(),
                device.serial_number,
                device.device_type or "OTHER",
                device.description or "",
                device.manufacturer or "",
                now,
                now
            ))
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to add device: {str(e)}")

    return {"status": "success", "message": "Device added to master allowlist"}

@router.get("/{device_id}", response_model=AllowlistDeviceResponse)
def get_device_by_id(device_id: int):
    """
    Task 9: GET /api/devices/{id} - Retrieve a single device.
    """
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, vendor_id, product_id, serial_number, device_type, description, manufacturer, status, created_at, updated_at
            FROM master_allowlist
            WHERE id = ?;
        """, (device_id,))
        r = cursor.fetchone()
        if not r:
            raise HTTPException(status_code=404, detail=f"Device ID {device_id} not found")

        return AllowlistDeviceResponse(
            id=r["id"],
            vendor_id=r["vendor_id"],
            product_id=r["product_id"],
            serial_number=r["serial_number"],
            device_type=r["device_type"] or "OTHER",
            description=r["description"] or "",
            manufacturer=r["manufacturer"] or "",
            status=r["status"],
            created_at=r["created_at"] or "",
            updated_at=r["updated_at"]
        )

@router.put("/{device_id}", response_model=dict)
@router.patch("/{device_id}", response_model=dict)
def update_device(device_id: int, update: AllowlistDeviceUpdate):
    """
    Task 9: PUT/PATCH /api/devices/{id} - Update device details.
    """
    now = utc_now_iso()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM master_allowlist WHERE id = ?;", (device_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail=f"Device ID {device_id} not found")

        updates = []
        params = []

        if update.device_type is not None:
            updates.append("device_type = ?")
            params.append(update.device_type)
        if update.description is not None:
            updates.append("description = ?")
            params.append(update.description)
        if update.manufacturer is not None:
            updates.append("manufacturer = ?")
            params.append(update.manufacturer)
        if update.status is not None:
            updates.append("status = ?")
            params.append(update.status.upper())

        if not updates:
            return {"status": "success", "message": "No changes specified"}

        updates.append("updated_at = ?")
        params.append(now)
        params.append(device_id)

        sql = f"UPDATE master_allowlist SET {', '.join(updates)} WHERE id = ?;"
        cursor.execute(sql, params)

    return {"status": "success", "message": f"Device ID {device_id} updated successfully"}

@router.delete("/{device_id}", response_model=dict)
def revoke_device_from_allowlist(device_id: int):
    """
    Task 9 & 10: DELETE /api/devices/{id} - Revoke/remove a device.
    Purges device from master_allowlist and marks all associated requests as REVOKED so clients enforce block.
    """
    now = utc_now_iso()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT vendor_id, product_id, serial_number, device_type, description FROM master_allowlist WHERE id = ?;", (device_id,))
        dev = cursor.fetchone()
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found in master allowlist")

        # 1. Delete from master_allowlist
        cursor.execute("DELETE FROM master_allowlist WHERE id = ?;", (device_id,))

        # 2. Mark any pending/approved requests for this hardware as REVOKED, or insert a REVOKED record
        cursor.execute("""
            UPDATE pending_requests
            SET status = 'REVOKED', decided_at = ?, decision_by = 'Administrator'
            WHERE vendor_id = ? AND product_id = ? AND serial_number = ?;
        """, (now, dev["vendor_id"], dev["product_id"], dev["serial_number"]))
        if cursor.rowcount == 0:
            cursor.execute("""
                INSERT INTO pending_requests (
                    request_id, client_id, vendor_id, product_id, serial_number,
                    device_type, description, status, requested_at, decided_at, decision_by
                ) VALUES (?, 'ALL_CLIENTS', ?, ?, ?, ?, ?, 'REVOKED', ?, ?, 'Administrator');
            """, (
                str(uuid.uuid4()), dev["vendor_id"], dev["product_id"], dev["serial_number"],
                dev["device_type"] or "OTHER", dev["description"] or "", now, now
            ))

        # 3. Log revocation event in central telemetry
        event_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO server_events (
                event_id, client_id, timestamp, event_type, vendor_id, product_id,
                serial_number, device_id, device_type, description, decision, reason, received_at
            ) VALUES (?, 'CENTRAL_SERVER', ?, 'DEVICE_BLOCKED', ?, ?, ?, '', ?, ?, 'BLOCK', 'Authorization revoked by administrator', ?);
        """, (
            event_id, now, dev["vendor_id"], dev["product_id"], dev["serial_number"],
            dev["device_type"] or "OTHER", dev["description"] or "", now
        ))
            
    return {"status": "success", "message": f"Device ID {device_id} revoked from master allowlist"}

@router.post("/check", response_model=DeviceCheckResponse)
@router.post("/check-or-request", response_model=DeviceCheckResponse)
def check_or_request_device(data: DeviceCheckRequest):
    """
    Task 9 & 10: POST /api/devices/check - Allow the client to query central policy when required.
    """
    vid = data.vendor_id.upper()
    pid = data.product_id.upper()
    serial = data.serial_number
    now = utc_now_iso()

    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Check Master Allowlist & Expiry
        cursor.execute("""
            SELECT id, status, expires_at, duration_minutes FROM master_allowlist
            WHERE vendor_id = ? AND product_id = ? AND serial_number = ? AND status = 'APPROVED';
        """, (vid, pid, serial))
        allowed = cursor.fetchone()
        
        if allowed:
            exp = allowed["expires_at"]
            if exp and exp < now:
                cursor.execute("UPDATE master_allowlist SET status = 'EXPIRED' WHERE id = ?;", (allowed["id"],))
                cursor.execute("UPDATE pending_requests SET status = 'EXPIRED' WHERE vendor_id = ? AND product_id = ? AND serial_number = ?;", (vid, pid, serial))
                return DeviceCheckResponse(
                    decision="BLOCK",
                    request_status="EXPIRED",
                    message="Device authorization expired. Central administrator re-approval required.",
                    duration_minutes=allowed["duration_minutes"],
                    expires_at=exp
                )
            return DeviceCheckResponse(
                decision="ALLOW",
                request_status="APPROVED",
                message="Device is registered in central master allowlist",
                duration_minutes=allowed["duration_minutes"],
                expires_at=exp
            )

        # 1b. Check for challenge replay across requests
        if data.captcha_challenge_id:
            cursor.execute("""
                SELECT request_id, captcha_result FROM pending_requests
                WHERE captcha_challenge_id = ? AND (vendor_id != ? OR product_id != ? OR serial_number != ?);
            """, (data.captcha_challenge_id, vid, pid, serial))
            replayed = cursor.fetchone()
            if replayed:
                data.captcha_result = "REPLAY_ATTEMPT"
                data.recommendation = "REJECT"
                data.severity = "CRITICAL"
                data.assessment_summary = "Replayed CAPTCHA challenge ID detected; rejected by central server"

        # 2. Safety Rule: If device has critical violations, reject immediately
        if data.recommendation == "REJECT" or data.severity == "CRITICAL":
            req_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO pending_requests (
                    request_id, client_id, vendor_id, product_id, serial_number,
                    device_type, description, device_path, status, requested_at,
                    session_id, captcha_challenge_id, captcha_result, verification_method,
                    verification_start, verification_completed, attempt_count, verification_score,
                    verification_duration_seconds, temp_release_applied, temp_release_duration_seconds,
                    re_quarantine_result, current_enforcement_state, total_risk_score, severity,
                    recommendation, assessment_summary, algorithms_json, decided_at, decision_by, decision_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'DECLINED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Central Policy', 'Critical Security Violation');
            """, (
                req_id, data.client_id, vid, pid, serial,
                data.device_type or "OTHER", data.description or "", data.device_path or "", now,
                data.session_id or "", data.captcha_challenge_id or "", data.captcha_result or "NOT_COMPLETED",
                data.verification_method or "NONE", data.verification_start or "", data.verification_completed or "",
                data.attempt_count or 0, data.verification_score or 0, data.verification_duration_seconds or 0.0,
                1 if data.temp_release_applied else 0, data.temp_release_duration_seconds or 0.0,
                data.re_quarantine_result or "", data.current_enforcement_state or "QUARANTINED",
                data.total_risk_score or 0, data.severity or "CRITICAL", data.recommendation or "REJECT",
                data.assessment_summary or "", data.algorithms_json or "{}", now
            ))
            return DeviceCheckResponse(
                decision="BLOCK",
                request_id=req_id,
                request_status="DECLINED",
                message=f"Central policy blocked device: Critical violations detected ({data.assessment_summary})"
            )

        # 3. Check Existing Requests for this Hardware Triplet
        cursor.execute("""
            SELECT request_id, status, expires_at, duration_minutes, decision_reason, decision_by FROM pending_requests
            WHERE vendor_id = ? AND product_id = ? AND serial_number = ?
            ORDER BY requested_at DESC LIMIT 1;
        """, (vid, pid, serial))
        existing_req = cursor.fetchone()

        if existing_req:
            req_id = existing_req["request_id"]
            req_status = existing_req["status"]
            exp = existing_req["expires_at"] if "expires_at" in existing_req.keys() else None
            dec_by = existing_req["decision_by"] if "decision_by" in existing_req.keys() else None

            # Determine if this reconnection attempt is eligible to transition to PENDING:
            # 1. Device must not have critical violations (recommendation != 'REJECT', severity != 'CRITICAL')
            # 2. For HID input devices (mouse, keyboard): human CAPTCHA verification is mandatory
            # 3. For non-HID devices (storage, network): CAPTCHA is NOT_APPLICABLE, so CAPTCHA is waived
            is_hid_device = (
                (data.device_type and data.device_type.upper() in ("HID", "MOUSE", "KEYBOARD")) or
                (data.captcha_result and data.captcha_result.upper() not in ("NOT_APPLICABLE", "NONE", ""))
            )
            is_captcha_passed = data.captcha_result in ("PASSED", "MOUSE_CAPTCHA_PASSED", "KEYBOARD_CAPTCHA_PASSED")
            is_non_hid_eligible = (
                (not is_hid_device) and
                data.device_type and
                data.device_type.upper() in ("STORAGE", "NETWORK", "COMPOSITE", "OTHER") and
                data.captcha_result in ("NOT_APPLICABLE", "NONE", "", None) and
                data.recommendation is not None
            )
            has_no_critical_risk = (data.recommendation != "REJECT" and data.severity != "CRITICAL")
            is_eligible_reconnect = (is_captcha_passed or is_non_hid_eligible) and has_no_critical_risk

            # Genuine explicit revocation: maintain fail-closed block unless freshly re-verified or clean non-HID re-submission
            if req_status == "REVOKED":
                if is_eligible_reconnect:
                    cursor.execute("""
                        UPDATE pending_requests SET
                            client_id = ?, device_type = ?, description = ?, device_path = ?,
                            status = 'PENDING', requested_at = ?,
                            session_id = ?, captcha_challenge_id = ?, captcha_result = ?, verification_method = ?,
                            verification_start = ?, verification_completed = ?, attempt_count = ?, verification_score = ?,
                            verification_duration_seconds = ?, temp_release_applied = ?, temp_release_duration_seconds = ?,
                            re_quarantine_result = ?, current_enforcement_state = ?, total_risk_score = ?, severity = ?,
                            recommendation = ?, assessment_summary = ?, algorithms_json = ?,
                            decided_at = NULL, decision_by = NULL, decision_reason = NULL,
                            expires_at = NULL, duration_minutes = NULL
                        WHERE request_id = ?;
                    """, (
                        data.client_id, data.device_type or "OTHER", data.description or "", data.device_path or "",
                        now,
                        data.session_id or "", data.captcha_challenge_id or "", data.captcha_result or "NOT_COMPLETED",
                        data.verification_method or "NONE", data.verification_start or "", data.verification_completed or "",
                        data.attempt_count or 0, data.verification_score or 0, data.verification_duration_seconds or 0.0,
                        1 if data.temp_release_applied else 0, data.temp_release_duration_seconds or 0.0,
                        data.re_quarantine_result or "", data.current_enforcement_state or "QUARANTINED",
                        data.total_risk_score or 0, data.severity or "LOW", data.recommendation or "REVIEW",
                        data.assessment_summary or "", data.algorithms_json or "{}", req_id
                    ))
                    res_msg = (
                        "Device completed human verification after revocation; awaiting administrator re-approval."
                        if is_hid_device
                        else "Non-HID device resubmitted after revocation; awaiting administrator re-approval."
                    )
                    return DeviceCheckResponse(
                        decision="ASK",
                        request_id=req_id,
                        request_status="PENDING",
                        message=res_msg
                    )
                return DeviceCheckResponse(
                    decision="BLOCK",
                    request_id=req_id,
                    request_status="REVOKED",
                    message="Authorization was revoked by central administrator"
                )
            elif req_status == "DECLINED":
                # If device was declined automatically by Central Policy (e.g., prior anomaly or CAPTCHA failure),
                # but now connects in a clean state (with passed CAPTCHA for HID or clean profile for non-HID),
                # submit as PENDING for admin review.
                # Explicit administrator declines (decision_by != 'Central Policy') are strictly preserved as BLOCK.
                is_auto_policy_decline = (dec_by == "Central Policy" or not dec_by)
                if is_auto_policy_decline and is_eligible_reconnect:
                    cursor.execute("""
                        UPDATE pending_requests SET
                            client_id = ?, device_type = ?, description = ?, device_path = ?,
                            status = 'PENDING', requested_at = ?,
                            session_id = ?, captcha_challenge_id = ?, captcha_result = ?, verification_method = ?,
                            verification_start = ?, verification_completed = ?, attempt_count = ?, verification_score = ?,
                            verification_duration_seconds = ?, temp_release_applied = ?, temp_release_duration_seconds = ?,
                            re_quarantine_result = ?, current_enforcement_state = ?, total_risk_score = ?, severity = ?,
                            recommendation = ?, assessment_summary = ?, algorithms_json = ?,
                            decided_at = NULL, decision_by = NULL, decision_reason = NULL
                        WHERE request_id = ?;
                    """, (
                        data.client_id, data.device_type or "OTHER", data.description or "", data.device_path or "",
                        now,
                        data.session_id or "", data.captcha_challenge_id or "", data.captcha_result or "NOT_COMPLETED",
                        data.verification_method or "NONE", data.verification_start or "", data.verification_completed or "",
                        data.attempt_count or 0, data.verification_score or 0, data.verification_duration_seconds or 0.0,
                        1 if data.temp_release_applied else 0, data.temp_release_duration_seconds or 0.0,
                        data.re_quarantine_result or "", data.current_enforcement_state or "QUARANTINED",
                        data.total_risk_score or 0, data.severity or "LOW", data.recommendation or "REVIEW",
                        data.assessment_summary or "", data.algorithms_json or "{}", req_id
                    ))
                    res_msg = (
                        "Device re-verified via CAPTCHA; awaiting administrator decision in Central Management UI"
                        if is_hid_device
                        else "Non-HID device resubmitted for evaluation; awaiting administrator decision in Central Management UI"
                    )
                    return DeviceCheckResponse(
                        decision="ASK",
                        request_id=req_id,
                        request_status="PENDING",
                        message=res_msg
                    )
                return DeviceCheckResponse(
                    decision="BLOCK",
                    request_id=req_id,
                    request_status="DECLINED",
                    message="Authorization declined by central administrator"
                )
            elif req_status == "EXPIRED" or (exp and exp < now):
                # If device has freshly completed human CAPTCHA challenge without critical violations (or clean non-HID),
                # allow re-submission as PENDING for administrator re-approval.
                if is_eligible_reconnect:
                    cursor.execute("""
                        UPDATE pending_requests SET
                            client_id = ?, device_type = ?, description = ?, device_path = ?,
                            status = 'PENDING', requested_at = ?,
                            session_id = ?, captcha_challenge_id = ?, captcha_result = ?, verification_method = ?,
                            verification_start = ?, verification_completed = ?, attempt_count = ?, verification_score = ?,
                            verification_duration_seconds = ?, temp_release_applied = ?, temp_release_duration_seconds = ?,
                            re_quarantine_result = ?, current_enforcement_state = ?, total_risk_score = ?, severity = ?,
                            recommendation = ?, assessment_summary = ?, algorithms_json = ?,
                            decided_at = NULL, decision_by = NULL, decision_reason = NULL,
                            expires_at = NULL, duration_minutes = NULL
                        WHERE request_id = ?;
                    """, (
                        data.client_id, data.device_type or "OTHER", data.description or "", data.device_path or "",
                        now,
                        data.session_id or "", data.captcha_challenge_id or "", data.captcha_result or "NOT_COMPLETED",
                        data.verification_method or "NONE", data.verification_start or "", data.verification_completed or "",
                        data.attempt_count or 0, data.verification_score or 0, data.verification_duration_seconds or 0.0,
                        1 if data.temp_release_applied else 0, data.temp_release_duration_seconds or 0.0,
                        data.re_quarantine_result or "", data.current_enforcement_state or "QUARANTINED",
                        data.total_risk_score or 0, data.severity or "LOW", data.recommendation or "REVIEW",
                        data.assessment_summary or "", data.algorithms_json or "{}", req_id
                    ))
                    res_msg = (
                        "Device re-verified via CAPTCHA; awaiting administrator re-approval in Central Management UI"
                        if is_hid_device
                        else "Non-HID device resubmitted; awaiting administrator re-approval in Central Management UI"
                    )
                    return DeviceCheckResponse(
                        decision="ASK",
                        request_id=req_id,
                        request_status="PENDING",
                        message=res_msg
                    )
                if req_status != "EXPIRED":
                    cursor.execute("UPDATE pending_requests SET status = 'EXPIRED' WHERE request_id = ?;", (req_id,))
                return DeviceCheckResponse(
                    decision="BLOCK",
                    request_id=req_id,
                    request_status="EXPIRED",
                    message="Device authorization expired. Central administrator re-approval required.",
                    duration_minutes=existing_req["duration_minutes"] if "duration_minutes" in existing_req.keys() else None,
                    expires_at=exp
                )
            elif req_status in ("PENDING", "APPROVED"):
                # If previously APPROVED but missing from master_allowlist, it is no longer allowlisted.
                # Never manufacture a revocation! Route it to PENDING for administrator review.
                cursor.execute("""
                    UPDATE pending_requests SET
                        client_id = ?, device_type = ?, description = ?, device_path = ?,
                        status = 'PENDING', requested_at = ?,
                        session_id = ?, captcha_challenge_id = ?, captcha_result = ?, verification_method = ?,
                        verification_start = ?, verification_completed = ?, attempt_count = ?, verification_score = ?,
                        verification_duration_seconds = ?, temp_release_applied = ?, temp_release_duration_seconds = ?,
                        re_quarantine_result = ?, current_enforcement_state = ?, total_risk_score = ?, severity = ?,
                        recommendation = ?, assessment_summary = ?, algorithms_json = ?,
                        decided_at = NULL, decision_by = NULL, decision_reason = NULL
                    WHERE request_id = ?;
                """, (
                    data.client_id, data.device_type or "OTHER", data.description or "", data.device_path or "",
                    now,
                    data.session_id or "", data.captcha_challenge_id or "", data.captcha_result or "NOT_COMPLETED",
                    data.verification_method or "NONE", data.verification_start or "", data.verification_completed or "",
                    data.attempt_count or 0, data.verification_score or 0, data.verification_duration_seconds or 0.0,
                    1 if data.temp_release_applied else 0, data.temp_release_duration_seconds or 0.0,
                    data.re_quarantine_result or "", data.current_enforcement_state or "QUARANTINED",
                    data.total_risk_score or 0, data.severity or "LOW", data.recommendation or "REVIEW",
                    data.assessment_summary or "", data.algorithms_json or "{}", req_id
                ))
                return DeviceCheckResponse(
                    decision="ASK",
                    request_id=req_id,
                    request_status="PENDING",
                    message="Awaiting administrator decision in Central Management UI"
                )

        # 4. Create New Pending Request with complete assessment metadata
        req_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO pending_requests (
                request_id, client_id, vendor_id, product_id, serial_number,
                device_type, description, device_path, status, requested_at,
                session_id, captcha_challenge_id, captcha_result, verification_method,
                verification_start, verification_completed, attempt_count, verification_score,
                verification_duration_seconds, temp_release_applied, temp_release_duration_seconds,
                re_quarantine_result, current_enforcement_state, total_risk_score, severity,
                recommendation, assessment_summary, algorithms_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            req_id, data.client_id, vid, pid, serial,
            data.device_type or "OTHER", data.description or "", data.device_path or "",
            now,
            data.session_id or "", data.captcha_challenge_id or "", data.captcha_result or "NOT_COMPLETED",
            data.verification_method or "NONE", data.verification_start or "", data.verification_completed or "",
            data.attempt_count or 0, data.verification_score or 0, data.verification_duration_seconds or 0.0,
            1 if data.temp_release_applied else 0, data.temp_release_duration_seconds or 0.0,
            data.re_quarantine_result or "", data.current_enforcement_state or "QUARANTINED",
            data.total_risk_score or 0, data.severity or "LOW", data.recommendation or "REVIEW",
            data.assessment_summary or "", data.algorithms_json or "{}"
        ))

    return DeviceCheckResponse(
        decision="ASK",
        request_id=req_id,
        request_status="PENDING",
        message="New device authorization request submitted with full assessment to Central Management UI"
    )

@router.post("/recover", response_model=dict)
def recover_device(data: DeviceRecoveryRequest):
    """
    Administrator recovery procedure for devices blocked by unverified scan errors or incorrect drive attribution.
    Genuinely confirmed malware requires explicit force_override=True with admin justification.
    """
    vid = data.vendor_id.upper()
    pid = data.product_id.upper()
    serial = data.serial_number
    admin = data.admin_user or "Administrator"
    reason = data.reason or "Administrator cleared unverified scan error revocation"
    now = utc_now_iso()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT request_id, status, decision_reason, total_risk_score, severity, recommendation
            FROM pending_requests
            WHERE vendor_id = ? AND product_id = ? AND serial_number = ? AND status = 'REVOKED';
        """, (vid, pid, serial))
        revoked_rows = cursor.fetchall()

        if not revoked_rows:
            cursor.execute("""
                SELECT id, status FROM master_allowlist
                WHERE vendor_id = ? AND product_id = ? AND serial_number = ? AND status = 'REVOKED';
            """, (vid, pid, serial))
            if not cursor.fetchone():
                return {
                    "status": "success",
                    "message": f"Device {vid}:{pid} ({serial}) has no active REVOKED records on central server."
                }

        # Check evidence for unverified scan errors vs confirmed malware
        for row in revoked_rows:
            dec_reason = row["decision_reason"] or ""
            is_unverified = (
                "Win32/MalwareSignature.Generic" in dec_reason or
                "0x80508023" in dec_reason or
                "drive A:" in dec_reason or
                "drive A:\\" in dec_reason or
                "drive B:" in dec_reason or
                "drive B:\\" in dec_reason or
                "Completion Failed" in dec_reason or
                "NOT_SCANNED" in dec_reason or
                "SCAN_FAILED" in dec_reason
            )
            if not is_unverified and not data.force_override:
                raise HTTPException(
                    status_code=400,
                    detail=f"Device {vid}:{pid} has a confirmed security revocation ('{dec_reason}'). "
                           f"Automatic recovery rejected; explicit admin override (force_override=True) required."
                )

        cursor.execute("""
            UPDATE pending_requests
            SET status = 'PENDING', decided_at = NULL, decision_by = NULL,
                decision_reason = ?
            WHERE vendor_id = ? AND product_id = ? AND serial_number = ? AND status = 'REVOKED';
        """, (f"Revocation cleared by {admin}: {reason}", vid, pid, serial))

        # Log recovery event in telemetry
        event_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO server_events (
                event_id, client_id, timestamp, event_type, vendor_id, product_id,
                serial_number, device_id, device_type, description, decision, reason, received_at
            ) VALUES (?, 'CENTRAL_SERVER', ?, 'USER_APPROVED', ?, ?, ?, '', 'STORAGE',
                     'Device recovered from false-positive revocation', 'ASK', ?, ?);
        """, (event_id, now, vid, pid, serial, f"Administrator {admin} recovered device: {reason}", now))

    return {
        "status": "success",
        "message": f"Device {vid}:{pid} ({serial}) recovered from revocation tombstone."
    }

