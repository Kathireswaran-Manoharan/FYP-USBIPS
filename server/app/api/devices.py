from fastapi import APIRouter, HTTPException, status, Query
from typing import List, Optional
import uuid
from ..models.schemas import (
    AllowlistDeviceCreate,
    AllowlistDeviceUpdate,
    AllowlistDeviceResponse,
    DeviceCheckRequest,
    DeviceCheckResponse
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
            SELECT id, vendor_id, product_id, serial_number, device_type, description, manufacturer, status, created_at, updated_at
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
        for r in rows:
            devices.append(AllowlistDeviceResponse(
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

    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Check Master Allowlist
        cursor.execute("""
            SELECT id FROM master_allowlist
            WHERE vendor_id = ? AND product_id = ? AND serial_number = ? AND status = 'APPROVED';
        """, (vid, pid, serial))
        allowed = cursor.fetchone()
        
        if allowed:
            return DeviceCheckResponse(
                decision="ALLOW",
                request_status="APPROVED",
                message="Device is registered in central master allowlist"
            )

        # 2. Check Existing Pending Request
        cursor.execute("""
            SELECT request_id, status FROM pending_requests
            WHERE vendor_id = ? AND product_id = ? AND serial_number = ?
            ORDER BY requested_at DESC LIMIT 1;
        """, (vid, pid, serial))
        existing_req = cursor.fetchone()

        if existing_req:
            req_id = existing_req["request_id"]
            req_status = existing_req["status"]

            if req_status == "APPROVED":
                # Master allowlist check failed, so device was revoked!
                cursor.execute("UPDATE pending_requests SET status = 'REVOKED' WHERE request_id = ?;", (req_id,))
                return DeviceCheckResponse(
                    decision="BLOCK",
                    request_id=req_id,
                    request_status="REVOKED",
                    message="Authorization was revoked by central administrator"
                )
            elif req_status in ("DECLINED", "REVOKED"):
                return DeviceCheckResponse(
                    decision="BLOCK",
                    request_id=req_id,
                    request_status=req_status,
                    message=f"Authorization {req_status.lower()} by central administrator"
                )
            else:
                return DeviceCheckResponse(
                    decision="ASK",
                    request_id=req_id,
                    request_status="PENDING",
                    message="Awaiting administrator decision in Central Management UI"
                )

        # 3. Create New Pending Request
        req_id = str(uuid.uuid4())
        now = utc_now_iso()
        cursor.execute("""
            INSERT INTO pending_requests (
                request_id, client_id, vendor_id, product_id, serial_number,
                device_type, description, device_path, status, requested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?);
        """, (
            req_id, data.client_id, vid, pid, serial,
            data.device_type or "OTHER", data.description or "", data.device_path or "",
            now
        ))

    return DeviceCheckResponse(
        decision="ASK",
        request_id=req_id,
        request_status="PENDING",
        message="New device authorization request submitted to Central Management UI"
    )
