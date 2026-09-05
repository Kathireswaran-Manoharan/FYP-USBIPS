from fastapi import APIRouter, HTTPException, status
from typing import List, Optional
import uuid
from ..models.schemas import (
    AllowlistDeviceCreate,
    AllowlistDeviceResponse,
    DeviceCheckRequest,
    DeviceCheckResponse
)
from ..database.db import get_db, utc_now_iso

router = APIRouter(prefix="/api/devices", tags=["Devices & Master Allowlist"])

@router.get("", response_model=List[AllowlistDeviceResponse])
def get_master_allowlist():
    devices = []
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, vendor_id, product_id, serial_number, device_type, description, manufacturer, status, created_at, updated_at
            FROM master_allowlist
            WHERE status = 'APPROVED'
            ORDER BY id DESC;
        """)
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

@router.delete("/{device_id}", response_model=dict)
def revoke_device_from_allowlist(device_id: int):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM master_allowlist WHERE id = ?;", (device_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Device not found in master allowlist")
            
    return {"status": "success", "message": f"Device ID {device_id} revoked from master allowlist"}

@router.post("/check-or-request", response_model=DeviceCheckResponse)
def check_or_request_device(data: DeviceCheckRequest):
    """
    Central Access-Control Policy Evaluation:
    1. If device is in master_allowlist -> Return ALLOW.
    2. If not, check if a pending_request exists for this device:
       - If approved -> Return ALLOW.
       - If declined -> Return BLOCK.
       - If pending -> Return ASK (awaiting admin decision).
       - If none -> Create new pending_request -> Return ASK.
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
                return DeviceCheckResponse(
                    decision="ALLOW",
                    request_id=req_id,
                    request_status="APPROVED",
                    message="Authorization approved by central administrator"
                )
            elif req_status == "DECLINED":
                return DeviceCheckResponse(
                    decision="BLOCK",
                    request_id=req_id,
                    request_status="DECLINED",
                    message="Authorization declined by central administrator"
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
