from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from ..models.schemas import PendingRequestResponse
from ..database.db import get_db, utc_now_iso

router = APIRouter(prefix="/api/requests", tags=["Authorization Requests"])

@router.get("", response_model=List[PendingRequestResponse])
def list_all_requests(status_filter: Optional[str] = Query(None, alias="status")):
    requests = []
    with get_db() as conn:
        cursor = conn.cursor()
        if status_filter:
            cursor.execute("""
                SELECT request_id, client_id, vendor_id, product_id, serial_number,
                       device_type, description, device_path, status, requested_at,
                       decided_at, decision_by
                FROM pending_requests
                WHERE status = ?
                ORDER BY requested_at DESC;
            """, (status_filter.upper(),))
        else:
            cursor.execute("""
                SELECT request_id, client_id, vendor_id, product_id, serial_number,
                       device_type, description, device_path, status, requested_at,
                       decided_at, decision_by
                FROM pending_requests
                ORDER BY requested_at DESC;
            """)
            
        rows = cursor.fetchall()
        for r in rows:
            requests.append(PendingRequestResponse(
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
                decision_by=r["decision_by"]
            ))
            
    return requests

@router.get("/pending", response_model=List[PendingRequestResponse])
def list_pending_requests():
    return list_all_requests(status_filter="PENDING")

@router.get("/{request_id}", response_model=PendingRequestResponse)
def get_request_by_id(request_id: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT request_id, client_id, vendor_id, product_id, serial_number,
                   device_type, description, device_path, status, requested_at,
                   decided_at, decision_by
            FROM pending_requests
            WHERE request_id = ?;
        """, (request_id,))
        r = cursor.fetchone()
        if not r:
            raise HTTPException(status_code=404, detail="Request not found")
            
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
            decision_by=r["decision_by"]
        )

@router.post("/{request_id}/approve", response_model=dict)
def approve_request(request_id: str, admin_user: str = "Admin"):
    now = utc_now_iso()
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. Fetch request details
        cursor.execute("""
            SELECT client_id, vendor_id, product_id, serial_number, device_type, description
            FROM pending_requests
            WHERE request_id = ?;
        """, (request_id,))
        req = cursor.fetchone()
        
        if not req:
            raise HTTPException(status_code=404, detail="Request not found")
            
        # 2. Update request status to APPROVED
        cursor.execute("""
            UPDATE pending_requests
            SET status = 'APPROVED', decided_at = ?, decision_by = ?
            WHERE request_id = ?;
        """, (now, admin_user, request_id))
        
        # 3. Add to master_allowlist
        cursor.execute("""
            INSERT INTO master_allowlist (
                vendor_id, product_id, serial_number, device_type, description,
                manufacturer, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'APPROVED', ?, ?)
            ON CONFLICT(vendor_id, product_id, serial_number) DO UPDATE SET
                status = 'APPROVED',
                device_type = excluded.device_type,
                description = excluded.description,
                updated_at = excluded.created_at;
        """, (
            req["vendor_id"], req["product_id"], req["serial_number"],
            req["device_type"], req["description"], "Approved Device",
            now, now
        ))
        
    return {
        "status": "success",
        "message": "Device request approved and added to central master allowlist",
        "request_id": request_id
    }

@router.post("/{request_id}/decline", response_model=dict)
def decline_request(request_id: str, admin_user: str = "Admin"):
    now = utc_now_iso()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE pending_requests
            SET status = 'DECLINED', decided_at = ?, decision_by = ?
            WHERE request_id = ?;
        """, (now, admin_user, request_id))
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Request not found")
            
    return {
        "status": "success",
        "message": "Device request declined. Device will be blocked on client.",
        "request_id": request_id
    }
