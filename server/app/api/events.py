from fastapi import APIRouter, Query
from typing import List, Optional
from datetime import datetime, timezone, timedelta
from ..models.schemas import BatchEventsRequest, SecurityEventResponse, StatsResponse
from ..database.db import get_db, utc_now_iso

router = APIRouter(tags=["Security Events & Telemetry"])

@router.post("/api/events/batch", response_model=dict)
def ingest_batch_events(batch: BatchEventsRequest):
    now = utc_now_iso()
    inserted_count = 0
    with get_db() as conn:
        cursor = conn.cursor()
        for evt in batch.events:
            cursor.execute("""
                INSERT OR IGNORE INTO server_events (
                    event_id, client_id, timestamp, event_type,
                    vendor_id, product_id, serial_number, device_id,
                    device_type, description, decision, reason, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                evt.event_id, evt.client_id, evt.timestamp, evt.event_type,
                evt.vendor_id or "", evt.product_id or "", evt.serial_number or "",
                evt.device_id or "", evt.device_type or "OTHER", evt.description or "",
                evt.decision or "", evt.reason or "", now
            ))
            if cursor.rowcount > 0:
                inserted_count += 1

    return {
        "status": "success",
        "received": len(batch.events),
        "inserted": inserted_count,
        "timestamp": now
    }

@router.get("/api/events", response_model=List[SecurityEventResponse])
def get_events(limit: int = Query(50, ge=1, le=500), client_id: Optional[str] = None):
    events = []
    with get_db() as conn:
        cursor = conn.cursor()
        if client_id:
            cursor.execute("""
                SELECT event_id, client_id, timestamp, event_type,
                       vendor_id, product_id, serial_number, device_id,
                       device_type, description, decision, reason, received_at
                FROM server_events
                WHERE client_id = ?
                ORDER BY timestamp DESC
                LIMIT ?;
            """, (client_id, limit))
        else:
            cursor.execute("""
                SELECT event_id, client_id, timestamp, event_type,
                       vendor_id, product_id, serial_number, device_id,
                       device_type, description, decision, reason, received_at
                FROM server_events
                ORDER BY timestamp DESC
                LIMIT ?;
            """, (limit,))

        rows = cursor.fetchall()
        for r in rows:
            events.append(SecurityEventResponse(
                event_id=r["event_id"],
                client_id=r["client_id"],
                timestamp=r["timestamp"] or "",
                event_type=r["event_type"] or "",
                vendor_id=r["vendor_id"] or "",
                product_id=r["product_id"] or "",
                serial_number=r["serial_number"] or "",
                device_id=r["device_id"] or "",
                device_type=r["device_type"] or "OTHER",
                description=r["description"] or "",
                decision=r["decision"] or "",
                reason=r["reason"] or "",
                received_at=r["received_at"] or ""
            ))
            
    return events

@router.get("/api/stats", response_model=StatsResponse)
def get_dashboard_stats():
    threshold = (datetime.now(timezone.utc) - timedelta(seconds=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM clients WHERE last_heartbeat >= ?;", (threshold,))
        active_clients = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM master_allowlist WHERE status = 'APPROVED';")
        allowed_devices = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM pending_requests WHERE status = 'PENDING';")
        pending_requests = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM server_events;")
        total_events = cursor.fetchone()[0]

    return StatsResponse(
        active_clients=active_clients,
        allowed_devices=allowed_devices,
        pending_requests=pending_requests,
        total_events=total_events
    )
