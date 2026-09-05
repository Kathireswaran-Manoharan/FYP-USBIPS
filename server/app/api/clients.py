from fastapi import APIRouter, HTTPException
from typing import List
from datetime import datetime, timezone, timedelta
from ..models.schemas import ClientRegister, ClientHeartbeat, ClientResponse
from ..database.db import get_db, utc_now_iso

router = APIRouter(prefix="/api/clients", tags=["Clients"])

@router.post("/register", response_model=dict)
def register_client(data: ClientRegister):
    now = utc_now_iso()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO clients (client_id, hostname, ip_address, os_version, agent_version, registered_at, last_heartbeat, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'ONLINE')
            ON CONFLICT(client_id) DO UPDATE SET
                hostname = excluded.hostname,
                ip_address = excluded.ip_address,
                os_version = excluded.os_version,
                agent_version = excluded.agent_version,
                last_heartbeat = excluded.last_heartbeat,
                status = 'ONLINE';
        """, (data.client_id, data.hostname, data.ip_address, data.os_version, data.agent_version, now, now))
    
    return {"status": "success", "message": "Client registered successfully", "client_id": data.client_id}

@router.post("/heartbeat", response_model=dict)
def client_heartbeat(data: ClientHeartbeat):
    now = utc_now_iso()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE clients
            SET last_heartbeat = ?, status = ?
            WHERE client_id = ?;
        """, (now, data.status or "ONLINE", data.client_id))
        
        if cursor.rowcount == 0:
            # If not yet registered, insert a minimal record
            cursor.execute("""
                INSERT INTO clients (client_id, registered_at, last_heartbeat, status)
                VALUES (?, ?, ?, ?);
            """, (data.client_id, now, now, data.status or "ONLINE"))
            
    return {"status": "success", "timestamp": now}

@router.get("", response_model=List[ClientResponse])
def list_clients():
    clients = []
    threshold = datetime.now(timezone.utc) - timedelta(seconds=90)
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT client_id, hostname, ip_address, os_version, agent_version, registered_at, last_heartbeat, status
            FROM clients
            ORDER BY last_heartbeat DESC;
        """)
        rows = cursor.fetchall()
        
        for row in rows:
            last_hb_str = row["last_heartbeat"]
            raw_status = (row["status"] or "ONLINE").upper()
            is_online = False
            if raw_status == "ONLINE" and last_hb_str:
                try:
                    dt = datetime.strptime(last_hb_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                    is_online = dt >= threshold
                except Exception:
                    is_online = False
            
            clients.append(ClientResponse(
                client_id=row["client_id"] or "",
                hostname=row["hostname"] or "Unknown",
                ip_address=row["ip_address"] or "N/A",
                os_version=row["os_version"] or "N/A",
                agent_version=row["agent_version"] or "1.0.0",
                registered_at=row["registered_at"] or "",
                last_heartbeat=row["last_heartbeat"] or "",
                status="ONLINE" if is_online else "OFFLINE",
                is_online=is_online
            ))
            
    return clients

@router.get("/{client_id}", response_model=ClientResponse)
def get_client(client_id: str):
    threshold = datetime.now(timezone.utc) - timedelta(seconds=90)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT client_id, hostname, ip_address, os_version, agent_version, registered_at, last_heartbeat, status
            FROM clients
            WHERE client_id = ?;
        """, (client_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Client '{client_id}' not found")

        last_hb_str = row["last_heartbeat"]
        raw_status = (row["status"] or "ONLINE").upper()
        is_online = False
        if raw_status == "ONLINE" and last_hb_str:
            try:
                dt = datetime.strptime(last_hb_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                is_online = dt >= threshold
            except Exception:
                is_online = False

        return ClientResponse(
            client_id=row["client_id"] or "",
            hostname=row["hostname"] or "Unknown",
            ip_address=row["ip_address"] or "N/A",
            os_version=row["os_version"] or "N/A",
            agent_version=row["agent_version"] or "1.0.0",
            registered_at=row["registered_at"] or "",
            last_heartbeat=row["last_heartbeat"] or "",
            status="ONLINE" if is_online else "OFFLINE",
            is_online=is_online
        )

@router.delete("/{client_id}", response_model=dict)
def delete_client(client_id: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM clients WHERE client_id = ?;", (client_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail=f"Client '{client_id}' not found")

    return {"status": "success", "message": f"Client '{client_id}' removed from fleet"}
