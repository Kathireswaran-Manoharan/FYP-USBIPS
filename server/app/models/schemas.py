from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

# --- Client Schemas ---
class ClientRegister(BaseModel):
    client_id: str
    hostname: Optional[str] = ""
    ip_address: Optional[str] = ""
    os_version: Optional[str] = ""
    agent_version: Optional[str] = "1.0.0"

class ClientHeartbeat(BaseModel):
    client_id: str
    status: Optional[str] = "ONLINE"

class ClientResponse(BaseModel):
    client_id: str
    hostname: str
    ip_address: str
    os_version: str
    agent_version: str
    registered_at: str
    last_heartbeat: str
    status: str
    is_online: bool = True

# --- Master Allowlist Schemas ---
class AllowlistDeviceCreate(BaseModel):
    vendor_id: str = Field(..., min_length=1, max_length=10)
    product_id: str = Field(..., min_length=1, max_length=10)
    serial_number: str = Field(..., min_length=1)
    device_type: Optional[str] = "OTHER"
    description: Optional[str] = ""
    manufacturer: Optional[str] = ""

class AllowlistDeviceResponse(BaseModel):
    id: int
    vendor_id: str
    product_id: str
    serial_number: str
    device_type: str
    description: str
    manufacturer: str
    status: str
    created_at: str
    updated_at: Optional[str] = None

# --- Access Check & Pending Request Schemas ---
class DeviceCheckRequest(BaseModel):
    client_id: str
    vendor_id: str
    product_id: str
    serial_number: str
    device_type: Optional[str] = "OTHER"
    description: Optional[str] = ""
    device_path: Optional[str] = ""

class DeviceCheckResponse(BaseModel):
    decision: str  # ALLOW, ASK, BLOCK
    request_id: Optional[str] = None
    request_status: Optional[str] = None  # PENDING, APPROVED, DECLINED
    message: str

class PendingRequestResponse(BaseModel):
    request_id: str
    client_id: str
    vendor_id: str
    product_id: str
    serial_number: str
    device_type: str
    description: str
    device_path: str
    status: str
    requested_at: str
    decided_at: Optional[str] = None
    decision_by: Optional[str] = None

# --- Security Event Schemas ---
class SecurityEventIngest(BaseModel):
    event_id: str
    client_id: str
    timestamp: str
    event_type: str
    vendor_id: Optional[str] = ""
    product_id: Optional[str] = ""
    serial_number: Optional[str] = ""
    device_id: Optional[str] = ""
    device_type: Optional[str] = "OTHER"
    description: Optional[str] = ""
    decision: Optional[str] = ""
    reason: Optional[str] = ""

class BatchEventsRequest(BaseModel):
    events: List[SecurityEventIngest]

class SecurityEventResponse(BaseModel):
    event_id: str
    client_id: str
    timestamp: str
    event_type: str
    vendor_id: str
    product_id: str
    serial_number: str
    device_id: str
    device_type: str
    description: str
    decision: str
    reason: str
    received_at: str

# --- Dashboard Stats ---
class StatsResponse(BaseModel):
    active_clients: int
    allowed_devices: int
    pending_requests: int
    total_events: int
