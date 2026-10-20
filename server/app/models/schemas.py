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

class AllowlistDeviceUpdate(BaseModel):
    device_type: Optional[str] = None
    description: Optional[str] = None
    manufacturer: Optional[str] = None
    status: Optional[str] = None

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
    duration_minutes: Optional[int] = None
    expires_at: Optional[str] = None
    decision_reason: Optional[str] = None

# --- Access Check & Pending Request Schemas ---
class DeviceCheckRequest(BaseModel):
    client_id: str
    vendor_id: str
    product_id: str
    serial_number: str
    device_type: Optional[str] = "OTHER"
    description: Optional[str] = ""
    device_path: Optional[str] = ""
    session_id: Optional[str] = ""
    captcha_challenge_id: Optional[str] = ""
    captcha_result: Optional[str] = "NOT_COMPLETED"  # PASSED, FAILED, TIMEOUT, EXPIRED, REPLAY_ATTEMPT, NOT_COMPLETED
    verification_method: Optional[str] = "NONE"      # KEYBOARD_TYPING, MOUSE_CLICK, NONE
    verification_start: Optional[str] = ""
    verification_completed: Optional[str] = ""
    attempt_count: Optional[int] = 0
    verification_score: Optional[int] = 0
    verification_duration_seconds: Optional[float] = 0.0
    temp_release_applied: Optional[bool] = False
    temp_release_duration_seconds: Optional[float] = 0.0
    re_quarantine_result: Optional[str] = ""
    current_enforcement_state: Optional[str] = "QUARANTINED"
    total_risk_score: Optional[int] = 0
    severity: Optional[str] = "LOW"
    recommendation: Optional[str] = "REVIEW"
    assessment_summary: Optional[str] = ""
    algorithms_json: Optional[str] = "{}"

class DeviceCheckResponse(BaseModel):
    decision: str  # ALLOW, ASK, BLOCK
    request_id: Optional[str] = None
    request_status: Optional[str] = None  # PENDING, APPROVED, DECLINED, REVOKED, EXPIRED
    message: str
    duration_minutes: Optional[int] = None
    expires_at: Optional[str] = None

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
    decision_reason: Optional[str] = None
    session_id: Optional[str] = ""
    captcha_challenge_id: Optional[str] = ""
    captcha_result: Optional[str] = "NOT_COMPLETED"
    verification_method: Optional[str] = "NONE"
    verification_start: Optional[str] = ""
    verification_completed: Optional[str] = ""
    attempt_count: Optional[int] = 0
    verification_score: Optional[int] = 0
    verification_duration_seconds: Optional[float] = 0.0
    temp_release_applied: Optional[bool] = False
    temp_release_duration_seconds: Optional[float] = 0.0
    re_quarantine_result: Optional[str] = ""
    current_enforcement_state: Optional[str] = "QUARANTINED"
    total_risk_score: Optional[int] = 0
    severity: Optional[str] = "LOW"
    recommendation: Optional[str] = "REVIEW"
    assessment_summary: Optional[str] = ""
    algorithms_json: Optional[str] = "{}"
    duration_minutes: Optional[int] = None
    expires_at: Optional[str] = None

class ApproveRequestPayload(BaseModel):
    duration_minutes: Optional[int] = None
    decision_reason: Optional[str] = "Approved by Administrator"
    admin_user: Optional[str] = "Admin"
    override_critical: Optional[bool] = False

class DeclineRequestPayload(BaseModel):
    decision_reason: Optional[str] = "Declined by Administrator"
    admin_user: Optional[str] = "Admin"

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

# --- Policy Configuration Schemas (Algorithms 1-7) ---
class PolicyConfigSchema(BaseModel):
    strict_allowlist_matching: bool = True
    fail_closed_when_server_offline: bool = True
    require_captcha_for_hid: bool = True
    captcha_timeout_seconds: int = 30
    captcha_max_attempts: int = 3
    iki_burst_threshold_cps: int = 30
    iki_min_variance_ms: float = 2.0
    hid_surveillance_window_seconds: int = 15
    block_unauthorized_composite: bool = True
    allow_composite_mouse_keyboard: bool = True
    protected_directory: str = "C:\\USBIPS_Protected"
    canary_file_name: str = "confidential_canary.txt"
    block_storage_execution: bool = True
    auto_terminate_storage_processes: bool = True
    block_usb_network_adapters: bool = True
    alert_on_gateway_override: bool = True
    max_reconnects_per_minute: int = 3
    flap_window_seconds: int = 15
    evasion_risk_threshold: int = 70

# --- Protected Folder Policy Schemas ---
class ProtectedFolderCreate(BaseModel):
    folder_path: str = Field(..., min_length=2)
    description: Optional[str] = ""
    is_enabled: Optional[bool] = True

class ProtectedFolderUpdate(BaseModel):
    description: Optional[str] = None
    is_enabled: Optional[bool] = None

class ProtectedFolderResponse(BaseModel):
    id: int
    folder_path: str
    description: str
    is_enabled: bool
    created_at: str
    updated_at: Optional[str] = None

# --- Policy Violation Incident Schema ---
class PolicyViolationIncidentRequest(BaseModel):
    client_id: str
    vendor_id: str
    product_id: str
    serial_number: Optional[str] = ""
    device_id: Optional[str] = ""
    device_type: Optional[str] = "STORAGE"
    description: Optional[str] = ""
    folder_path: str
    operation: str
    attribution_tier: str  # DEFINITIVE, PROBABILISTIC, UNCERTAIN
    attribution_evidence: str
    enforcement_applied: bool = False
    enforcement_verified: bool = False
    enforcement_code: Optional[str] = ""

# --- Device Recovery Schema ---
class DeviceRecoveryRequest(BaseModel):
    vendor_id: str
    product_id: str
    serial_number: str
    admin_user: Optional[str] = "Administrator"
    reason: Optional[str] = "Cleared unverified scan error revocation"
    force_override: Optional[bool] = False


