from fastapi import APIRouter, HTTPException
from typing import Dict, Any

from ..database.db import get_db, utc_now_iso
from ..models.schemas import PolicyConfigSchema

router = APIRouter(prefix="/api/policies", tags=["Security Policies (Algorithms 1-7)"])

@router.get("", response_model=PolicyConfigSchema)
def get_policies():
    """Fetch current central security policies for Algorithms 1-7."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT strict_allowlist_matching, fail_closed_when_server_offline,
                   require_captcha_for_hid, captcha_timeout_seconds,
                   captcha_max_attempts, iki_burst_threshold_cps,
                   iki_min_variance_ms, hid_surveillance_window_seconds,
                   block_unauthorized_composite, allow_composite_mouse_keyboard,
                   protected_directory, canary_file_name,
                   block_storage_execution, auto_terminate_storage_processes,
                   block_usb_network_adapters, alert_on_gateway_override,
                   max_reconnects_per_minute, flap_window_seconds,
                   evasion_risk_threshold
            FROM policies WHERE id = 1;
        """)
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Policies not configured")
        
        return PolicyConfigSchema(
            strict_allowlist_matching=bool(row["strict_allowlist_matching"]),
            fail_closed_when_server_offline=bool(row["fail_closed_when_server_offline"]),
            require_captcha_for_hid=bool(row["require_captcha_for_hid"]),
            captcha_timeout_seconds=int(row["captcha_timeout_seconds"]),
            captcha_max_attempts=int(row["captcha_max_attempts"] if "captcha_max_attempts" in row.keys() else 3),
            iki_burst_threshold_cps=int(row["iki_burst_threshold_cps"]),
            iki_min_variance_ms=float(row["iki_min_variance_ms"]),
            hid_surveillance_window_seconds=int(row["hid_surveillance_window_seconds"]),
            block_unauthorized_composite=bool(row["block_unauthorized_composite"]),
            allow_composite_mouse_keyboard=bool(row["allow_composite_mouse_keyboard"]),
            protected_directory=str(row["protected_directory"]),
            canary_file_name=str(row["canary_file_name"]),
            block_storage_execution=bool(row["block_storage_execution"]),
            auto_terminate_storage_processes=bool(row["auto_terminate_storage_processes"]),
            block_usb_network_adapters=bool(row["block_usb_network_adapters"]),
            alert_on_gateway_override=bool(row["alert_on_gateway_override"]),
            max_reconnects_per_minute=int(row["max_reconnects_per_minute"]),
            flap_window_seconds=int(row["flap_window_seconds"]),
            evasion_risk_threshold=int(row["evasion_risk_threshold"])
        )

@router.put("", response_model=PolicyConfigSchema)
def update_policies(policy: PolicyConfigSchema):
    """Update fleetwide security policies for Algorithms 1-7."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE policies
            SET strict_allowlist_matching = ?,
                fail_closed_when_server_offline = ?,
                require_captcha_for_hid = ?,
                captcha_timeout_seconds = ?,
                captcha_max_attempts = ?,
                iki_burst_threshold_cps = ?,
                iki_min_variance_ms = ?,
                hid_surveillance_window_seconds = ?,
                block_unauthorized_composite = ?,
                allow_composite_mouse_keyboard = ?,
                protected_directory = ?,
                canary_file_name = ?,
                block_storage_execution = ?,
                auto_terminate_storage_processes = ?,
                block_usb_network_adapters = ?,
                alert_on_gateway_override = ?,
                max_reconnects_per_minute = ?,
                flap_window_seconds = ?,
                evasion_risk_threshold = ?,
                updated_at = ?
            WHERE id = 1;
        """, (
            1 if policy.strict_allowlist_matching else 0,
            1 if policy.fail_closed_when_server_offline else 0,
            1 if policy.require_captcha_for_hid else 0,
            policy.captcha_timeout_seconds,
            policy.captcha_max_attempts,
            policy.iki_burst_threshold_cps,
            policy.iki_min_variance_ms,
            policy.hid_surveillance_window_seconds,
            1 if policy.block_unauthorized_composite else 0,
            1 if policy.allow_composite_mouse_keyboard else 0,
            policy.protected_directory,
            policy.canary_file_name,
            1 if policy.block_storage_execution else 0,
            1 if policy.auto_terminate_storage_processes else 0,
            1 if policy.block_usb_network_adapters else 0,
            1 if policy.alert_on_gateway_override else 0,
            policy.max_reconnects_per_minute,
            policy.flap_window_seconds,
            policy.evasion_risk_threshold,
            utc_now_iso()
        ))
    return get_policies()

@router.post("/reset", response_model=PolicyConfigSchema)
def reset_policies():
    """Reset central security policies to safe defaults."""
    default_policy = PolicyConfigSchema()
    return update_policies(default_policy)

