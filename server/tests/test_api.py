import os
import sys
import unittest
import tempfile
from fastapi.testclient import TestClient

# Ensure root path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

# Set test database path before importing app
temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
temp_db.close()
os.environ["USBIPS_SERVER_DB"] = temp_db.name

from server.app.main import app
from server.app.database.db import get_db

class TestUSBIPSServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(temp_db.name):
            try:
                os.remove(temp_db.name)
            except Exception:
                pass

    def test_01_health_and_dashboard(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertIn("healthy", res.json()["status"])

        res_ui = self.client.get("/")
        self.assertEqual(res_ui.status_code, 200)
        self.assertIn("USBIPS Central Management Console", res_ui.text)

    def test_02_client_registration_and_heartbeat(self):
        client_data = {
            "client_id": "test-machine-guid-001",
            "hostname": "WORKSTATION-01",
            "ip_address": "192.168.1.50",
            "os_version": "Windows 11 Pro",
            "agent_version": "1.0.0"
        }
        res = self.client.post("/api/clients/register", json=client_data)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "success")

        # Heartbeat
        hb_res = self.client.post("/api/clients/heartbeat", json={"client_id": "test-machine-guid-001"})
        self.assertEqual(hb_res.status_code, 200)

        # List
        list_res = self.client.get("/api/clients")
        self.assertEqual(list_res.status_code, 200)
        clients = list_res.json()
        self.assertTrue(any(c["client_id"] == "test-machine-guid-001" for c in clients))

    def test_03_master_allowlist_crud(self):
        device_data = {
            "vendor_id": "046D",
            "product_id": "C077",
            "serial_number": "SN-LOGI-MOUSE-01",
            "device_type": "HID",
            "description": "Logitech Optical Mouse",
            "manufacturer": "Logitech"
        }
        res = self.client.post("/api/devices", json=device_data)
        self.assertEqual(res.status_code, 201)

        # Retrieve allowlist
        get_res = self.client.get("/api/devices")
        self.assertEqual(get_res.status_code, 200)
        devices = get_res.json()
        found = next((d for d in devices if d["vendor_id"] == "046D" and d["product_id"] == "C077"), None)
        self.assertIsNotNone(found)
        dev_id = found["id"]

        # Task 9: GET /api/devices/{id}
        single_res = self.client.get(f"/api/devices/{dev_id}")
        self.assertEqual(single_res.status_code, 200)
        self.assertEqual(single_res.json()["vendor_id"], "046D")

        # Task 9: PUT /api/devices/{id} update device description and manufacturer
        update_res = self.client.put(f"/api/devices/{dev_id}", json={
            "description": "Logitech Performance Gaming Mouse",
            "manufacturer": "Logitech International"
        })
        self.assertEqual(update_res.status_code, 200)

        # Verify update applied
        verify_res = self.client.get(f"/api/devices/{dev_id}")
        self.assertEqual(verify_res.json()["description"], "Logitech Performance Gaming Mouse")

        # Task 9: Search filtering
        search_res = self.client.get("/api/devices?search=Gaming")
        self.assertEqual(search_res.status_code, 200)
        self.assertTrue(any(d["id"] == dev_id for d in search_res.json()))

        # Task 9: POST /api/device/check & /api/devices/check
        check_req = {
            "client_id": "test-machine-guid-001",
            "vendor_id": "046D",
            "product_id": "C077",
            "serial_number": "SN-LOGI-MOUSE-01"
        }
        chk_res1 = self.client.post("/api/device/check", json=check_req)
        self.assertEqual(chk_res1.status_code, 200)
        self.assertEqual(chk_res1.json()["decision"], "ALLOW")

        chk_res2 = self.client.post("/api/devices/check", json=check_req)
        self.assertEqual(chk_res2.status_code, 200)
        self.assertEqual(chk_res2.json()["decision"], "ALLOW")

    def test_04_unknown_device_server_approval_flow(self):
        # 1. Unknown device plugs into client -> checks server
        unknown_dev = {
            "client_id": "test-machine-guid-001",
            "vendor_id": "0781",
            "product_id": "5583",
            "serial_number": "SANDISK-SECURE-999",
            "device_type": "STORAGE",
            "description": "SanDisk Ultra USB 3.0"
        }
        res = self.client.post("/api/devices/check-or-request", json=unknown_dev)
        self.assertEqual(res.status_code, 200)
        res_data = res.json()
        self.assertEqual(res_data["decision"], "ASK")
        self.assertEqual(res_data["request_status"], "PENDING")
        req_id = res_data["request_id"]
        self.assertIsNotNone(req_id)

        # 2. Verify request appears in pending queue for Administrator
        pending_res = self.client.get("/api/requests/pending")
        self.assertEqual(pending_res.status_code, 200)
        pending_list = pending_res.json()
        self.assertTrue(any(p["request_id"] == req_id for p in pending_list))

        # Task 10: Verify GET /api/requests/{request_id} polling
        req_poll = self.client.get(f"/api/requests/{req_id}")
        self.assertEqual(req_poll.status_code, 200)
        self.assertEqual(req_poll.json()["status"], "PENDING")

        # 3. Administrator approves request in Management UI
        app_res = self.client.post(f"/api/requests/{req_id}/approve")
        self.assertEqual(app_res.status_code, 200)

        # Task 10: Verify GET /api/requests/{request_id} returns APPROVED
        req_poll_after = self.client.get(f"/api/requests/{req_id}")
        self.assertEqual(req_poll_after.status_code, 200)
        self.assertEqual(req_poll_after.json()["status"], "APPROVED")

        # 4. Client polls check-or-request again -> Now receives ALLOW!
        chk_again = self.client.post("/api/devices/check-or-request", json=unknown_dev)
        self.assertEqual(chk_again.status_code, 200)
        self.assertEqual(chk_again.json()["decision"], "ALLOW")

        # 5. Verify device is now also in master allowlist
        allow_res = self.client.get("/api/devices")
        allowed_devs = allow_res.json()
        self.assertTrue(any(d["serial_number"] == "SANDISK-SECURE-999" for d in allowed_devs))

    def test_05_unknown_device_server_decline_flow(self):
        unknown_dev = {
            "client_id": "test-machine-guid-001",
            "vendor_id": "1234",
            "product_id": "DEAD",
            "serial_number": "BADUSB-PICO-001",
            "device_type": "HID",
            "description": "Suspicious Key Injector"
        }
        res = self.client.post("/api/devices/check-or-request", json=unknown_dev)
        self.assertEqual(res.status_code, 200)
        req_id = res.json()["request_id"]

        # Administrator declines
        dec_res = self.client.post(f"/api/requests/{req_id}/decline")
        self.assertEqual(dec_res.status_code, 200)

        # Client checks -> gets BLOCK
        chk_res = self.client.post("/api/devices/check-or-request", json=unknown_dev)
        self.assertEqual(chk_res.status_code, 200)
        self.assertEqual(chk_res.json()["decision"], "BLOCK")

    def test_06_device_revocation(self):
        # Add a device
        res = self.client.post("/api/devices", json={
            "vendor_id": "1111",
            "product_id": "2222",
            "serial_number": "REVOKE-TEST-01",
            "device_type": "STORAGE"
        })
        self.assertEqual(res.status_code, 201)

        # Find its ID
        devs = self.client.get("/api/devices").json()
        target = next(d for d in devs if d["serial_number"] == "REVOKE-TEST-01")
        dev_id = target["id"]

        # Revoke it
        del_res = self.client.delete(f"/api/devices/{dev_id}")
        self.assertEqual(del_res.status_code, 200)

        # Verify not in allowlist
        devs_after = self.client.get("/api/devices").json()
        self.assertFalse(any(d["id"] == dev_id for d in devs_after))

        # Verify check-or-request returns BLOCK for revoked device
        chk = self.client.post("/api/devices/check-or-request", json={
            "client_id": "test-machine-guid-001",
            "vendor_id": "1111",
            "product_id": "2222",
            "serial_number": "REVOKE-TEST-01"
        })
        self.assertEqual(chk.status_code, 200)
        self.assertEqual(chk.json()["decision"], "BLOCK")
        self.assertEqual(chk.json()["request_status"], "REVOKED")

        # Verify GET /api/requests/{req_id} returns status REVOKED for polling client
        chk_req_id = chk.json()["request_id"]
        poll_res = self.client.get(f"/api/requests/{chk_req_id}")
        self.assertEqual(poll_res.status_code, 200)
        self.assertEqual(poll_res.json()["status"], "REVOKED")

    def test_07_batch_event_ingestion_and_stats(self):
        batch = {
            "events": [
                {
                    "event_id": "evt-001",
                    "client_id": "test-machine-guid-001",
                    "timestamp": "2026-09-06T01:50:00Z",
                    "event_type": "DEVICE_CONNECTED",
                    "vendor_id": "046D",
                    "product_id": "C077",
                    "decision": "ALLOW",
                    "reason": "Found in allowlist"
                },
                {
                    "event_id": "evt-002",
                    "client_id": "test-machine-guid-001",
                    "timestamp": "2026-09-06T01:50:05Z",
                    "event_type": "DEVICE_QUARANTINED",
                    "decision": "-",
                    "reason": "Zero-trust quarantine"
                }
            ]
        }
        res = self.client.post("/api/events/batch", json=batch)
        self.assertEqual(res.status_code, 200)
        res_json = res.json()
        self.assertEqual(res_json["received"], 2)
        self.assertEqual(res_json["inserted"], 2)
        self.assertEqual(res_json["ingested_count"], 2)

        # Query events
        evt_res = self.client.get("/api/events")
        self.assertEqual(evt_res.status_code, 200)
        events = evt_res.json()
        self.assertGreaterEqual(len(events), 2)

        # Check stats
        stats_res = self.client.get("/api/stats")
        self.assertEqual(stats_res.status_code, 200)
        stats = stats_res.json()
        self.assertGreaterEqual(stats["total_events"], 2)
        self.assertGreaterEqual(stats["active_clients"], 1)

    def test_08_client_management_endpoints(self):
        client_data = {
            "client_id": "test-guid-to-deregister-999",
            "hostname": "TEMP-WORKSTATION",
            "ip_address": "10.0.0.99",
            "os_version": "Windows 11",
            "agent_version": "1.0.0"
        }
        # 1. Register
        reg_res = self.client.post("/api/clients/register", json=client_data)
        self.assertEqual(reg_res.status_code, 200)

        # 2. Get single client
        get_res = self.client.get("/api/clients/test-guid-to-deregister-999")
        self.assertEqual(get_res.status_code, 200)
        client_info = get_res.json()
        self.assertEqual(client_info["hostname"], "TEMP-WORKSTATION")
        self.assertEqual(client_info["ip_address"], "10.0.0.99")
        self.assertTrue(client_info["is_online"])
        self.assertEqual(client_info["status"], "ONLINE")

        # 3. Graceful offline notification
        hb_res = self.client.post("/api/clients/heartbeat", json={
            "client_id": "test-guid-to-deregister-999",
            "status": "OFFLINE"
        })
        self.assertEqual(hb_res.status_code, 200)

        # 4. Verify client shows offline
        get_after = self.client.get("/api/clients/test-guid-to-deregister-999")
        self.assertEqual(get_after.status_code, 200)
        self.assertFalse(get_after.json()["is_online"])
        self.assertEqual(get_after.json()["status"], "OFFLINE")

        # 5. Deregister / Delete client
        del_res = self.client.delete("/api/clients/test-guid-to-deregister-999")
        self.assertEqual(del_res.status_code, 200)

        # 6. Verify client returns 404
        not_found_res = self.client.get("/api/clients/test-guid-to-deregister-999")
        self.assertEqual(not_found_res.status_code, 404)

        # 7. Verify DELETE on non-existent client returns 404
        del_404_res = self.client.delete("/api/clients/test-guid-to-deregister-999")
        self.assertEqual(del_404_res.status_code, 404)

    def test_09_server_bind_validation(self):
        from server.run_server import validate_bind_address
        # 1. Valid local bind address on an ephemeral port should succeed
        self.assertTrue(validate_bind_address("127.0.0.1", 0))

        # 2. Invalid IP address string should fail gracefully without unhandled exception
        self.assertFalse(validate_bind_address("999.999.999.999", 8000))


    def test_10_algorithm_event_types(self):
        """Verify server accepts Alg 1-4 event types via batch ingest."""
        client_id = "alg-test-client-001"
        self.client.post("/api/clients/register", json={
            "client_id": client_id, "hostname": "ALG-TEST-HOST",
            "ip_address": "10.0.0.99", "os_version": "Windows 11",
            "agent_version": "1.0.0"
        })
        alg_events = [
            {"event_id": "alg1-001", "client_id": client_id,
             "timestamp": "2026-10-17T10:00:00Z", "event_type": "ALLOWLIST_MATCH",
             "vendor_id": "1234", "product_id": "5678", "serial_number": "SN-ALG1",
             "device_id": "USB\\VID_1234&PID_5678\\SN-ALG1", "device_type": "HID",
             "description": "Trusted Keyboard", "decision": "ALLOW",
             "reason": "[ALG1] Device fingerprint matched local allowlist"},
            {"event_id": "alg2-captcha-req", "client_id": client_id,
             "timestamp": "2026-10-17T10:01:00Z", "event_type": "HID_CAPTCHA_REQUIRED",
             "vendor_id": "ABCD", "product_id": "EF01", "serial_number": "SN-HID",
             "device_id": "USB\\VID_ABCD&PID_EF01\\SN-HID", "device_type": "HID",
             "description": "Unknown HID", "decision": "PENDING",
             "reason": "[ALG2] CAPTCHA initiated"},
            {"event_id": "alg2-captcha-pass", "client_id": client_id,
             "timestamp": "2026-10-17T10:01:30Z", "event_type": "HID_CAPTCHA_PASSED",
             "vendor_id": "ABCD", "product_id": "EF01", "serial_number": "SN-HID",
             "device_id": "USB\\VID_ABCD&PID_EF01\\SN-HID", "device_type": "HID",
             "description": "Unknown HID", "decision": "ALLOW",
             "reason": "[ALG2] CAPTCHA passed"},
            {"event_id": "alg2-captcha-timeout", "client_id": client_id,
             "timestamp": "2026-10-17T10:01:45Z", "event_type": "HID_CAPTCHA_TIMEOUT",
             "vendor_id": "ABCD", "product_id": "EF01", "serial_number": "SN-HID",
             "device_id": "USB\\VID_ABCD&PID_EF01\\SN-HID", "device_type": "HID",
             "description": "Unknown HID", "decision": "BLOCK",
             "reason": "[ALG2] CAPTCHA challenge timed out"},
            {"event_id": "alg2-anomaly", "client_id": client_id,
             "timestamp": "2026-10-17T10:02:00Z", "event_type": "HID_ANOMALY_DETECTED",
             "vendor_id": "ABCD", "product_id": "EF01", "serial_number": "SN-HID",
             "device_id": "USB\\VID_ABCD&PID_EF01\\SN-HID", "device_type": "HID",
             "description": "Unknown HID", "decision": "BLOCK",
             "reason": "[ALG2] Burst 50CPS Variance=0ms2"},
            {"event_id": "alg3-composite", "client_id": client_id,
             "timestamp": "2026-10-17T10:03:00Z", "event_type": "COMPOSITE_POLICY_VIOLATION",
             "vendor_id": "DEAD", "product_id": "BEEF", "serial_number": "SN-BADUSB",
             "device_id": "USB\\VID_DEAD&PID_BEEF\\SN-BADUSB", "device_type": "COMPOSITE",
             "description": "Suspicious Composite", "decision": "BLOCK",
             "reason": "[ALG3] HID+Storage composite blocked"},
            {"event_id": "alg4-file", "client_id": client_id,
             "timestamp": "2026-10-17T10:04:00Z", "event_type": "PROTECTED_FILE_ACCESS",
             "vendor_id": "1234", "product_id": "5678", "serial_number": "SN-ALG1",
             "device_id": "USB\\VID_1234&PID_5678\\SN-ALG1", "device_type": "STORAGE",
             "description": "Storage Device", "decision": "ALERT",
             "reason": "[ALG4] Canary file touched"},
        ]
        res = self.client.post("/api/events/batch", json={"events": alg_events})
        self.assertEqual(res.status_code, 200, f"Batch failed: {res.text}")
        body = res.json()
        ingested = body.get("inserted", body.get("ingested_count", 0))
        self.assertEqual(ingested, len(alg_events), f"Expected {len(alg_events)} events, got {ingested}")
        stats_res = self.client.get("/api/stats")
        self.assertEqual(stats_res.status_code, 200)
        self.assertGreater(stats_res.json()["total_events"], 0)

    def test_11_policy_configuration_endpoints(self):
        """Verify GET, PUT, and POST /reset for central security policies (Alg 1-7)."""
        # 1. GET default policies
        get_res = self.client.get("/api/policies")
        self.assertEqual(get_res.status_code, 200)
        policy = get_res.json()
        self.assertTrue(policy["strict_allowlist_matching"])
        self.assertTrue(policy["require_captcha_for_hid"])
        self.assertEqual(policy["captcha_timeout_seconds"], 30)
        self.assertEqual(policy["captcha_max_attempts"], 3)
        self.assertEqual(policy["iki_burst_threshold_cps"], 30)
        self.assertTrue(policy["block_storage_execution"])
        self.assertEqual(policy["max_reconnects_per_minute"], 3)

        # 2. PUT updated policies
        policy["captcha_timeout_seconds"] = 45
        policy["captcha_max_attempts"] = 5
        policy["iki_burst_threshold_cps"] = 25
        policy["block_storage_execution"] = False
        policy["max_reconnects_per_minute"] = 5
        put_res = self.client.put("/api/policies", json=policy)
        self.assertEqual(put_res.status_code, 200)
        updated = put_res.json()
        self.assertEqual(updated["captcha_timeout_seconds"], 45)
        self.assertEqual(updated["captcha_max_attempts"], 5)
        self.assertEqual(updated["iki_burst_threshold_cps"], 25)
        self.assertFalse(updated["block_storage_execution"])
        self.assertEqual(updated["max_reconnects_per_minute"], 5)

        # Verify persistence via fresh GET
        verify_res = self.client.get("/api/policies")
        self.assertEqual(verify_res.status_code, 200)
        self.assertEqual(verify_res.json()["captcha_timeout_seconds"], 45)
        self.assertEqual(verify_res.json()["captcha_max_attempts"], 5)

        # 3. POST /reset back to defaults
        reset_res = self.client.post("/api/policies/reset")
        self.assertEqual(reset_res.status_code, 200)
        reset_policy = reset_res.json()
        self.assertEqual(reset_policy["captcha_timeout_seconds"], 30)
        self.assertEqual(reset_policy["captcha_max_attempts"], 3)
        self.assertEqual(reset_policy["iki_burst_threshold_cps"], 30)
        self.assertTrue(reset_policy["block_storage_execution"])
        self.assertEqual(reset_policy["max_reconnects_per_minute"], 3)

    def test_12_trust_assessment_and_security_events(self):
        """Verify server ingests and serves TAE and security module events (A1-A10)."""
        client_id = "tae-test-client-001"
        self.client.post("/api/clients/register", json={
            "client_id": client_id, "hostname": "TAE-TEST-HOST",
            "ip_address": "10.0.0.100", "os_version": "Windows 11",
            "agent_version": "1.0.0"
        })

        tae_events = [
            {
                "event_id": "tae-001",
                "client_id": client_id,
                "timestamp": "2026-10-19T01:30:00Z",
                "event_type": "TRUST_ASSESSMENT_COMPLETED",
                "vendor_id": "046D",
                "product_id": "C077",
                "serial_number": "SN-TRUSTED-01",
                "device_id": "USB\VID_046D&PID_C077\SN-TRUSTED-01",
                "device_type": "HID",
                "description": "Standard Trusted Mouse",
                "decision": "ALLOW",
                "reason": "[A10-TAE] Score=10 Severity=LOW Rec=APPROVE | Identity:MATCH Admin:AUTHORIZED"
            },
            {
                "event_id": "malware-001",
                "client_id": client_id,
                "timestamp": "2026-10-19T01:30:10Z",
                "event_type": "MALWARE_DETECTED",
                "vendor_id": "0781",
                "product_id": "5567",
                "serial_number": "SN-INFECTED-01",
                "device_id": "USB\VID_0781&PID_5567\SN-INFECTED-01",
                "device_type": "STORAGE",
                "description": "Removable USB Drive",
                "decision": "BLOCK",
                "reason": "[A4-AV] Defender MpCmdRun.exe detected threat: Trojan:Win32/Wacatac.B!ml"
            },
            {
                "event_id": "susp-file-001",
                "client_id": client_id,
                "timestamp": "2026-10-19T01:30:20Z",
                "event_type": "SUSPICIOUS_FILE_DETECTED",
                "vendor_id": "0781",
                "product_id": "5567",
                "serial_number": "SN-INFECTED-01",
                "device_id": "USB\VID_0781&PID_5567\SN-INFECTED-01",
                "device_type": "STORAGE",
                "description": "Removable USB Drive",
                "decision": "BLOCK",
                "reason": "[A5-FILE] Disguised PE binary detected: autorun.inf launches payload.pdf.exe"
            },
            {
                "event_id": "exfil-001",
                "client_id": client_id,
                "timestamp": "2026-10-19T01:30:30Z",
                "event_type": "DATA_EXFILTRATION_DETECTED",
                "vendor_id": "0781",
                "product_id": "5567",
                "serial_number": "SN-INFECTED-01",
                "device_id": "USB\VID_0781&PID_5567\SN-INFECTED-01",
                "device_type": "STORAGE",
                "description": "Removable USB Drive",
                "decision": "BLOCK",
                "reason": "[A7-EXFIL] Exfiltration burst: 8 sensitive files written to removable storage"
            }
        ]

        # 1. Ingest batch
        res = self.client.post("/api/events/batch", json={"events": tae_events})
        self.assertEqual(res.status_code, 200, f"Batch failed: {res.text}")
        body = res.json()
        ingested = body.get("inserted", body.get("ingested_count", 0))
        self.assertEqual(ingested, len(tae_events))

        # 2. Query events stream and verify ingestion
        events_res = self.client.get("/api/events?limit=50")
        self.assertEqual(events_res.status_code, 200)
        fetched = events_res.json()
        event_ids = {e["event_id"] for e in fetched}
        for te in tae_events:
            self.assertIn(te["event_id"], event_ids)

        # 3. Verify specific event contents
        tae_evt = next(e for e in fetched if e["event_id"] == "tae-001")
        self.assertEqual(tae_evt["event_type"], "TRUST_ASSESSMENT_COMPLETED")
        self.assertEqual(tae_evt["decision"], "ALLOW")
        self.assertIn("[A10-TAE]", tae_evt["reason"])

        exfil_evt = next(e for e in fetched if e["event_id"] == "exfil-001")
        self.assertEqual(exfil_evt["event_type"], "DATA_EXFILTRATION_DETECTED")
        self.assertEqual(exfil_evt["decision"], "BLOCK")

    def test_13_hid_captcha_and_evidence_assessment_submission(self):
        """Verify client submission of complete HID CAPTCHA lifecycle metadata and 12-algorithm evidence."""
        req_data = {
            "client_id": "test-machine-guid-001",
            "vendor_id": "046D",
            "product_id": "C31C",
            "serial_number": "HID-KBD-TEST-001",
            "device_type": "HID",
            "description": "Logitech USB Keyboard",
            "device_path": "\\\\?\\HID#VID_046D&PID_C31C#001#{4d1e55b2-f16f-11cf-88cb-001111000030}",
            "session_id": "sess-kb-001",
            "captcha_challenge_id": "chal-kb-9821",
            "captcha_result": "PASSED",
            "verification_method": "KEYBOARD_TYPING",
            "verification_start": "2026-10-19T10:00:00Z",
            "verification_completed": "2026-10-19T10:00:04Z",
            "attempt_count": 1,
            "verification_score": 100,
            "verification_duration_seconds": 4.2,
            "temp_release_applied": True,
            "temp_release_duration_seconds": 5.0,
            "re_quarantine_result": "QUARANTINED (CR_NOT_DISABLEABLE: user-mode zero trust active)",
            "current_enforcement_state": "QUARANTINED",
            "total_risk_score": 25,
            "severity": "LOW",
            "recommendation": "REVIEW",
            "assessment_summary": "CAPTCHA passed; device re-quarantined awaiting admin approval",
            "algorithms_json": '{"A1":{"status":"NOT_ASSESSED","risk":25},"A3":{"status":"PASS","risk":0}}'
        }

        # 1. Post check-or-request
        res = self.client.post("/api/devices/check-or-request", json=req_data)
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["decision"], "ASK")
        self.assertEqual(body["request_status"], "PENDING")
        req_id = body["request_id"]
        self.assertTrue(req_id)

        # 2. Query pending request and inspect complete persisted evidence
        get_res = self.client.get(f"/api/requests/{req_id}")
        self.assertEqual(get_res.status_code, 200)
        req_rec = get_res.json()
        self.assertEqual(req_rec["captcha_result"], "PASSED")
        self.assertEqual(req_rec["verification_method"], "KEYBOARD_TYPING")
        self.assertEqual(req_rec["attempt_count"], 1)
        self.assertEqual(req_rec["verification_score"], 100)
        self.assertEqual(req_rec["re_quarantine_result"], "QUARANTINED (CR_NOT_DISABLEABLE: user-mode zero trust active)")
        self.assertEqual(req_rec["current_enforcement_state"], "QUARANTINED")
        self.assertEqual(req_rec["total_risk_score"], 25)

    def test_14_timed_approval_and_expiry_enforcement(self):
        """Verify admin approval duration selection and automatic expiration when authorization expires."""
        # 1. Submit pending request
        req_data = {
            "client_id": "test-machine-guid-001",
            "vendor_id": "046D",
            "product_id": "C077",
            "serial_number": "MOUSE-TEST-002",
            "device_type": "HID",
            "description": "Logitech USB Optical Mouse",
            "captcha_result": "PASSED",
            "verification_method": "MOUSE_CLICK",
            "total_risk_score": 25,
            "severity": "LOW",
            "recommendation": "REVIEW"
        }
        res = self.client.post("/api/devices/check-or-request", json=req_data)
        req_id = res.json()["request_id"]

        # 2. Approve with 60 minutes duration
        approve_res = self.client.post(
            f"/api/requests/{req_id}/approve",
            json={"duration_minutes": 60, "decision_reason": "Approved for 1 hour maintenance", "admin_user": "SecAdmin"}
        )
        self.assertEqual(approve_res.status_code, 200)
        self.assertIn("Expires:", approve_res.json()["message"])
        exp_time = approve_res.json()["expires_at"]
        self.assertIsNotNone(exp_time)

        # 3. Check device via check-or-request: should now return ALLOW
        check_res = self.client.post("/api/devices/check-or-request", json=req_data)
        self.assertEqual(check_res.json()["decision"], "ALLOW")
        self.assertEqual(check_res.json()["request_status"], "APPROVED")

        # 4. Simulate expired device in database: set expires_at to past timestamp
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE master_allowlist
                SET expires_at = '2020-01-01T00:00:00Z'
                WHERE serial_number = 'MOUSE-TEST-002';
            """)

        # 5. Subsequent check-or-request must enforce EXPIRED and BLOCK
        exp_check_res = self.client.post("/api/devices/check-or-request", json=req_data)
        self.assertEqual(exp_check_res.json()["decision"], "BLOCK")
        self.assertEqual(exp_check_res.json()["request_status"], "EXPIRED")

    def test_15_critical_security_finding_approval_prevention(self):
        """Verify that CAPTCHA pass CANNOT override critical BadUSB / high-risk findings."""
        req_data = {
            "client_id": "test-machine-guid-001",
            "vendor_id": "1234",
            "product_id": "5678",
            "serial_number": "BADUSB-DUCKY-001",
            "device_type": "COMPOSITE (HID+Storage)",
            "description": "BadUSB Rubber Ducky with Storage",
            "captcha_result": "PASSED",
            "total_risk_score": 85,
            "severity": "CRITICAL",
            "recommendation": "REJECT",
            "assessment_summary": "REJECTED: High-risk composite device violation"
        }
        res = self.client.post("/api/devices/check-or-request", json=req_data)
        self.assertEqual(res.status_code, 200)
        # Should be automatically blocked by central policy due to CRITICAL finding
        self.assertEqual(res.json()["decision"], "BLOCK")
        self.assertEqual(res.json()["request_status"], "DECLINED")
        req_id = res.json()["request_id"]

        # Attempting standard approval on CRITICAL / REJECT request must fail with 400
        appr_res = self.client.post(
            f"/api/requests/{req_id}/approve",
            json={"duration_minutes": 15, "override_critical": False}
        )
        self.assertEqual(appr_res.status_code, 400)
        self.assertIn("CRITICAL", appr_res.json()["detail"])

    def test_16_captcha_timeout_never_allows_and_stays_quarantined(self):
        """Verify that CAPTCHA timeout is recorded as TIMEOUT, never auto-approves, and rejects replayed challenges."""
        timeout_data = {
            "client_id": "test-machine-guid-001",
            "vendor_id": "046D",
            "product_id": "C31D",
            "serial_number": "TIMEOUT-KBD-999",
            "device_type": "HID",
            "description": "Timed-out USB Keyboard",
            "session_id": "sess-timeout-test",
            "captcha_challenge_id": "chal-timeout-unique-1234",
            "captcha_result": "TIMEOUT",
            "verification_method": "KEYBOARD_TYPING",
            "attempt_count": 0,
            "verification_score": 0,
            "verification_duration_seconds": 30.0,
            "temp_release_applied": False,
            "temp_release_duration_seconds": 0.0,
            "re_quarantine_result": "QUARANTINED",
            "current_enforcement_state": "QUARANTINED",
            "total_risk_score": 35,
            "severity": "MEDIUM",
            "recommendation": "REVIEW",
            "assessment_summary": "Human verification timed out; device remains quarantined"
        }

        # 1. Submit check-or-request with TIMEOUT
        res = self.client.post("/api/devices/check-or-request", json=timeout_data)
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["decision"], "ASK")
        self.assertEqual(body["request_status"], "PENDING")
        req_id = body["request_id"]

        # 2. Query request details and verify persisted verification metadata
        req_res = self.client.get(f"/api/requests/{req_id}")
        self.assertEqual(req_res.status_code, 200)
        req_rec = req_res.json()
        self.assertEqual(req_rec["captcha_result"], "TIMEOUT")
        self.assertEqual(req_rec["verification_score"], 0)
        self.assertFalse(req_rec["temp_release_applied"])
        self.assertEqual(req_rec["current_enforcement_state"], "QUARANTINED")

        # 3. Verify device was NOT added to master allowlist
        allow_res = self.client.get("/api/devices?search=TIMEOUT-KBD-999")
        self.assertEqual(allow_res.status_code, 200)
        self.assertEqual(len(allow_res.json()), 0)

        # 4. Verify server-side challenge replay rejection:
        # A different hardware device attempting to reuse the same challenge ID must be rejected as REPLAY_ATTEMPT
        replay_data = {
            "client_id": "test-machine-guid-002",
            "vendor_id": "FFFF",
            "product_id": "EEEE",
            "serial_number": "REPLAY-DEVICE-001",
            "device_type": "HID",
            "captcha_challenge_id": "chal-timeout-unique-1234",
            "captcha_result": "PASSED"
        }
        replay_res = self.client.post("/api/devices/check-or-request", json=replay_data)
        self.assertEqual(replay_res.status_code, 200)
        self.assertEqual(replay_res.json()["decision"], "BLOCK")
        self.assertEqual(replay_res.json()["request_status"], "DECLINED")
        self.assertIn("Critical", replay_res.json()["message"])

    def test_17_accurate_revocation_and_missing_allowlist_workflow(self):
        """
        Priority 1 Regression Test:
        Verify accurate state mapping across:
        1. Approved device
        2. Explicit administrator revocation
        3. Missing allowlist entry (no manufactured revocation)
        4. Expired approval
        5. Brand new unknown device
        6. Existing pending request
        """
        vid = "2222"
        pid = "3333"
        sn_approved = "SN-APPROVED-001"
        sn_revoked = "SN-REVOKED-002"
        sn_missing = "SN-MISSING-003"
        sn_expired = "SN-EXPIRED-004"
        sn_unknown = "SN-UNKNOWN-005"

        # 1. Approved Device: Add to allowlist, verify returns ALLOW / APPROVED
        self.client.post("/api/devices", json={
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": sn_approved,
            "device_type": "STORAGE"
        })
        chk_app = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-001",
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": sn_approved
        }).json()
        self.assertEqual(chk_app["decision"], "ALLOW")
        self.assertEqual(chk_app["request_status"], "APPROVED")

        # 2. Explicit Revocation: Add device, then explicitly call DELETE /api/devices/{id}
        add_rev = self.client.post("/api/devices", json={
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": sn_revoked,
            "device_type": "STORAGE"
        })
        devs = self.client.get(f"/api/devices?search={sn_revoked}").json()
        dev_id = devs[0]["id"]
        del_res = self.client.delete(f"/api/devices/{dev_id}")
        self.assertEqual(del_res.status_code, 200)

        chk_rev = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-001",
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": sn_revoked
        }).json()
        self.assertEqual(chk_rev["decision"], "BLOCK")
        self.assertEqual(chk_rev["request_status"], "REVOKED")
        self.assertIn("revoked by central administrator", chk_rev["message"].lower())

        # 3. Missing Allowlist Entry:
        # Create an approved request in pending_requests, but DO NOT have it in master_allowlist
        req_res = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-001",
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": sn_missing,
            "device_type": "HID"
        }).json()
        req_id = req_res["request_id"]
        # Simulate approval of request
        self.client.post(f"/api/requests/{req_id}/approve", json={"decision_reason": "Test Approval"})
        # Now manually remove it from master_allowlist without calling DELETE (simulate missing allowlist record)
        from server.app.database.db import get_db
        with get_db() as conn:
            conn.cursor().execute("DELETE FROM master_allowlist WHERE serial_number = ?;", (sn_missing,))

        # Subsequent check-or-request MUST NOT manufacture a REVOKED status! It must route to PENDING.
        chk_missing = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-001",
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": sn_missing
        }).json()
        self.assertEqual(chk_missing["decision"], "ASK")
        self.assertEqual(chk_missing["request_status"], "PENDING")
        self.assertNotEqual(chk_missing["request_status"], "REVOKED")

        # 4. Expired Approval:
        # Create an approved request with duration 1 minute that already expired
        exp_res = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-001",
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": sn_expired,
            "device_type": "HID"
        }).json()
        exp_req_id = exp_res["request_id"]
        self.client.post(f"/api/requests/{exp_req_id}/approve", json={"duration_minutes": 15})
        with get_db() as conn:
            # Set expires_at in the past
            past_time = "2020-01-01T00:00:00Z"
            conn.cursor().execute("UPDATE master_allowlist SET expires_at = ? WHERE serial_number = ?;", (past_time, sn_expired))
            conn.cursor().execute("UPDATE pending_requests SET expires_at = ? WHERE serial_number = ?;", (past_time, sn_expired))

        chk_expired = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-001",
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": sn_expired
        }).json()
        self.assertEqual(chk_expired["decision"], "BLOCK")
        self.assertEqual(chk_expired["request_status"], "EXPIRED")

        # 5. Unknown Device: Never seen before
        chk_unknown = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-001",
            "vendor_id": "9999",
            "product_id": "8888",
            "serial_number": sn_unknown,
            "device_type": "OTHER"
        }).json()
        self.assertEqual(chk_unknown["decision"], "ASK")
        self.assertEqual(chk_unknown["request_status"], "PENDING")

        # 6. Existing Pending Request check-in: keeps PENDING
        chk_pending = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-001",
            "vendor_id": "9999",
            "product_id": "8888",
            "serial_number": sn_unknown,
            "device_type": "OTHER"
        }).json()
        self.assertEqual(chk_pending["decision"], "ASK")
        self.assertEqual(chk_pending["request_status"], "PENDING")

    def test_18_end_to_end_server_client_review_and_revocation_cycle(self):
        """
        Verify complete end-to-end cycle:
        1. Client submits unknown device with full A1-A10 assessment.
        2. Status is PENDING.
        3. Admin views pending list and all 12 modules.
        4. Admin approves with 60m duration.
        5. Polling client receives APPROVED and duration.
        6. Subsequent check returns ALLOW / APPROVED.
        7. Admin explicitly revokes via DELETE.
        8. Subsequent check returns BLOCK / REVOKED.
        """
        device_data = {
            "client_id": "endpoint-e2e-001",
            "vendor_id": "1234",
            "product_id": "5678",
            "serial_number": "E2E-TEST-SERIAL-999",
            "device_type": "STORAGE",
            "description": "Enterprise Secure USB",
            "device_path": "\\\\?\\USB#VID_1234&PID_5678#E2E-TEST-SERIAL-999#{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
            "session_id": "sess-e2e-12345",
            "total_risk_score": 10,
            "severity": "LOW",
            "recommendation": "REVIEW",
            "assessment_summary": "Storage peripheral clean; awaiting administrative approval",
            "algorithms_json": '{"A1":{"status":"NOT_ASSESSED","risk":25,"evidence":"Allowlist lookup"},"A4":{"status":"PASS","risk":0,"evidence":"AV scan clean"}}'
        }

        # 1. Unknown device submitted
        sub_res = self.client.post("/api/devices/check-or-request", json=device_data).json()
        self.assertEqual(sub_res["decision"], "ASK")
        self.assertEqual(sub_res["request_status"], "PENDING")
        req_id = sub_res["request_id"]

        # 2. Client polls request status -> PENDING
        poll_pending = self.client.get(f"/api/requests/{req_id}").json()
        self.assertEqual(poll_pending["status"], "PENDING")
        self.assertIn("A4", poll_pending["algorithms_json"])

        # 3. Admin views pending queue
        pending_list = self.client.get("/api/requests/pending").json()
        target_req = next(r for r in pending_list if r["request_id"] == req_id)
        self.assertEqual(target_req["serial_number"], "E2E-TEST-SERIAL-999")

        # 4. Admin approves with 60m duration
        app_res = self.client.post(f"/api/requests/{req_id}/approve", json={
            "duration_minutes": 60,
            "decision_reason": "Approved for 1 hour maintenance shift"
        })
        self.assertEqual(app_res.status_code, 200)

        # 5. Polling client receives APPROVED and duration
        poll_approved = self.client.get(f"/api/requests/{req_id}").json()
        self.assertEqual(poll_approved["status"], "APPROVED")
        self.assertEqual(poll_approved["duration_minutes"], 60)
        self.assertIsNotNone(poll_approved["expires_at"])

        # 6. Subsequent check-or-request returns ALLOW / APPROVED
        chk_allow = self.client.post("/api/devices/check-or-request", json=device_data).json()
        self.assertEqual(chk_allow["decision"], "ALLOW")
        self.assertEqual(chk_allow["request_status"], "APPROVED")
        self.assertEqual(chk_allow["duration_minutes"], 60)

        # 7. Admin revokes device from master allowlist
        devs = self.client.get("/api/devices?search=E2E-TEST-SERIAL-999").json()
        self.assertEqual(len(devs), 1)
        del_res = self.client.delete(f"/api/devices/{devs[0]['id']}")
        self.assertEqual(del_res.status_code, 200)

        # 8. Subsequent check-or-request returns BLOCK / REVOKED
        chk_rev = self.client.post("/api/devices/check-or-request", json=device_data).json()
        self.assertEqual(chk_rev["decision"], "BLOCK")
        self.assertEqual(chk_rev["request_status"], "REVOKED")

    def test_19_unknown_camera_and_storage_pending_never_revoked(self):
        """
        Verify that new, previously unseen camera and storage devices are entered as PENDING,
        never manufactured as REVOKED or rejected.
        """
        # 1. New unknown USB Camera
        camera_data = {
            "client_id": "endpoint-cam-001",
            "vendor_id": "046D",
            "product_id": "0825",
            "serial_number": "HD-PRO-CAM-001",
            "device_type": "OTHER",
            "description": "Logitech HD Webcam C270",
            "recommendation": "REVIEW",
            "severity": "LOW",
            "total_risk_score": 25,
            "assessment_summary": "Unknown webcam; awaiting administrator authorization"
        }
        res_cam = self.client.post("/api/devices/check-or-request", json=camera_data).json()
        self.assertEqual(res_cam["decision"], "ASK")
        self.assertEqual(res_cam["request_status"], "PENDING")
        self.assertTrue(
            "authorization request submitted" in res_cam["message"].lower() or
            "awaiting administrator" in res_cam["message"].lower()
        )

        # 2. New unknown Flash Storage
        storage_data = {
            "client_id": "endpoint-storage-001",
            "vendor_id": "0781",
            "product_id": "5583",
            "serial_number": "SANDISK-CRUZER-9876",
            "device_type": "STORAGE",
            "description": "SanDisk Ultra USB 3.0",
            "recommendation": "REVIEW",
            "severity": "LOW",
            "total_risk_score": 25,
            "assessment_summary": "Removable storage inspected; awaiting administrative authorization"
        }
        res_store = self.client.post("/api/devices/check-or-request", json=storage_data).json()
        self.assertEqual(res_store["decision"], "ASK")
        self.assertEqual(res_store["request_status"], "PENDING")
        self.assertNotEqual(res_store["request_status"], "REVOKED")

    def test_20_historical_revocation_preserved_camera(self):
        """
        Verify that explicit historical revocation for Camera 046D:094C:2508APXHB378
        is preserved and stays REVOKED / BLOCK.
        """
        # Seed the historical revocation if not already in test DB
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO pending_requests (
                    request_id, client_id, vendor_id, product_id, serial_number,
                    device_type, description, status, requested_at, decided_at, decision_by, decision_reason
                ) VALUES (
                    '6f9ee78d-12f9-4413-9554-d7e990d7f93e', 'ALL_CLIENTS', '046D', '094C', '2508APXHB378',
                    'OTHER', 'Logitech ConferenceCam', 'REVOKED', '2026-03-01T00:00:00Z', '2026-03-01T00:00:00Z',
                    'Administrator', 'Revoked by central administrator'
                );
            """)

        revoked_cam = {
            "client_id": "test-client-guid-001",
            "vendor_id": "046D",
            "product_id": "094C",
            "serial_number": "2508APXHB378",
            "device_type": "OTHER",
            "description": "Logitech ConferenceCam"
        }
        chk_res = self.client.post("/api/devices/check-or-request", json=revoked_cam).json()
        self.assertEqual(chk_res["decision"], "BLOCK")
        self.assertEqual(chk_res["request_status"], "REVOKED")
        self.assertEqual(chk_res["request_id"], "6f9ee78d-12f9-4413-9554-d7e990d7f93e")
        self.assertIn("revoked by central administrator", chk_res["message"].lower())

    def test_21_admin_approval_duration_expiry_and_rejection(self):
        """
        Verify administrator approval workflow with duration, expiry calculation,
        and explicit rejection workflow.
        """
        device_data = {
            "client_id": "client-eval-001",
            "vendor_id": "AAAA",
            "product_id": "BBBB",
            "serial_number": "SN-EVAL-1234",
            "device_type": "STORAGE",
            "description": "Test Evaluated Storage",
            "total_risk_score": 15,
            "severity": "LOW",
            "recommendation": "REVIEW"
        }
        sub = self.client.post("/api/devices/check-or-request", json=device_data).json()
        req_id = sub["request_id"]

        # Approve with 30 minutes duration
        app_res = self.client.post(f"/api/requests/{req_id}/approve", json={
            "duration_minutes": 30,
            "decision_reason": "Approved for 30m diagnostic test"
        })
        self.assertEqual(app_res.status_code, 200)

        # Check request status
        req_info = self.client.get(f"/api/requests/{req_id}").json()
        self.assertEqual(req_info["status"], "APPROVED")
        self.assertEqual(req_info["duration_minutes"], 30)
        self.assertIsNotNone(req_info["expires_at"])

        # Check device query
        chk = self.client.post("/api/devices/check-or-request", json=device_data).json()
        self.assertEqual(chk["decision"], "ALLOW")
        self.assertEqual(chk["request_status"], "APPROVED")

        # Test another device for rejection
        reject_data = {
            "client_id": "client-eval-002",
            "vendor_id": "CCCC",
            "product_id": "DDDD",
            "serial_number": "SN-REJECT-5678",
            "device_type": "OTHER",
            "description": "Untrusted Unknown Device"
        }
        sub_rej = self.client.post("/api/devices/check-or-request", json=reject_data).json()
        rej_id = sub_rej["request_id"]

        dec_res = self.client.post(f"/api/requests/{rej_id}/decline", json={
            "decision_reason": "Denied due to unauthorized device class"
        })
        self.assertEqual(dec_res.status_code, 200)

        chk_after_rej = self.client.post("/api/devices/check-or-request", json=reject_data).json()
        self.assertEqual(chk_after_rej["decision"], "BLOCK")
        self.assertEqual(chk_after_rej["request_status"], "DECLINED")

    def test_22_expired_approval_requires_reauthorization(self):
        """
        Verify that expired authorizations are marked EXPIRED and require re-authorization.
        """
        device_data = {
            "client_id": "client-exp-001",
            "vendor_id": "EEEE",
            "product_id": "FFFF",
            "serial_number": "SN-EXP-9999",
            "device_type": "STORAGE",
            "description": "Timed Shift Device"
        }
        # Insert pre-expired entry directly into master_allowlist
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO master_allowlist (
                    vendor_id, product_id, serial_number, device_type, description,
                    status, created_at, updated_at, duration_minutes, expires_at
                ) VALUES (
                    'EEEE', 'FFFF', 'SN-EXP-9999', 'STORAGE', 'Timed Shift Device',
                    'APPROVED', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 10, '2026-01-01T00:10:00Z'
                );
            """)

        chk = self.client.post("/api/devices/check-or-request", json=device_data).json()
        self.assertEqual(chk["decision"], "BLOCK")
        self.assertEqual(chk["request_status"], "EXPIRED")
        self.assertIn("expired", chk["message"].lower())

    def test_23_mouse_and_keyboard_captcha_metadata_ingestion(self):
        """
        Verify that Mouse CAPTCHA (MOUSE_CLICK) and Keyboard CAPTCHA (KEYBOARD_TYPING)
        metadata and outcomes (PASSED, FAILED, TIMEOUT) are ingested and preserved correctly.
        """
        # Mouse CAPTCHA PASSED
        mouse_data = {
            "client_id": "client-hid-001",
            "vendor_id": "046D",
            "product_id": "C077",
            "serial_number": "MOUSE-CAPTCHA-SN1",
            "device_type": "HID",
            "description": "Logitech Optical Mouse",
            "session_id": "sess-mouse-pass",
            "captcha_challenge_id": "chal-mouse-101",
            "captcha_result": "PASSED",
            "verification_method": "MOUSE_CLICK",
            "attempt_count": 1,
            "verification_score": 100,
            "verification_duration_seconds": 2.1,
            "temp_release_applied": True,
            "temp_release_duration_seconds": 3.0,
            "re_quarantine_result": "QUARANTINED",
            "current_enforcement_state": "QUARANTINED",
            "recommendation": "REVIEW",
            "severity": "LOW",
            "total_risk_score": 25,
            "assessment_summary": "Mouse operator verified via click challenge; restricted under zero-trust"
        }
        res_m = self.client.post("/api/devices/check-or-request", json=mouse_data).json()
        self.assertEqual(res_m["decision"], "ASK")
        self.assertEqual(res_m["request_status"], "PENDING")

        req_detail = self.client.get(f"/api/requests/{res_m['request_id']}").json()
        self.assertEqual(req_detail["verification_method"], "MOUSE_CLICK")
        self.assertEqual(req_detail["captcha_result"], "PASSED")
        self.assertEqual(req_detail["verification_score"], 100)
        self.assertTrue(req_detail["temp_release_applied"])
        self.assertEqual(req_detail["re_quarantine_result"], "QUARANTINED")

        # Keyboard CAPTCHA TIMEOUT
        kb_data = {
            "client_id": "client-hid-002",
            "vendor_id": "04F2",
            "product_id": "0833",
            "serial_number": "KB-CAPTCHA-TIMEOUT-SN",
            "device_type": "HID",
            "description": "Chicony USB Keyboard",
            "session_id": "sess-kb-timeout",
            "captcha_challenge_id": "chal-kb-202",
            "captcha_result": "TIMEOUT",
            "verification_method": "KEYBOARD_TYPING",
            "attempt_count": 0,
            "verification_score": 0,
            "temp_release_applied": False,
            "re_quarantine_result": "QUARANTINED",
            "recommendation": "REVIEW",
            "severity": "MEDIUM",
            "total_risk_score": 50,
            "assessment_summary": "Human verification timed out"
        }
        res_kb = self.client.post("/api/devices/check-or-request", json=kb_data).json()
        self.assertEqual(res_kb["decision"], "ASK")

        kb_detail = self.client.get(f"/api/requests/{res_kb['request_id']}").json()
        self.assertEqual(kb_detail["verification_method"], "KEYBOARD_TYPING")
        self.assertEqual(kb_detail["captcha_result"], "TIMEOUT")
        self.assertEqual(kb_detail["verification_score"], 0)

    def test_24_dashboard_root_route_and_static_assets(self):
        """
        Verify dashboard root route returns HTTP 200 with HTML, CSS loads,
        and all expected UI elements are present.
        """
        res_root = self.client.get("/")
        self.assertEqual(res_root.status_code, 200)
        self.assertIn("USBIPS Central Management Console", res_root.text)
        self.assertIn("Device Security Assessments & Fleet Authorization", res_root.text)
        self.assertIn("filter-pill", res_root.text)
        self.assertIn("api-error-banner", res_root.text)

        # Alias route
        res_dash = self.client.get("/dashboard")
        self.assertEqual(res_dash.status_code, 200)

        # Static CSS
        res_css = self.client.get("/static/app.css")
        self.assertEqual(res_css.status_code, 200)
        self.assertIn("--bg-main", res_css.text)

    def test_25_risk_explanations_and_algorithms_meta(self):
        """
        Verify algorithms_json rich meta serialization including identity match,
        admin authorization state, truthful malware scan status, and explainable reasons.
        """
        meta_json = (
            '{"A1":{"name":"Device Fingerprinting","status":"NOT_ASSESSED","risk":25,"evidence":"Triplet check"},'
            '"A4":{"name":"Antivirus Scan","status":"NOT_SCANNED","risk":0,"evidence":"Volume unmounted"},'
            '"meta":{"identity_match":false,"admin_authorized":false,"malware_scan_result":"NOT_SCANNED",'
            '"behavioral_risk_score":10,"reasons":["[A1] Unknown device (+25 risk)","[A4] Removable storage not scanned"]}}'
        )
        report_data = {
            "client_id": "client-meta-001",
            "vendor_id": "9999",
            "product_id": "8888",
            "serial_number": "SN-META-7777",
            "device_type": "STORAGE",
            "description": "Enterprise Flash Disk",
            "total_risk_score": 25,
            "severity": "LOW",
            "recommendation": "REVIEW",
            "assessment_summary": "Storage awaiting scan and admin approval",
            "algorithms_json": meta_json
        }
        res = self.client.post("/api/devices/check-or-request", json=report_data).json()
        req_id = res["request_id"]

        req_info = self.client.get(f"/api/requests/{req_id}").json()
        self.assertEqual(req_info["total_risk_score"], 25)
        self.assertEqual(req_info["severity"], "LOW")
        self.assertIn("NOT_SCANNED", req_info["algorithms_json"])
        self.assertIn("identity_match", req_info["algorithms_json"])

    def test_26_refined_hid_mouse_and_keyboard_distinct_workflows(self):
        """
        Verify separate, distinct CAPTCHA workflows exclusively for HID mouse and keyboard:
        - Distinct MOUSE_CAPTCHA_PASSED and KEYBOARD_CAPTCHA_PASSED statuses
        - Neither CAPTCHA pass auto-authorizes the device (zero-trust pending state)
        - Target device remains quarantined until explicit administrator approval
        - Unmixed session tracking and honest enforcement state reporting
        """
        # 1. New Mouse arrival with MOUSE_CAPTCHA_PASSED
        mouse_req = {
            "client_id": "client-hid-test",
            "vendor_id": "046D",
            "product_id": "C077",
            "serial_number": "SN-NEW-MOUSE-99",
            "device_type": "MOUSE",
            "description": "Logitech Optical Mouse M90",
            "session_id": "sess-mouse-distinct-01",
            "captcha_challenge_id": "chal-mouse-01",
            "captcha_result": "MOUSE_CAPTCHA_PASSED",
            "verification_method": "MOUSE_CLICK",
            "attempt_count": 1,
            "verification_score": 100,
            "verification_duration_seconds": 4.2,
            "temp_release_applied": False,
            "temp_release_duration_seconds": 0.0,
            "re_quarantine_result": "QUARANTINED_PENDING_ADMIN_REVIEW",
            "current_enforcement_state": "QUARANTINED",
            "total_risk_score": 10,
            "severity": "LOW",
            "recommendation": "REVIEW",
            "assessment_summary": "Mouse passed visual human challenge; quarantined pending admin approval"
        }
        res_m = self.client.post("/api/devices/check-or-request", json=mouse_req).json()
        self.assertEqual(res_m["decision"], "ASK")
        self.assertEqual(res_m["request_status"], "PENDING")
        mouse_req_id = res_m["request_id"]

        # Verify mouse request details
        m_detail = self.client.get(f"/api/requests/{mouse_req_id}").json()
        self.assertEqual(m_detail["device_type"], "MOUSE")
        self.assertEqual(m_detail["captcha_result"], "MOUSE_CAPTCHA_PASSED")
        self.assertEqual(m_detail["verification_method"], "MOUSE_CLICK")
        self.assertEqual(m_detail["current_enforcement_state"], "QUARANTINED")
        self.assertEqual(m_detail["re_quarantine_result"], "QUARANTINED_PENDING_ADMIN_REVIEW")

        # Invariant: CAPTCHA pass alone NEVER auto-authorizes
        check_again = self.client.post("/api/devices/check-or-request", json=mouse_req).json()
        self.assertEqual(check_again["decision"], "ASK")
        self.assertEqual(check_again["request_status"], "PENDING")

        # 2. New Keyboard arrival with KEYBOARD_CAPTCHA_PASSED
        kb_req = {
            "client_id": "client-hid-test",
            "vendor_id": "046D",
            "product_id": "C31C",
            "serial_number": "SN-NEW-KB-99",
            "device_type": "KEYBOARD",
            "description": "Logitech K120 Keyboard",
            "session_id": "sess-kb-distinct-01",
            "captcha_challenge_id": "chal-kb-01",
            "captcha_result": "KEYBOARD_CAPTCHA_PASSED",
            "verification_method": "KEYBOARD_TYPING",
            "attempt_count": 1,
            "verification_score": 100,
            "verification_duration_seconds": 3.8,
            "temp_release_applied": False,
            "temp_release_duration_seconds": 0.0,
            "re_quarantine_result": "QUARANTINED_PENDING_ADMIN_REVIEW",
            "current_enforcement_state": "QUARANTINED",
            "total_risk_score": 10,
            "severity": "LOW",
            "recommendation": "REVIEW",
            "assessment_summary": "Keyboard passed typing human challenge; quarantined pending admin approval"
        }
        res_k = self.client.post("/api/devices/check-or-request", json=kb_req).json()
        self.assertEqual(res_k["decision"], "ASK")
        self.assertEqual(res_k["request_status"], "PENDING")
        kb_req_id = res_k["request_id"]

        # Verify keyboard request details (sessions strictly unmixed)
        k_detail = self.client.get(f"/api/requests/{kb_req_id}").json()
        self.assertEqual(k_detail["device_type"], "KEYBOARD")
        self.assertEqual(k_detail["captcha_result"], "KEYBOARD_CAPTCHA_PASSED")
        self.assertEqual(k_detail["verification_method"], "KEYBOARD_TYPING")
        self.assertNotEqual(m_detail["session_id"], k_detail["session_id"])
        self.assertNotEqual(m_detail["captcha_challenge_id"], k_detail["captcha_challenge_id"])

        # 3. Explicit Admin Approval gate: Approve ONLY the mouse
        appr_res = self.client.post(f"/api/requests/{mouse_req_id}/approve", json={
            "duration_minutes": 60,
            "decision_reason": "Approved by IT Admin for workstation use",
            "admin_user": "SecurityAdmin"
        })
        self.assertEqual(appr_res.status_code, 200)

        # Approved mouse now allowed
        m_after_appr = self.client.post("/api/devices/check-or-request", json=mouse_req).json()
        self.assertEqual(m_after_appr["decision"], "ALLOW")
        self.assertEqual(m_after_appr["request_status"], "APPROVED")

        # Invariant: Unapproved keyboard is STILL PENDING/RESTRICTED
        k_check = self.client.post("/api/devices/check-or-request", json=kb_req).json()
        self.assertEqual(k_check["decision"], "ASK")
        self.assertEqual(k_check["request_status"], "PENDING")

        # 4. Explicit Admin Decline gate: Decline the keyboard
        dec_res = self.client.post(f"/api/requests/{kb_req_id}/decline", json={
            "decision_reason": "Declined untrusted keyboard",
            "admin_user": "SecurityAdmin"
        })
        self.assertEqual(dec_res.status_code, 200)

        # Declined keyboard now strictly BLOCKED
        k_after_dec = self.client.post("/api/devices/check-or-request", json=kb_req).json()
        self.assertEqual(k_after_dec["decision"], "BLOCK")
        self.assertEqual(k_after_dec["request_status"], "DECLINED")

    def test_27_preserve_non_hid_usb_workflows(self):
        """
        Verify that non-HID devices (storage, cameras, network adapters) retain
        their existing classification, scanning, authorization, and bypass HID CAPTCHA.
        """
        # 1. Non-HID Storage Device
        storage_req = {
            "client_id": "client-storage-test",
            "vendor_id": "0781",
            "product_id": "5583",
            "serial_number": "SN-SANDISK-ULTRA-01",
            "device_type": "STORAGE",
            "description": "SanDisk Ultra USB 3.0",
            "session_id": "sess-storage-01",
            "captcha_result": "NOT_COMPLETED",
            "verification_method": "NONE",
            "current_enforcement_state": "QUARANTINED",
            "total_risk_score": 15,
            "severity": "LOW",
            "recommendation": "REVIEW",
            "assessment_summary": "Removable storage scanned; awaiting administrator authorization"
        }
        res_s = self.client.post("/api/devices/check-or-request", json=storage_req).json()
        self.assertEqual(res_s["decision"], "ASK")
        s_detail = self.client.get(f"/api/requests/{res_s['request_id']}").json()
        self.assertEqual(s_detail["device_type"], "STORAGE")
        self.assertEqual(s_detail["verification_method"], "NONE")
        self.assertEqual(s_detail["captcha_result"], "NOT_COMPLETED")

        # 2. Non-HID Camera Device
        cam_req = {
            "client_id": "client-cam-test",
            "vendor_id": "046D",
            "product_id": "0825",
            "serial_number": "SN-LOGI-C270-HD",
            "device_type": "CAMERA",
            "description": "Logitech HD Webcam C270",
            "session_id": "sess-cam-01",
            "captcha_result": "NOT_COMPLETED",
            "verification_method": "NONE",
            "current_enforcement_state": "QUARANTINED",
            "total_risk_score": 5,
            "severity": "LOW",
            "recommendation": "REVIEW",
            "assessment_summary": "UVC Camera device detected; CAPTCHA bypassed"
        }
        res_c = self.client.post("/api/devices/check-or-request", json=cam_req).json()
        self.assertEqual(res_c["decision"], "ASK")
        c_detail = self.client.get(f"/api/requests/{res_c['request_id']}").json()
        self.assertEqual(c_detail["device_type"], "CAMERA")
        self.assertEqual(c_detail["verification_method"], "NONE")

        # 3. Non-HID Network Adapter
        net_req = {
            "client_id": "client-net-test",
            "vendor_id": "0BDA",
            "product_id": "8153",
            "serial_number": "SN-REALTEK-GIGABIT",
            "device_type": "NETWORK_ADAPTER",
            "description": "Realtek USB Gigabit Ethernet",
            "session_id": "sess-net-01",
            "captcha_result": "NOT_COMPLETED",
            "verification_method": "NONE",
            "current_enforcement_state": "QUARANTINED",
            "total_risk_score": 10,
            "severity": "LOW",
            "recommendation": "REVIEW",
            "assessment_summary": "USB Ethernet adapter evaluated by Algorithm 6"
        }
        res_n = self.client.post("/api/devices/check-or-request", json=net_req).json()
        self.assertEqual(res_n["decision"], "ASK")
        n_detail = self.client.get(f"/api/requests/{res_n['request_id']}").json()
        self.assertEqual(n_detail["device_type"], "NETWORK_ADAPTER")
        self.assertEqual(n_detail["verification_method"], "NONE")

    def test_28_unknown_mouse_captcha_passed_pending_approval_dashboard_retrieval(self):
        """
        Verify that an unknown USB mouse passing CAPTCHA creates a PENDING authorization
        request in the database, returns decision=ASK / request_status=PENDING to the client,
        and is retrievable via GET /api/requests?status=PENDING for dashboard display.
        """
        mouse_req = {
            "client_id": "test-workstation-win11",
            "vendor_id": "1BCF",
            "product_id": "0005",
            "serial_number": "SN-OPTICAL-MOUSE-999",
            "device_type": "MOUSE",
            "description": "Optical USB Mouse",
            "device_path": "\\\\?\\USB#VID_1BCF&PID_0005#SN-OPTICAL-MOUSE-999#{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
            "session_id": "sess-mouse-verify-999",
            "captcha_challenge_id": "CHALLENGE_MOUSE_SYM_STAR",
            "captcha_result": "MOUSE_CAPTCHA_PASSED",
            "verification_method": "MOUSE_CLICK",
            "verification_start": "2026-10-19T10:00:00Z",
            "verification_completed": "2026-10-19T10:00:05Z",
            "attempt_count": 1,
            "verification_score": 100,
            "verification_duration_seconds": 4.8,
            "temp_release_applied": True,
            "temp_release_duration_seconds": 15.0,
            "re_quarantine_result": "SUCCESS",
            "current_enforcement_state": "QUARANTINED",
            "total_risk_score": 10,
            "severity": "LOW",
            "recommendation": "REVIEW",
            "assessment_summary": "Optical USB Mouse completed human visual mouse CAPTCHA and re-quarantined cleanly",
            "algorithms_json": "{\"identity\":{\"status\":\"PASS\"},\"badusb\":{\"status\":\"PASS\"}}"
        }

        # 1. Client sends request to /api/devices/check-or-request
        resp = self.client.post("/api/devices/check-or-request", json=mouse_req)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["decision"], "ASK")
        self.assertEqual(data["request_status"], "PENDING")
        self.assertTrue(bool(data["request_id"]))
        req_id = data["request_id"]

        # 2. Server database persistence verification
        detail_resp = self.client.get(f"/api/requests/{req_id}")
        self.assertEqual(detail_resp.status_code, 200)
        detail = detail_resp.json()
        self.assertEqual(detail["status"], "PENDING")
        self.assertEqual(detail["vendor_id"], "1BCF")
        self.assertEqual(detail["product_id"], "0005")
        self.assertEqual(detail["serial_number"], "SN-OPTICAL-MOUSE-999")
        self.assertEqual(detail["device_type"], "MOUSE")
        self.assertEqual(detail["captcha_result"], "MOUSE_CAPTCHA_PASSED")
        self.assertEqual(detail["verification_method"], "MOUSE_CLICK")
        self.assertEqual(detail["current_enforcement_state"], "QUARANTINED")

        # 3. Dashboard API pending requests retrieval verification (used by dashboard UI)
        dashboard_list = self.client.get("/api/requests?status=PENDING")
        self.assertEqual(dashboard_list.status_code, 200)
        pending_items = dashboard_list.json()
        matching = [item for item in pending_items if item["request_id"] == req_id]
        self.assertEqual(len(matching), 1, "The pending mouse request must appear in GET /api/requests?status=PENDING")
        self.assertEqual(matching[0]["status"], "PENDING")
        self.assertEqual(matching[0]["vendor_id"], "1BCF")
        self.assertEqual(matching[0]["product_id"], "0005")

        # 4. Re-evaluation of auto-declined records: verify transitioning to PENDING
        # If an auto-decline occurred previously, connecting and passing CAPTCHA must re-open to PENDING
        decline_req = dict(mouse_req)
        decline_req["serial_number"] = "SN-AUTO-DECLINED-THEN-PASSED"
        decline_req["captcha_challenge_id"] = "CHALLENGE_MOUSE_SYM_TRIANGLE"
        decline_req["captcha_result"] = "FAILED"
        decline_req["severity"] = "MEDIUM"
        decline_req["recommendation"] = "REVIEW"

        init_resp = self.client.post("/api/devices/check-or-request", json=decline_req).json()
        init_id = init_resp["request_id"]

        # Admin or central policy marks it declined
        self.client.post(f"/api/requests/{init_id}/decline", json={"decision_reason": "Central Policy auto-decline"})
        # Update decision_by to Central Policy to simulate auto policy decline
        with get_db() as conn:
            conn.execute("UPDATE pending_requests SET decision_by = 'Central Policy' WHERE request_id = ?", (init_id,))

        # Device reconnects and passes CAPTCHA cleanly
        clean_retry = dict(decline_req)
        clean_retry["captcha_challenge_id"] = "CHALLENGE_MOUSE_SYM_CIRCLE"
        clean_retry["captcha_result"] = "MOUSE_CAPTCHA_PASSED"
        clean_retry["severity"] = "LOW"
        clean_retry["recommendation"] = "REVIEW"
        retry_resp = self.client.post("/api/devices/check-or-request", json=clean_retry).json()
        self.assertEqual(retry_resp["decision"], "ASK")
        self.assertEqual(retry_resp["request_status"], "PENDING")

        # Confirm it appears on dashboard pending list
        dash_res2 = self.client.get("/api/requests?status=PENDING").json()
        self.assertTrue(any(item["request_id"] == init_id for item in dash_res2))

    def test_29_revoked_and_expired_reauthorization_lifecycle_and_delete(self):
        """
        Verify:
        1. Revoked device without CAPTCHA remains BLOCK/REVOKED.
        2. Revoked mouse with MOUSE_CAPTCHA_PASSED transitions to ASK/PENDING.
        3. Revoked keyboard with KEYBOARD_CAPTCHA_PASSED transitions to ASK/PENDING.
        4. Expired device without CAPTCHA remains BLOCK/EXPIRED.
        5. Expired device with MOUSE_CAPTCHA_PASSED transitions to ASK/PENDING.
        6. DELETE /api/requests/{id} deletes the request from the dashboard queue.
        """
        # 1. Seed a revoked mouse in pending_requests
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO pending_requests (
                    request_id, client_id, vendor_id, product_id, serial_number,
                    device_type, description, status, requested_at, decided_at, decision_by, decision_reason,
                    captcha_result, verification_method
                ) VALUES (
                    'test-req-revoked-mouse-413c', 'client-01', '413C', '301A', '6&3b683a3c&0&2',
                    'MOUSE', 'Dell USB Optical Mouse', 'REVOKED', '2026-10-19T10:00:00Z', '2026-10-19T11:00:00Z',
                    'Administrator', 'Revoked by admin', 'KEYBOARD_CAPTCHA_TIMEOUT', 'KEYBOARD_TYPING'
                );
            """)

        # 2. Check without passing CAPTCHA -> Remains BLOCK / REVOKED
        no_captcha_req = {
            "client_id": "client-01",
            "vendor_id": "413C",
            "product_id": "301A",
            "serial_number": "6&3b683a3c&0&2",
            "device_type": "MOUSE",
            "description": "Dell USB Optical Mouse",
            "captcha_result": "NOT_COMPLETED",
            "verification_method": "NONE"
        }
        res_block = self.client.post("/api/devices/check-or-request", json=no_captcha_req).json()
        self.assertEqual(res_block["decision"], "BLOCK")
        self.assertEqual(res_block["request_status"], "REVOKED")

        # 3. Mouse reconnects and completes human visual mouse CAPTCHA -> Transitions to ASK / PENDING
        mouse_passed_req = {
            "client_id": "client-01",
            "vendor_id": "413C",
            "product_id": "301A",
            "serial_number": "6&3b683a3c&0&2",
            "device_type": "MOUSE",
            "description": "Dell USB Optical Mouse",
            "session_id": "sess-mouse-reauth-01",
            "captcha_challenge_id": "chal-mouse-reauth-01",
            "captcha_result": "MOUSE_CAPTCHA_PASSED",
            "verification_method": "MOUSE_CLICK",
            "verification_score": 100,
            "verification_duration_seconds": 3.2,
            "current_enforcement_state": "QUARANTINED",
            "total_risk_score": 10,
            "severity": "LOW",
            "recommendation": "REVIEW"
        }
        res_pending = self.client.post("/api/devices/check-or-request", json=mouse_passed_req).json()
        self.assertEqual(res_pending["decision"], "ASK")
        self.assertEqual(res_pending["request_status"], "PENDING")
        self.assertEqual(res_pending["request_id"], "test-req-revoked-mouse-413c")

        # Confirm visible on dashboard under PENDING
        dash_pending = self.client.get("/api/requests?status=PENDING").json()
        self.assertTrue(any(r["request_id"] == "test-req-revoked-mouse-413c" for r in dash_pending))

        # 4. Keyboard with KEYBOARD_CAPTCHA_PASSED also transitions properly
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO pending_requests (
                    request_id, client_id, vendor_id, product_id, serial_number,
                    device_type, description, status, requested_at, decided_at, decision_by, decision_reason,
                    captcha_result, verification_method
                ) VALUES (
                    'test-req-revoked-kb-046d', 'client-01', '046D', 'C31C', 'SN-REVOKED-KB-99',
                    'KEYBOARD', 'Logitech K120', 'REVOKED', '2026-10-19T10:00:00Z', '2026-10-19T11:00:00Z',
                    'Administrator', 'Revoked by admin', 'NOT_COMPLETED', 'NONE'
                );
            """)

        kb_passed_req = {
            "client_id": "client-01",
            "vendor_id": "046D",
            "product_id": "C31C",
            "serial_number": "SN-REVOKED-KB-99",
            "device_type": "KEYBOARD",
            "description": "Logitech K120",
            "session_id": "sess-kb-reauth-01",
            "captcha_challenge_id": "chal-kb-reauth-01",
            "captcha_result": "KEYBOARD_CAPTCHA_PASSED",
            "verification_method": "KEYBOARD_TYPING",
            "verification_score": 100,
            "verification_duration_seconds": 4.1,
            "current_enforcement_state": "QUARANTINED",
            "total_risk_score": 10,
            "severity": "LOW",
            "recommendation": "REVIEW"
        }
        res_kb = self.client.post("/api/devices/check-or-request", json=kb_passed_req).json()
        self.assertEqual(res_kb["decision"], "ASK")
        self.assertEqual(res_kb["request_status"], "PENDING")

        # 5. Expired device reauthorization
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO master_allowlist (
                    vendor_id, product_id, serial_number, device_type, description,
                    manufacturer, status, created_at, updated_at, duration_minutes, expires_at
                ) VALUES (
                    '046D', 'C077', 'SN-EXPIRED-MOUSE-88', 'MOUSE', 'Expired Mouse',
                    'Logitech', 'APPROVED', '2026-10-19T00:00:00Z', '2026-10-19T00:00:00Z', 15, '2026-10-19T00:15:00Z'
                );
            """)
            cursor.execute("""
                INSERT OR REPLACE INTO pending_requests (
                    request_id, client_id, vendor_id, product_id, serial_number,
                    device_type, description, status, requested_at, decided_at, decision_by, decision_reason,
                    captcha_result, verification_method, duration_minutes, expires_at
                ) VALUES (
                    'test-req-expired-mouse-88', 'client-01', '046D', 'C077', 'SN-EXPIRED-MOUSE-88',
                    'MOUSE', 'Expired Mouse', 'APPROVED', '2026-10-19T00:00:00Z', '2026-10-19T00:00:00Z',
                    'Administrator', 'Approved', 'MOUSE_CAPTCHA_PASSED', 'MOUSE_CLICK', 15, '2026-10-19T00:15:00Z'
                );
            """)

        # Expired mouse with new CAPTCHA pass re-opens as PENDING
        exp_mouse_req = {
            "client_id": "client-01",
            "vendor_id": "046D",
            "product_id": "C077",
            "serial_number": "SN-EXPIRED-MOUSE-88",
            "device_type": "MOUSE",
            "description": "Expired Mouse",
            "session_id": "sess-mouse-reauth-88",
            "captcha_challenge_id": "chal-mouse-reauth-88",
            "captcha_result": "MOUSE_CAPTCHA_PASSED",
            "verification_method": "MOUSE_CLICK",
            "verification_score": 100,
            "verification_duration_seconds": 2.9,
            "current_enforcement_state": "QUARANTINED",
            "total_risk_score": 10,
            "severity": "LOW",
            "recommendation": "REVIEW"
        }
        # Initial check detects expiration, updates allowlist, and returns BLOCK/EXPIRED
        res_exp_init = self.client.post("/api/devices/check-or-request", json=exp_mouse_req).json()
        self.assertEqual(res_exp_init["decision"], "BLOCK")
        self.assertEqual(res_exp_init["request_status"], "EXPIRED")

        # Subsequent reconnect with new CAPTCHA challenge re-opens as PENDING for admin review
        reconnect_req = dict(exp_mouse_req)
        reconnect_req["captcha_challenge_id"] = "chal-mouse-reauth-88-retry"
        res_exp = self.client.post("/api/devices/check-or-request", json=reconnect_req).json()
        self.assertEqual(res_exp["decision"], "ASK")
        self.assertEqual(res_exp["request_status"], "PENDING")

        # 6. Test DELETE /api/requests/{id} (dashboard card dismissal)
        del_res = self.client.delete("/api/requests/test-req-expired-mouse-88")
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.json()["status"], "success")

        # Verify 404 on get
        get_after_del = self.client.get("/api/requests/test-req-expired-mouse-88")
        self.assertEqual(get_after_del.status_code, 404)

    def test_30_keyboard_captcha_lifecycle_quarantine_and_approval(self):
        """
        Verify the complete keyboard CAPTCHA lifecycle:
        1. New unknown USB keyboard classified as KEYBOARD and passes typing challenge.
        2. Post-CAPTCHA: device returns to quarantine (status=PENDING, decision=ASK).
        3. Dashboard API returns device as KEYBOARD under PENDING requests.
        4. Invariant: CAPTCHA pass alone NEVER directly authorizes.
        5. Failed, timed out, or cancelled CAPTCHA strictly blocked.
        6. Explicit administrator approval enables the keyboard in master allowlist.
        7. Revocation strictly returns device to BLOCK.
        """
        # 1. New unknown physical USB keyboard completes typing challenge
        kb_req = {
            "client_id": "client-kb-e2e",
            "vendor_id": "413C",
            "product_id": "2107",
            "serial_number": "KB-DELL-TEST-001",
            "device_type": "KEYBOARD",
            "description": "Dell KB216 Wired Keyboard",
            "device_path": r"\\?\USB#VID_413C&PID_2107#KB-DELL-TEST-001#{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
            "session_id": "sess-kb-dell-001",
            "captcha_challenge_id": "chal-kb-dell-001",
            "captcha_result": "KEYBOARD_CAPTCHA_PASSED",
            "verification_method": "KEYBOARD_TYPING",
            "attempt_count": 1,
            "verification_score": 100,
            "verification_duration_seconds": 4.5,
            "temp_release_applied": False,
            "temp_release_duration_seconds": 0.0,
            "re_quarantine_result": "QUARANTINED_PENDING_ADMIN_REVIEW",
            "current_enforcement_state": "QUARANTINED",
            "total_risk_score": 10,
            "severity": "LOW",
            "recommendation": "REVIEW",
            "assessment_summary": "Dell keyboard passed typing challenge from attributed physical hardware; quarantined pending admin approval"
        }
        res_post = self.client.post("/api/devices/check-or-request", json=kb_req).json()
        self.assertEqual(res_post["decision"], "ASK")
        self.assertEqual(res_post["request_status"], "PENDING")
        req_id = res_post["request_id"]

        # 2. Verify dashboard API returns device as KEYBOARD in pending list
        reqs = self.client.get("/api/requests").json()
        matching = [r for r in reqs if r["request_id"] == req_id]
        self.assertEqual(len(matching), 1)
        k_rec = matching[0]
        self.assertEqual(k_rec["device_type"], "KEYBOARD")
        self.assertEqual(k_rec["status"], "PENDING")
        self.assertEqual(k_rec["captcha_result"], "KEYBOARD_CAPTCHA_PASSED")
        self.assertEqual(k_rec["verification_method"], "KEYBOARD_TYPING")
        self.assertEqual(k_rec["current_enforcement_state"], "QUARANTINED")

        # 3. Invariant: Unapproved keyboard remains quarantined on repeated check
        check_unapproved = self.client.post("/api/devices/check-or-request", json=kb_req).json()
        self.assertEqual(check_unapproved["decision"], "ASK")
        self.assertEqual(check_unapproved["request_status"], "PENDING")

        # 4. Verify failed, timed-out, and cancelled CAPTCHA devices are blocked
        for fail_result in ["KEYBOARD_CAPTCHA_FAILED", "KEYBOARD_CAPTCHA_TIMEOUT", "KEYBOARD_CAPTCHA_CANCELLED"]:
            fail_req = dict(kb_req)
            fail_req["product_id"] = "2108"
            fail_req["serial_number"] = f"KB-FAIL-{fail_result}"
            fail_req["session_id"] = f"sess-fail-{fail_result}"
            fail_req["captcha_challenge_id"] = f"chal-fail-{fail_result}"
            fail_req["captcha_result"] = fail_result
            fail_req["verification_score"] = 0
            fail_req["recommendation"] = "REJECT"
            fail_req["severity"] = "HIGH"
            res_fail = self.client.post("/api/devices/check-or-request", json=fail_req).json()
            # Non-passed CAPTCHA cannot be approved
            self.assertIn(res_fail["decision"], ["ASK", "BLOCK"])
            if res_fail["decision"] == "ASK":
                # Stored as pending with failed captcha; verify admin decline blocks it
                fail_req_id = res_fail["request_id"]
                dec = self.client.post(f"/api/requests/{fail_req_id}/decline", json={
                    "decision_reason": f"Declined due to {fail_result}",
                    "admin_user": "SecurityAdmin"
                })
                self.assertEqual(dec.status_code, 200)
                subsequent = self.client.post("/api/devices/check-or-request", json=fail_req).json()
                self.assertEqual(subsequent["decision"], "BLOCK")

        # 5. Administrator approves the keyboard
        appr = self.client.post(f"/api/requests/{req_id}/approve", json={
            "duration_minutes": 0,
            "decision_reason": "Approved permanent corporate USB keyboard",
            "admin_user": "SecurityAdmin"
        })
        self.assertEqual(appr.status_code, 200)

        # 6. Approved keyboard is now allowed by check-or-request
        check_approved = self.client.post("/api/devices/check-or-request", json=kb_req).json()
        self.assertEqual(check_approved["decision"], "ALLOW")
        self.assertEqual(check_approved["request_status"], "APPROVED")

        # 7. Device exists in master allowlist
        allowlist = self.client.get("/api/devices").json()
        matching_al = [d for d in allowlist if d["vendor_id"] == "413C" and d["product_id"] == "2107"]
        self.assertGreaterEqual(len(matching_al), 1)
        self.assertEqual(matching_al[0]["device_type"], "KEYBOARD")
        self.assertEqual(matching_al[0]["status"], "APPROVED")

        # 8. Administrator revokes the keyboard from master allowlist
        dev_id = matching_al[0]["id"]
        rev = self.client.delete(f"/api/devices/{dev_id}")
        self.assertEqual(rev.status_code, 200)

        # Revoked keyboard polling without fresh CAPTCHA is strictly blocked
        rev_poll = dict(kb_req)
        rev_poll["session_id"] = "sess-poll-after-rev"
        rev_poll["captcha_challenge_id"] = "chal-poll-after-rev"
        rev_poll["captcha_result"] = "NOT_COMPLETED"
        check_revoked = self.client.post("/api/devices/check-or-request", json=rev_poll).json()
        self.assertEqual(check_revoked["decision"], "BLOCK")
        self.assertEqual(check_revoked["request_status"], "REVOKED")

    def test_21_non_hid_pendrive_authorization_lifecycle(self):
        """
        Verify complete non-HID (storage / pendrive) lifecycle:
        1. Storage device connects with NOT_APPLICABLE CAPTCHA -> Enters PENDING approval queue
        2. Appears on GET /api/requests/pending
        3. Automatic decline (e.g. client timeout) -> Resubmission with clean report transitions back to PENDING
        4. Administrator explicitly approves -> ALLOW decision, added to master allowlist
        5. Storage device with critical risk -> Strictly BLOCKED and DECLINED, never PENDING
        6. HID devices still strictly require CAPTCHA (regression check for mouse & keyboard)
        """
        storage_req = {
            "client_id": "test-client-pendrive-01",
            "vendor_id": "0781",
            "product_id": "5583",
            "serial_number": "SANDISK-CRUZER-BLADE-001",
            "device_type": "STORAGE",
            "description": "SanDisk Cruzer Blade USB 2.0",
            "device_path": "\\\\?\\USB#VID_0781&PID_5583#SANDISK-CRUZER-BLADE-001#{a5dcbf10-6530-11d2-901f-00c04fb951ed}",
            "captcha_result": "NOT_APPLICABLE",
            "verification_method": "NONE",
            "total_risk_score": 25,
            "severity": "LOW",
            "recommendation": "REVIEW",
            "assessment_summary": "Storage device requires administrator review; zero-trust quarantine applied"
        }

        # 1. Fresh pendrive connection -> ASK / PENDING
        res = self.client.post("/api/devices/check-or-request", json=storage_req)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["decision"], "ASK")
        self.assertEqual(data["request_status"], "PENDING")
        req_id = data["request_id"]
        self.assertIsNotNone(req_id)

        # 2. Appears in pending queue
        pending_res = self.client.get("/api/requests/pending")
        self.assertEqual(pending_res.status_code, 200)
        pending_list = pending_res.json()
        self.assertTrue(any(p["request_id"] == req_id for p in pending_list))

        # 3. Simulate Central Policy auto-decline (e.g. client timeout)
        with get_db() as conn:
            conn.execute("UPDATE pending_requests SET status = 'DECLINED', decision_by = 'Central Policy' WHERE request_id = ?;", (req_id,))

        # Verify DECLINED check without assessment returns BLOCK
        declined_check = self.client.post("/api/devices/check-or-request", json={
            "client_id": "test-client-pendrive-01",
            "vendor_id": "0781",
            "product_id": "5583",
            "serial_number": "SANDISK-CRUZER-BLADE-001"
        }).json()
        self.assertEqual(declined_check["decision"], "BLOCK")
        self.assertEqual(declined_check["request_status"], "DECLINED")

        # Re-connecting with clean assessment report transitions back to PENDING for admin review
        reconnect_res = self.client.post("/api/devices/check-or-request", json=storage_req).json()
        self.assertEqual(reconnect_res["decision"], "ASK")
        self.assertEqual(reconnect_res["request_status"], "PENDING")

        # 4. Administrator approves the pendrive
        appr_res = self.client.post(f"/api/requests/{req_id}/approve", json={
            "duration_minutes": 15,
            "decision_reason": "Approved pendrive for test transfer",
            "admin_user": "SecurityAdmin"
        })
        self.assertEqual(appr_res.status_code, 200)

        # Client re-checks -> Now receives ALLOW!
        allow_check = self.client.post("/api/devices/check-or-request", json=storage_req).json()
        self.assertEqual(allow_check["decision"], "ALLOW")
        self.assertEqual(allow_check["request_status"], "APPROVED")
        self.assertEqual(allow_check["duration_minutes"], 15)

        # 5. Non-HID device with critical risk is strictly BLOCKED
        critical_storage_req = dict(storage_req)
        critical_storage_req["serial_number"] = "MALICIOUS-PENDRIVE-666"
        critical_storage_req["recommendation"] = "REJECT"
        critical_storage_req["severity"] = "CRITICAL"
        critical_storage_req["assessment_summary"] = "Autorun worm detected on partition"
        crit_res = self.client.post("/api/devices/check-or-request", json=critical_storage_req).json()
        self.assertEqual(crit_res["decision"], "BLOCK")
        self.assertEqual(crit_res["request_status"], "DECLINED")

        # 6. HID device regression test: HID device with NOT_APPLICABLE is NEVER approved
        fake_hid_req = {
            "client_id": "test-client-01",
            "vendor_id": "046D",
            "product_id": "C077",
            "serial_number": "SPOOF-HID-NO-CAPTCHA",
            "device_type": "HID",
            "captcha_result": "NOT_APPLICABLE",
            "recommendation": "REVIEW",
            "severity": "LOW"
        }
        with get_db() as conn:
            conn.execute("""
                INSERT INTO pending_requests (
                    request_id, client_id, vendor_id, product_id, serial_number, device_type, status, requested_at, decision_by
                ) VALUES ('fake-hid-req', 'test-client-01', '046D', 'C077', 'SPOOF-HID-NO-CAPTCHA', 'HID', 'REVOKED', '2026-01-01T00:00:00Z', 'Administrator');
            """)
        # HID device reconnecting with NOT_APPLICABLE captcha MUST remain BLOCKED (cannot bypass CAPTCHA)
        fake_hid_check = self.client.post("/api/devices/check-or-request", json=fake_hid_req).json()
        self.assertEqual(fake_hid_check["decision"], "BLOCK")
        self.assertEqual(fake_hid_check["request_status"], "REVOKED")

    def test_32_protected_folder_policies_crud_and_persistence(self):
        # 1. Default policy exists on initialization
        res = self.client.get("/api/protected-folders")
        self.assertEqual(res.status_code, 200)
        folders = res.json()
        self.assertTrue(any(f["folder_path"] == "C:\\USBIPS_Protected" for f in folders))

        # 2. Add new valid protected folder
        new_folder = {
            "folder_path": "C:\\EnterpriseSecureData",
            "description": "Sensitive Financial Records",
            "is_enabled": True
        }
        create_res = self.client.post("/api/protected-folders", json=new_folder)
        self.assertEqual(create_res.status_code, 201)
        created = create_res.json()
        self.assertEqual(created["folder_path"], "C:\\EnterpriseSecureData")
        self.assertTrue(created["is_enabled"])
        folder_id = created["id"]

        # 3. Path Validation: Reject relative or invalid paths
        bad_paths = [
            "relative/path",
            "not_a_drive_path",
            "C:",
            "C:\\",
            "C:\\Folder<Invalid>*"
        ]
        for bad in bad_paths:
            bad_res = self.client.post("/api/protected-folders", json={"folder_path": bad})
            self.assertEqual(bad_res.status_code, 400, f"Expected 400 for bad path '{bad}'")

        # 4. Duplicate folder path rejected with 409 Conflict
        dup_res = self.client.post("/api/protected-folders", json=new_folder)
        self.assertEqual(dup_res.status_code, 409)

        # 5. Toggle folder policy (Active -> Disabled -> Active)
        toggle_res = self.client.put(f"/api/protected-folders/{folder_id}/toggle")
        self.assertEqual(toggle_res.status_code, 200)
        self.assertFalse(toggle_res.json()["is_enabled"])

        # 6. Synchronization filter: enabled_only=true excludes disabled folder
        sync_res = self.client.get("/api/protected-folders?enabled_only=true")
        self.assertEqual(sync_res.status_code, 200)
        enabled_list = sync_res.json()
        self.assertFalse(any(f["id"] == folder_id for f in enabled_list))

        # Toggle back to enabled
        toggle_back = self.client.put(f"/api/protected-folders/{folder_id}/toggle")
        self.assertTrue(toggle_back.json()["is_enabled"])

        # 7. Delete folder policy
        del_res = self.client.delete(f"/api/protected-folders/{folder_id}")
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.json()["status"], "success")

        # Verify it is gone
        verify_del = self.client.get("/api/protected-folders")
        self.assertFalse(any(f["id"] == folder_id for f in verify_del.json()))

    def test_33_confirmed_policy_violation_revokes_device(self):
        # 1. Setup: Register and approve an innocent USB storage device
        dev_data = {
            "vendor_id": "0781",
            "product_id": "5581",
            "serial_number": "SN-COMPLIANT-DRIVE-01",
            "device_type": "STORAGE",
            "description": "SanDisk Ultra USB 3.0",
            "manufacturer": "SanDisk"
        }
        add_res = self.client.post("/api/devices", json=dev_data)
        self.assertEqual(add_res.status_code, 201)

        # Confirm device is currently allowed
        check_res = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-test-99",
            "vendor_id": "0781",
            "product_id": "5581",
            "serial_number": "SN-COMPLIANT-DRIVE-01",
            "device_type": "STORAGE"
        }).json()
        self.assertEqual(check_res["decision"], "ALLOW")

        # 2. Confirmed policy violation: Process executing from removable drive touches protected data
        violation_incident = {
            "client_id": "client-test-99",
            "vendor_id": "0781",
            "product_id": "5581",
            "serial_number": "SN-COMPLIANT-DRIVE-01",
            "device_id": "USB\\VID_0781&PID_5581\\SN-COMPLIANT-DRIVE-01",
            "device_type": "STORAGE",
            "description": "SanDisk Ultra USB 3.0",
            "folder_path": "C:\\USBIPS_Protected",
            "operation": "MODIFIED",
            "attribution_tier": "DEFINITIVE",
            "attribution_evidence": "Process 'payload.exe' executing from removable volume E: opened C:\\USBIPS_Protected\\confidential_canary.txt",
            "enforcement_applied": True,
            "enforcement_verified": True,
            "enforcement_code": "CR_SUCCESS"
        }
        incident_res = self.client.post("/api/incidents/policy-violation", json=violation_incident)
        self.assertEqual(incident_res.status_code, 200)
        inc_data = incident_res.json()
        self.assertEqual(inc_data["action_taken"], "DEVICE_REVOKED_AND_BLOCKED")
        self.assertTrue(inc_data["device_revoked"])
        self.assertTrue(inc_data["allowlist_purged"])

        # 3. Verify device is no longer in master_allowlist
        allow_res = self.client.get("/api/devices").json()
        self.assertFalse(any(d["serial_number"] == "SN-COMPLIANT-DRIVE-01" for d in allow_res))

        # 4. Verify client re-check returns BLOCK / REVOKED
        post_violation_check = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-test-99",
            "vendor_id": "0781",
            "product_id": "5581",
            "serial_number": "SN-COMPLIANT-DRIVE-01",
            "device_type": "STORAGE"
        }).json()
        self.assertEqual(post_violation_check["decision"], "BLOCK")
        self.assertEqual(post_violation_check["request_status"], "REVOKED")

    def test_34_uncertain_attribution_does_not_revoke_device(self):
        # 1. Setup: Approve another USB storage device
        dev_data = {
            "vendor_id": "13FE",
            "product_id": "1D20",
            "serial_number": "SN-INNOCENT-DRIVE-02",
            "device_type": "STORAGE",
            "description": "Kingston DataTraveler",
            "manufacturer": "Kingston"
        }
        self.assertEqual(self.client.post("/api/devices", json=dev_data).status_code, 201)

        # 2. Report incident with UNCERTAIN attribution (e.g. background OS file change during session)
        uncertain_incident = {
            "client_id": "client-test-99",
            "vendor_id": "13FE",
            "product_id": "1D20",
            "serial_number": "SN-INNOCENT-DRIVE-02",
            "device_id": "USB\\VID_13FE&PID_1D20\\SN-INNOCENT-DRIVE-02",
            "device_type": "STORAGE",
            "description": "Kingston DataTraveler",
            "folder_path": "C:\\EnterpriseSecureData",
            "operation": "CREATED",
            "attribution_tier": "UNCERTAIN",
            "attribution_evidence": "File created by svchost.exe while USB was connected; no USB process or write correlation proven",
            "enforcement_applied": False,
            "enforcement_verified": False
        }
        inc_res = self.client.post("/api/incidents/policy-violation", json=uncertain_incident)
        self.assertEqual(inc_res.status_code, 200)
        inc_data = inc_res.json()
        self.assertEqual(inc_data["action_taken"], "ALERT_RECORDED_ONLY")
        self.assertFalse(inc_data["device_revoked"])

        # 3. Verify device REMAINS ALLOWED in master_allowlist & client check
        allow_check = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-test-99",
            "vendor_id": "13FE",
            "product_id": "1D20",
            "serial_number": "SN-INNOCENT-DRIVE-02",
            "device_type": "STORAGE"
        }).json()
        self.assertEqual(allow_check["decision"], "ALLOW")

    def test_35_scenario_1_usb_executable_launch_revocation(self):
        # Scenario 1: Executable launched directly from removable volume
        vid, pid, sn = "0951", "1666", "SN-KINGSTON-EXE-01"
        self.assertEqual(self.client.post("/api/devices", json={
            "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE", "description": "Kingston DataTraveler 3.0"
        }).status_code, 201)

        # Dispatch Scenario 1 violation
        res = self.client.post("/api/incidents/policy-violation", json={
            "client_id": "client-endpoint-alpha",
            "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_id": f"USB\\VID_{vid}&PID_{pid}\\{sn}",
            "device_type": "STORAGE",
            "description": "Kingston DataTraveler 3.0",
            "folder_path": "E:\\malicious_payload.exe",
            "operation": "EXECUTABLE_LAUNCHED",
            "attribution_tier": "DEFINITIVE",
            "attribution_evidence": "Process 'E:\\malicious_payload.exe' (PID 4412) executed directly from removable volume E:",
            "enforcement_applied": True,
            "enforcement_verified": True,
            "enforcement_code": "CR_SUCCESS (0: Devnode operation succeeded)"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action_taken"], "DEVICE_REVOKED_AND_BLOCKED")
        self.assertTrue(data["device_revoked"])

        # Confirm device is blocked on subsequent check
        chk = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-endpoint-alpha",
            "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE"
        }).json()
        self.assertEqual(chk["decision"], "BLOCK")
        self.assertEqual(chk["request_status"], "REVOKED")

    def test_36_scenario_3_protected_file_read_telemetry_reporting(self):
        # Scenario 3: Protected-file access attempt reporting
        vid, pid, sn = "0781", "5583", "SN-SANDISK-READ-01"
        self.assertEqual(self.client.post("/api/devices", json={
            "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE", "description": "SanDisk Ultra"
        }).status_code, 201)

        res = self.client.post("/api/incidents/policy-violation", json={
            "client_id": "client-endpoint-alpha",
            "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_id": f"USB\\VID_{vid}&PID_{pid}\\{sn}",
            "device_type": "STORAGE",
            "description": "SanDisk Ultra",
            "folder_path": "C:\\USBIPS_Protected\\confidential_canary.txt",
            "operation": "FILE_READ_ATTEMPT",
            "attribution_tier": "UNCERTAIN",
            "attribution_evidence": "Attempted file read observed on protected path; user-mode watcher lacking kernel minifilter cannot deny before read",
            "enforcement_applied": False,
            "enforcement_verified": False
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["action_taken"], "ALERT_RECORDED_ONLY")
        self.assertFalse(data["device_revoked"])

    def test_37_recover_unverified_scan_error_revocation(self):
        # Seed an unverified scan error revocation
        vid, pid, sn = "13FE", "1D20", "SN-RECOVER-UNVERIFIED-01"
        req_id = "test-req-unverified-fp"
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO pending_requests (
                    request_id, client_id, vendor_id, product_id, serial_number,
                    device_type, description, status, requested_at, decided_at, decision_by, decision_reason
                ) VALUES (?, 'client-01', ?, ?, ?, 'STORAGE', 'USB Mass Storage Device', 'REVOKED',
                         '2026-10-20T10:00:00Z', '2026-10-20T10:01:00Z', 'System Policy Enforcement',
                         'Policy violation: Confirmed unauthorized AntivirusMalwareScan on protected folder REMOVABLE_STORAGE. Evidence: Post-approval malware detected by antivirus engine: Threat detected: Win32/MalwareSignature.Generic');
            """, (req_id, vid, pid, sn))

        # 1. Verify device is initially blocked as REVOKED
        chk = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-01", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE"
        }).json()
        self.assertEqual(chk["request_status"], "REVOKED")
        self.assertEqual(chk["decision"], "BLOCK")

        rec_res = self.client.post("/api/devices/recover", json={
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": sn,
            "reason": "Defender scan error 0x80508023 on inaccessible drive A: verified as false positive"
        })
        self.assertEqual(rec_res.status_code, 200)
        self.assertEqual(rec_res.json()["status"], "success")

        # 2. Check pending_requests is now PENDING and can be approved
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM pending_requests WHERE request_id = ?;", (req_id,))
            self.assertEqual(cursor.fetchone()["status"], "PENDING")

        # 3. Approve request
        app_res = self.client.post(f"/api/requests/{req_id}/approve", json={
            "admin_user": "Administrator",
            "decision_reason": "Approved clean USB drive"
        })
        self.assertEqual(app_res.status_code, 200)

        # 4. Check device returns ALLOW
        final_chk = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-01", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE"
        }).json()
        self.assertEqual(final_chk["decision"], "ALLOW")

    def test_38_recover_confirmed_malware_requires_force_override(self):
        # Seed a confirmed genuine malware revocation
        vid, pid, sn = "0781", "5583", "SN-GENUINE-MALWARE-01"
        req_id = "test-req-genuine-malware"
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO pending_requests (
                    request_id, client_id, vendor_id, product_id, serial_number,
                    device_type, description, status, requested_at, decided_at, decision_by, decision_reason
                ) VALUES (?, 'client-01', ?, ?, ?, 'STORAGE', 'SanDisk Flash Drive', 'REVOKED',
                         '2026-10-20T10:00:00Z', '2026-10-20T10:01:00Z', 'System Policy Enforcement',
                         'AntivirusMalwareScan: Confirmed malware Trojan:Win32/Wacatac.B!ml on E:\\payload.exe');
            """, (req_id, vid, pid, sn))

        # 1. Recovery without force_override MUST fail
        rec_fail = self.client.post("/api/devices/recover", json={
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": sn,
            "force_override": False
        })
        self.assertEqual(rec_fail.status_code, 400)
        self.assertIn("confirmed security revocation", rec_fail.json()["detail"].lower())

        # 2. Recovery with force_override=True succeeds
        rec_ok = self.client.post("/api/devices/recover", json={
            "vendor_id": vid,
            "product_id": pid,
            "serial_number": sn,
            "force_override": True,
            "reason": "Authorized lab quarantine environment override by SecOps"
        })
        self.assertEqual(rec_ok.status_code, 200)
        self.assertEqual(rec_ok.json()["status"], "success")

    def test_39_permanent_removal_lifecycle(self):
        """
        Verify:
        1. Approved device in master_allowlist returns ALLOW.
        2. DELETE /api/devices/{id}?permanent=true removes device from master_allowlist AND purges pending_requests.
        3. On reinsertion, device is NOT auto-approved and NOT permanently blocked; it returns ASK/PENDING.
        4. DELETE /api/requests/{id} on an approved request also removes from master_allowlist, ensuring no stale auto-approval.
        """
        vid, pid, sn = "0951", "1666", "SN-PERM-REMOVE-001"

        # 1. Register and approve device
        chk1 = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-perm-test", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE", "description": "Kingston DataTraveler"
        }).json()
        self.assertEqual(chk1["decision"], "ASK")
        req_id = chk1["request_id"]

        app_res = self.client.post(f"/api/requests/{req_id}/approve", json={
            "admin_user": "SecAdmin", "decision_reason": "Approved for transfer"
        })
        self.assertEqual(app_res.status_code, 200)

        # Verify device is now ALLOW
        chk2 = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-perm-test", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE"
        }).json()
        self.assertEqual(chk2["decision"], "ALLOW")

        # 2. Get master allowlist entry ID
        devs = self.client.get(f"/api/devices?search={sn}").json()
        self.assertTrue(len(devs) > 0)
        dev_id = devs[0]["id"]

        # 3. Explicit Permanent Removal via DELETE /api/devices/{id}?permanent=true
        del_perm = self.client.delete(f"/api/devices/{dev_id}?permanent=true")
        self.assertEqual(del_perm.status_code, 200)
        self.assertIn("permanently removed", del_perm.json()["message"].lower())

        # Verify purged from master_allowlist
        devs_after = self.client.get(f"/api/devices?search={sn}").json()
        self.assertEqual(len(devs_after), 0)

        # Verify purged from pending_requests
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM pending_requests WHERE vendor_id = ? AND product_id = ? AND serial_number = ?;", (vid, pid, sn))
            self.assertEqual(cursor.fetchone()[0], 0)

        # 4. Re-insert the same physical peripheral -> MUST go through new-device authorization (ASK/PENDING)
        reinsert_chk = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-perm-test", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE", "description": "Kingston DataTraveler"
        }).json()
        self.assertEqual(reinsert_chk["decision"], "ASK")
        self.assertEqual(reinsert_chk["request_status"], "PENDING")

        # 5. Approve again, then test permanent removal via DELETE /api/requests/{id}
        new_req_id = reinsert_chk["request_id"]
        self.client.post(f"/api/requests/{new_req_id}/approve", json={"admin_user": "SecAdmin"})
        chk_app = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-perm-test", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE"
        }).json()
        self.assertEqual(chk_app["decision"], "ALLOW")

        del_req_res = self.client.delete(f"/api/requests/{new_req_id}")
        self.assertEqual(del_req_res.status_code, 200)

        # Re-check MUST NOT auto-approve; master_allowlist entry was purged
        reinsert_chk2 = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-perm-test", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE"
        }).json()
        self.assertEqual(reinsert_chk2["decision"], "ASK")
        self.assertEqual(reinsert_chk2["request_status"], "PENDING")

    def test_40_post_approval_scan_status_synchronization(self):
        """
        Verify:
        1. An approved storage device synchronizes post-approval scan results to pending_requests.
        2. Algorithms metadata reflects CLEAN, SCANNING, INFECTED, FAILED, and UNAVAILABLE truthfully.
        """
        vid, pid, sn = "0781", "5583", "SN-SCAN-SYNC-001"

        # 1. Register and approve
        chk = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-scan-test", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE"
        }).json()
        req_id = chk["request_id"]
        self.client.post(f"/api/requests/{req_id}/approve", json={"admin_user": "SecAdmin"})

        # 2. Client synchronizes completed CLEAN scan telemetry on approved device
        clean_algo_json = (
            '{"meta":{"identity_match":true,"admin_authorized":true,'
            '"malware_scan_result":"CLEAN","executable_policy_status":"COMPLIANT",'
            '"behavioral_risk_score":0,"reasons":["Media clean"]}}'
        )
        sync_res = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-scan-test", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE", "algorithms_json": clean_algo_json,
            "total_risk_score": 0, "severity": "LOW", "recommendation": "APPROVE"
        }).json()
        self.assertEqual(sync_res["decision"], "ALLOW")

        # Verify pending_requests now has CLEAN scan status
        req_record = self.client.get(f"/api/requests/{req_id}").json()
        self.assertIn('"malware_scan_result":"CLEAN"', req_record["algorithms_json"])

        # 3. Client synchronizes INFECTED scan telemetry
        infected_algo_json = (
            '{"meta":{"identity_match":true,"admin_authorized":true,'
            '"malware_scan_result":"INFECTED","executable_policy_status":"COMPLIANT",'
            '"exact_threat_evidence":"Trojan:Win32/Wacatac.B!ml","exact_threat_file":"E:\\\\trojan.exe",'
            '"behavioral_risk_score":60,"reasons":["Malware detected"]}}'
        )
        self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-scan-test", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE", "algorithms_json": infected_algo_json,
            "total_risk_score": 60, "severity": "HIGH", "recommendation": "REJECT"
        })
        req_record2 = self.client.get(f"/api/requests/{req_id}").json()
        self.assertIn('"malware_scan_result":"INFECTED"', req_record2["algorithms_json"])
        self.assertIn('Trojan:Win32/Wacatac.B!ml', req_record2["algorithms_json"])

    def test_41_master_allowlist_purged_on_confirmed_critical_threat(self):
        """
        Verify:
        1. An administrator-approved device in master_allowlist is checked.
        2. If client submits a confirmed critical threat (.exe, .com, or malware: recommendation='REJECT', severity='CRITICAL'),
           the master_allowlist entry is immediately purged.
        3. The response returns decision='BLOCK' and request_status='DECLINED'.
        4. Subsequent checks do NOT return ALLOW.
        """
        vid, pid, sn = "0781", "5581", "SN-APPROVED-OVERRIDE-BLOCKED-041"

        # 1. Register and approve device in master_allowlist
        chk1 = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-override-test", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE"
        }).json()
        req_id = chk1["request_id"]
        self.client.post(f"/api/requests/{req_id}/approve", json={"admin_user": "SuperAdmin"})

        # Verify device is now in master_allowlist
        allow_res = self.client.get(f"/api/devices?search={sn}").json()
        self.assertEqual(len(allow_res), 1)
        self.assertEqual(allow_res[0]["status"], "APPROVED")

        # 2. Storage inspection finds prohibited .exe on removable volume -> submits REJECT / CRITICAL
        threat_json = (
            '{"meta":{"identity_match":true,"admin_authorized":true,'
            '"malware_scan_result":"CLEAN","executable_policy_status":"BLOCKED",'
            '"exact_threat_evidence":"Prohibited executable extension (.exe) detected on removable media: E:\\\\backdoor.exe",'
            '"exact_threat_file":"E:\\\\backdoor.exe",'
            '"behavioral_risk_score":85,"reasons":["Prohibited executable (.exe) detected"]}}'
        )
        chk_threat = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-override-test", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE", "algorithms_json": threat_json,
            "total_risk_score": 85, "severity": "CRITICAL", "recommendation": "REJECT",
            "assessment_summary": "Prohibited executable detected on removable storage"
        }).json()

        # MUST be blocked, NEVER allowed!
        self.assertEqual(chk_threat["decision"], "BLOCK")
        self.assertEqual(chk_threat["request_status"], "DECLINED")

        # 3. Master allowlist MUST be purged of this device
        allow_res2 = self.client.get(f"/api/devices?search={sn}").json()
        self.assertEqual(len(allow_res2), 0)

        # 4. Subsequent queries MUST NOT return ALLOW
        chk_after = self.client.post("/api/devices/check-or-request", json={
            "client_id": "client-override-test", "vendor_id": vid, "product_id": pid, "serial_number": sn,
            "device_type": "STORAGE"
        }).json()
        self.assertNotEqual(chk_after["decision"], "ALLOW")

if __name__ == "__main__":
    unittest.main()




