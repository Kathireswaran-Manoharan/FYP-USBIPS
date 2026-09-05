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
        self.assertEqual(res.json()["received"], 2)

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

if __name__ == "__main__":
    unittest.main()
