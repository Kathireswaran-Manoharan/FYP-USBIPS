# USBIPS — Final Verification Report: Mouse CAPTCHA, Administrator Authorization, Risk Dashboard, and Dashboard Loading

**Project:** Centralized USB Intrusion Prevention System (USBIPS) for Healthcare Systems  
**Date:** October 19, 2026  
**Environment:** Windows 10/11 x64, Visual Studio 2026 (v145), Python 3.11, FastAPI, Starlette, SQLite  
**Execution Context:** Standard User / Elevated Administrator Tested  
**Database File:** `server/usbips_server.db` (Preserved intact; historical records preserved)  
**Client Executable:** `.\x64\Debug\USBIPSClient.exe`  

---

## 1. Executive Summary & Verification Metrics

All four core system objectives requested by the user have been investigated, remediated, and verified in the existing codebase:

1. **Mouse-Only Interactive CAPTCHA:**
   - Designed and implemented a genuine click-operable multi-choice challenge in C++ Win32 GUI (`AccessControl/HIDBehaviorMonitor.cpp` & `.h`).
   - Presents a target symbol (e.g., `Star ★`, `Triangle ▲`, `Circle ●`, `Square ■`, `Diamond ◆`) with 4 randomized choice buttons, active selection highlight, explicit `✓ Confirm Selection` button, `Cancel` button, and countdown timer.
   - Requires active human selection and confirmation; clicking an option alone does not grant verification. Responses are validated against the issued challenge symbol.
   - Evaluates attempts, rejects late or replayed submissions, safely propagates `WM_QUIT` during application shutdown, and isolates focus without killing the main client process.
   - Preserves working Keyboard CAPTCHA (`KEYBOARD_TYPING`) alongside the new Mouse CAPTCHA (`MOUSE_CLICK`).
   - Automated tests added in `main.cpp` (`Test 3.13`) and `test_api.py` (`test_23_mouse_and_keyboard_captcha_metadata_ingestion`).
2. **Correct Unknown-Device Authorization:**
   - Fixed authorization mapping in `server/app/api/devices.py` and `server/app/api/requests.py`.
   - Truly new, unknown peripherals (cameras, storage, HIDs) enter central state `PENDING` (`decision="ASK"`), awaiting administrator review. They are **never** manufactured as `REVOKED`.
   - The historical revocation record for Camera `046D:094C:2508APXHB378` (ID `6f9ee78d-12f9-4413-9554-d7e990d7f93e`) in `server/usbips_server.db` is preserved intact and continues to be enforced as `REVOKED` (`decision="BLOCK"`).
   - Missing `master_allowlist` entries alone never manufacture a revocation. Expired authorizations transition to `EXPIRED` (`decision="BLOCK"`) and require re-authorization.
   - Configurable authorization durations (15m, 1h, 8h, 24h, Permanent) accurately compute `expires_at` and synchronize to client allowlists.
3. **Fixed Dashboard Loading:**
   - Root route `http://127.0.0.1:8000/` and alias `/dashboard` now cleanly return HTTP 200.
   - Diagnosed Jinja2 template signature incompatibilities across Starlette versions (`TemplateResponse(name, {"request": request})` vs `TemplateResponse(request, name)`) and implemented backwards-compatible handling.
   - Fixed dashboard empty-state behavior: previously the dashboard only queried `/api/requests/pending`, appearing empty when devices were in `REVOKED` or `DECLINED` states. Added interactive filter pills (`All Evaluated Devices`, `Pending Review`, `Revoked / Blocked`, `Approved History`) allowing viewing of all fleet devices.
   - Integrated visible backend error notification banners when API calls fail.
4. **Comprehensive Risk Scores & Explanations Display:**
   - The central dashboard renders detailed cards for all evaluated peripherals.
   - Displays Device Identity (VID, PID, Serial, Class), Client ID, and Request Status.
   - Separates TAE Trust Score (`N/100` with severity `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), Recommendation (`APPROVE`, `REVIEW`, `REJECT`), and Final Policy Decision (`ALLOW`, `BLOCK`, `ASK`).
   - Displays Identity Match and Admin Authorization status.
   - Provides **truthful malware scan status**: `NOT_SCANNED` and `NOT_APPLICABLE` are clearly distinguished from `CLEAN` and never falsely labeled clean.
   - Displays Behavioral Risk score and explainable human-readable decision reasons.
   - Breaks down individual A1–A12 outcomes and numeric risk contributions in an evidence table.
   - Shows pending request IDs, approval expiry timestamps, and admin action buttons (`Approve`, `Decline & Block`, `Re-Authorize`, `Revoke`).

### Verification Scorecard
- **C++ Client x64 Debug Build:** **PASS** (0 errors, 0 warnings).
- **C++ Security Modules Self-Test Suite (`--verify-algorithms`):** **12/12 PASSED** (All 12 modules, 10 CAPTCHA lifecycle checks, and Mouse Challenge response evaluation).
- **Python Server Test Suite (`python -m unittest`):** **25/25 PASSED** (Ran in 1.566s with 0 failures).
- **Physical USB Testing:** **NOT PERFORMED / UNVERIFIED** (Honest status distinction; no physical hardware tests are falsely claimed).

---

## 2. Root Cause Analysis

### 2.1 Mouse-Only CAPTCHA Interaction
- **Prior Behavior:**
  - `PromptMouseCaptchaChallenge` previously displayed a single button that directly submitted hardcoded strings `L"CLICK", L"CLICK"`. This failed to provide a genuine interactive challenge and could not differentiate a human clicking the correct target from random clicking or script execution.
  - When an untrusted USB mouse was plugged in, the device was immediately quarantined, but if its historical record in `usbips_server.db` had been declined or revoked during earlier testing, `check_or_request_device` returned `BLOCK`, so the mouse was blocked regardless of CAPTCHA completion.
  - Windows user-mode input hooks (`WH_MOUSE_LL`) intercept input at the desktop thread level. They cannot identify which physical USB mouse generated a raw click event without kernel-mode filter drivers.
- **Remediation:**
  - Implemented `MouseCaptchaProc` with interactive visual target presentation: the header shows a target symbol (e.g. `Click the Star ★`), and 4 randomized symbol buttons are dynamically generated.
  - The user must click the target symbol to highlight it (turning blue), then click `✓ Confirm Selection`.
  - The dialog tracks `selectedIndex`, allows canceling via `Cancel` button or `VK_ESCAPE`, counts down a 30-second timer, and drains `WM_QUIT` safely.
  - Implemented `EvaluateMouseChallengeResponse` in `AccessControl/HIDBehaviorMonitor.cpp` to validate selected symbol vs target symbol, enforce attempt limits (max 3), reject replayed challenge IDs, and handle timeouts.

### 2.2 Unknown-Device Authorization & Revocation Mapping
- **Prior Behavior:**
  - In `server/app/api/devices.py`, when a device was previously in `APPROVED` status but missing from `master_allowlist`, the code mutated the database record to `REVOKED` and returned `"Authorization was revoked by central administrator"`. This manufactured false revocations for any device that had its allowlist entry purged or expired.
  - Camera `046D:094C:2508APXHB378` already had a legitimate historical `REVOKED` record in `server/usbips_server.db` (ID `6f9ee78d-12f9-4413-9554-d7e990d7f93e`), which must remain `REVOKED`. However, new unknown cameras or storage devices were at risk of being misclassified if allowlist matching failed.
- **Remediation:**
  - Separated state evaluation into 6 distinct paths:
    1. Active allowlist entry present & unexpired &ne; `REVOKED` &rarr; `ALLOW / APPROVED`.
    2. Explicit administrative revocation (`REVOKED`) &rarr; `BLOCK / REVOKED` (historical record preserved).
    3. Explicit administrative rejection (`DECLINED`) &rarr; `BLOCK / DECLINED`.
    4. Expired authorization (`expires_at < now`) &rarr; `BLOCK / EXPIRED` (requires re-authorization).
    5. Missing allowlist entry with previous approval &rarr; `ASK / PENDING` (never manufactured into `REVOKED`).
    6. Previously unseen unknown device &rarr; `ASK / PENDING` (creates new pending request awaiting review).
  - Added re-authorization endpoint `POST /api/requests/{id}/reauthorize` allowing admins to reactivate expired or declined devices.

### 2.3 Dashboard Loading Failure
- **Prior Behavior:**
  - Navigating to `http://127.0.0.1:8000/` failed to show evaluated devices because:
    1. Newer Starlette versions accept `TemplateResponse(request, name)` while older versions require `TemplateResponse(name, {"request": request})`. Incompatibility caused internal server errors on some environments.
    2. The dashboard frontend only fetched `/api/requests/pending`. Because all historical test devices in `usbips_server.db` were either `REVOKED` or `DECLINED`, the pending queue was empty, rendering a blank screen with no indication of system status.
- **Remediation:**
  - Added try-except fallback in `serve_dashboard` in `server/app/main.py`.
  - Added route alias `@app.get("/dashboard")`.
  - Updated `index.html` to query `/api/requests/all` and render interactive filter pills:
    - **All Evaluated Devices** (shows complete fleet history).
    - **Pending Review** (shows active pending requests).
    - **Revoked / Blocked** (shows explicitly blocked devices).
    - **Approved History** (shows active allowlisted devices).
  - Added visible error banner `#apiErrorBanner` that displays network/server errors with actionable messages.

### 2.4 Risk Scores & Algorithm Explanations
- **Prior Behavior:**
  - The client C++ `SerializeAlgorithmsJson` did not embed rich metadata regarding identity match, admin authorization, truthful malware scan status, or human-readable explanation strings.
  - The dashboard lacked UI elements to present individual A1–A12 algorithm risk points or explain why a device was categorized with a specific risk score.
- **Remediation:**
  - Updated `AccessControl/TrustAssessmentEngine.cpp` to include a structured `meta` object in `algorithms_json` containing `identity_match`, `admin_authorized`, `malware_scan_result`, `behavioral_risk_score`, and `reasons`.
  - Updated `server/app/templates/index.html` to parse `algorithms_json` and render:
    - Trust Score `N/100` badge with severity-coded background (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
    - Recommendation vs Policy Decision (e.g. `Recommendation: REVIEW | Final Decision: ASK / PENDING`).
    - Identity match badge & Admin Authorization badge.
    - Truthful Malware Scan badge (`NOT_SCANNED` or `NOT_APPLICABLE` explicitly labeled and never described as clean).
    - Behavioral risk score badge.
    - Explainable Decision Rationale list itemizing every finding.
    - Individual A1–A12 numeric risk contribution table detailing points and outcome.

---

## 3. Files Changed and Summary of Modifications

| File Path | Component | Description of Changes |
| :--- | :--- | :--- |
| `AccessControl/HIDBehaviorMonitor.h` | C++ Client | Added `EvaluateMouseChallengeResponse` signature and mouse challenge validation structures. |
| `AccessControl/HIDBehaviorMonitor.cpp` | C++ Client | Implemented multi-choice interactive mouse challenge dialog (`MouseCaptchaProc`) with 4 randomized symbol buttons, selection highlighting, confirmation button, cancel handling, timer countdown, attempt decrements, replay rejection, and `WM_QUIT` propagation. |
| `AccessControl/TrustAssessmentEngine.cpp` | C++ Client | Enhanced `SerializeAlgorithmsJson` with rich `meta` section (identity match, admin authorization, truthful malware scan status, behavioral risk score, and human-readable reasons list). |
| `main.cpp` | C++ Client | Added automated test `[3.13]` verifying mouse challenge response evaluation (symbol match, mismatch attempt decrement, exhaustion, replay rejection, and timeout). |
| `server/app/api/devices.py` | FastAPI Server | Fixed unknown-device authorization mapping: new devices enter `PENDING`; preserved historical revocations; expired approvals transition to `EXPIRED`; missing allowlist entries route to `PENDING` without manufactured revocations. Added `/api/devices/{id}/reauthorize`. |
| `server/app/api/requests.py` | FastAPI Server | Added `/api/requests/{id}/reauthorize` and `/api/requests/{id}/revoke` endpoints to manage request lifecycle transitions. |
| `server/app/main.py` | FastAPI Server | Added Starlette backwards-compatible `TemplateResponse` handling and `/dashboard` alias route. |
| `server/app/templates/index.html` | Web Dashboard | Added API error banner, filter pills (`All`, `Pending`, `Revoked`, `Approved`), comprehensive card view with Trust Score `N/100`, severity, recommendation vs policy decision, identity match, admin auth state, truthful malware scan status, behavioral risk, explainable rationale list, A1–A12 risk contribution table, and duration selector. |
| `server/tests/test_api.py` | Test Suite | Added tests 19 to 25 covering unknown camera/storage `PENDING` workflow, camera historical revocation preservation, admin approval duration/expiry/rejection, expired re-authorization, mouse/keyboard CAPTCHA ingestion, dashboard root route/assets, and rich algorithms meta serialization. |
| `docs/FINAL_VERIFICATION_REPORT.md` | Documentation | Updated with complete root cause analysis, test results, route verification, and architectural boundaries. |

---

## 4. Empirical Test Results

### 4.1 C++ Algorithmic & Security Modules Test Suite
Command executed:
```powershell
.\x64\Debug\USBIPSClient.exe --verify-algorithms
```
Output Summary:
```text
=======================================================
SECURITY MODULES VERIFICATION SUMMARY: 12/12 PASSED
=======================================================
[TEST 1/12] MODULE A1: Hardware Identity & Physical Fingerprint Extraction -> PASSED
[TEST 2/12] MODULE A2: Allowlist Integrity & Cryptographic Validation    -> PASSED
[TEST 3/12] MODULE A3: Interactive HID & Keystroke Dynamics Analysis      -> PASSED
  [3.1]  Simulated typing challenge (correct text): PASS
  [3.2]  Simulated typing challenge (incorrect text): FAIL
  [3.3]  CAPTCHA deadline timeout verification: TIMEOUT
  [3.4]  Post-timeout late response submission: REJECTED (REPLAY_ATTEMPT)
  [3.5]  Replayed challenge response submission: REJECTED (REPLAY_ATTEMPT)
  [3.6]  Duplicate timeout callbacks handling: IDEMPOTENT
  [3.7]  Timeout isolation during multi-device tracking: ISOLATED
  [3.8]  Client process preservation check: PASS
  [3.9]  Timeout allowlist exclusion verification: VERIFIED
  [3.10] Central revocation priority override: REVOKED
  [3.11] Input guard hook lifecycle & focus isolation: PASS
  [3.12] Modal message loop WM_QUIT shutdown propagation: PASS (ExitCode: 42)
  [3.13] Mouse CAPTCHA challenge response evaluation: PASS
         - Correct symbol match: PASS
         - Incorrect symbol mismatch: FAIL (Attempts decremented)
         - Attempt exhaustion: EXHAUSTED
         - Replayed challenge ID: REJECTED (REPLAY_ATTEMPT)
         - Expired challenge: TIMEOUT
[TEST 4/12] MODULE A4: Removable Storage Antivirus Scanning             -> PASSED
[TEST 5/12] MODULE A5: Suspicious Storage File Heuristics                -> PASSED
[TEST 6/12] MODULE A6: Storage Process Execution Monitoring              -> PASSED
[TEST 7/12] MODULE A7: Composite & Multi-Interface BadUSB Detection     -> PASSED
[TEST 8/12] MODULE A8: Data Exfiltration Rate & Canary Monitoring        -> PASSED
[TEST 9/12] MODULE A9: USB Network & DNS Anomaly Detection               -> PASSED
[TEST 10/12] MODULE A10: Reconnection Evasion & Flapping Analysis        -> PASSED
[TEST 11/12] MODULE A11: Policy Enforcement & Synchronization            -> PASSED
[TEST 12/12] MODULE A12: Unified Trust Assessment Engine (TAE)           -> PASSED
  [12.1] Baseline Authorized Device: APPROVE (Score 0/100 LOW)
  [12.2] Unknown Device with Low Risk: REVIEW (Score 25/100 LOW)
  [12.3] Critical Denial: Malware Detected: REJECT (Score 85/100 CRITICAL)
  [12.4] Critical Denial: Composite BadUSB: REJECT (Score 100/100 CRITICAL)
  [12.5] Incomplete Evidence: AV Scanner Failed: REVIEW (Score 20/100 LOW)
  [12.6] Incomplete Evidence: AV Engine Unavailable: REVIEW (Score 15/100 LOW)
  [12.7] Suspicious File Finding: REVIEW (Score 40/100 MEDIUM)
  [12.8] Revoked Device Authorization State: REVIEW / BLOCK (Score 25/100 LOW)
  [12.9] Continuous Behavioral Surveillance (Canary Breach): REJECT (Score 85/100 CRITICAL)
```
- **Result:** **12/12 PASSED (Exit Code: 0)**.

### 4.2 Python Central Server Automated Test Suite
Command executed:
```powershell
python -m unittest discover -s server/tests -p "test_*.py" -v
```
Output Summary:
```text
test_01_health_and_dashboard ..................................................... ok
test_02_client_registration_and_heartbeat ........................................ ok
test_03_master_allowlist_crud .................................................... ok
test_04_unknown_device_server_approval_flow ...................................... ok
test_05_unknown_device_server_decline_flow ....................................... ok
test_06_device_revocation ........................................................ ok
test_07_batch_event_ingestion_and_stats .......................................... ok
test_08_client_management_endpoints .............................................. ok
test_09_server_bind_validation ................................................... ok
test_10_algorithm_event_types .................................................... ok
test_11_policy_configuration_endpoints ........................................... ok
test_12_trust_assessment_and_security_events .................................... ok
test_13_hid_captcha_and_evidence_assessment_submission ........................... ok
test_14_timed_approval_and_expiry_enforcement .................................... ok
test_15_critical_security_finding_approval_prevention ............................ ok
test_16_captcha_timeout_never_allows_and_stays_quarantined ....................... ok
test_17_accurate_revocation_and_missing_allowlist_workflow ....................... ok
test_18_end_to_end_server_client_review_and_revocation_cycle ..................... ok
test_19_unknown_camera_and_storage_pending_never_revoked ......................... ok
test_20_historical_revocation_preserved_camera ................................... ok
test_21_admin_approval_duration_expiry_and_rejection ............................. ok
test_22_expired_approval_requires_reauthorization ................................ ok
test_23_mouse_and_keyboard_captcha_metadata_ingestion ............................ ok
test_24_dashboard_root_route_and_static_assets ................................... ok
test_25_risk_explanations_and_algorithms_meta .................................... ok

----------------------------------------------------------------------
Ran 25 tests in 1.566s
OK
```
- **Result:** **25/25 PASSED (Exit Code: 0)**.

---

## 5. Dashboard Routes & API Authorization State Verification

### 5.1 Route Accessibility & Response Codes
| Route | Method | Expected HTTP | Verified Behavior |
| :--- | :---: | :---: | :--- |
| `http://127.0.0.1:8000/` | GET | 200 OK | Serves Jinja2 `index.html` template with full fleet overview, live metrics, filter pills, and risk breakdown. |
| `http://127.0.0.1:8000/dashboard` | GET | 200 OK | Serves identical template via alias route. |
| `/static/css/style.css` | GET | 200 OK | Returns dashboard stylesheet with dark-mode palette and responsive layout. |
| `/api/requests/all` | GET | 200 OK | Returns all historical and active device requests with complete risk assessment metadata. |
| `/api/requests/pending` | GET | 200 OK | Returns devices awaiting administrator decision (`status: PENDING`). |
| `/api/devices` | GET | 200 OK | Returns active master allowlist entries. |
| `/api/events` | GET | 200 OK | Returns security audit events. |

### 5.2 Authorization State Transitions Matrix
| Client Event / Context | Prior State | Action / API Call | Resulting State | Policy Decision | Allowed in Local DB? |
| :--- | :---: | :--- | :---: | :---: | :---: |
| **New Unknown Camera / Storage** | None | `POST /api/devices/check-or-request` | `PENDING` | `ASK` | No |
| **Historical Revoked Camera** (`046D:094C:2508APXHB378`) | `REVOKED` | `POST /api/devices/check-or-request` | `REVOKED` | `BLOCK` | No |
| **Admin Approval (1 Hour Duration)** | `PENDING` | `POST /api/requests/{id}/approve` | `APPROVED` | `ALLOW` | Yes (`expires_at = now + 1h`) |
| **Approval Reached Expiration** | `APPROVED` | Time elapsed (`now > expires_at`) | `EXPIRED` | `BLOCK` | Purged from Allowlist |
| **Admin Re-Authorizes Expired Device** | `EXPIRED` | `POST /api/requests/{id}/reauthorize` | `PENDING` | `ASK` | No (Awaiting new review) |
| **Admin Explicit Revocation** | `APPROVED` | `DELETE /api/devices/{id}` or `/requests/{id}/revoke` | `REVOKED` | `BLOCK` | Immediately Purged |
| **Offline Unknown Device** | None | Client Offline (`m_restClient == null`) | `QUARANTINED` | `BLOCK` | No (Fail-Closed Policy) |

---

## 6. Honest Technical Limitations & Windows Architectural Constraints

1. **User-Mode Mouse & Keyboard Hook Isolation (`WH_MOUSE_LL` / `WH_KEYBOARD_LL`):**
   - In Windows user-mode, all physical mice and keyboards multiplex into the active interactive desktop's message queue (`CS_GLOBALCLASS` / desktop input stream).
   - User-mode hooks cannot definitively isolate the physical hardware origin of an input event to a specific USB port or device instance ID without a kernel-mode class filter driver (`mouclass.sys` / `kbdclass.sys`).
   - USBIPS enforces software focus isolation (dropping input if the CAPTCHA window loses focus) and requires active human visual challenge selection. It does not claim impossible user-mode physical peripheral segregation.
2. **Device Disablement Elevation Requirement:**
   - Calling `CM_Disable_DevNode` on USB devnodes requires elevated Administrator privileges (`Run as Administrator`).
   - Under standard user accounts, Windows PnP returns `CR_ACCESS_DENIED` (51). USBIPS maintains an application-level lock in this scenario.
3. **Primary Keyboard Protection:**
   - Active system keyboards return `CR_NOT_DISABLEABLE` (40) by Windows PnP design to prevent system lockouts. USBIPS drops keystrokes in user-mode software rather than attempting unsafe PnP disablement.
4. **Storage Pre-Execution & Hardware Write Blocking:**
   - Storage execution monitoring is implemented via user-mode Toolhelp32 process enumeration and `TerminateProcess`. True pre-execution blocking requires Windows AppLocker or a kernel minifilter driver.
   - Data exfiltration tracking operates via file copy rate heuristics and canary sentinels. Hardware-level write protection requires `StorageDevicePolicies\WriteProtect` registry configuration or storage filter drivers.

---

## 7. Separate Status: Automated Verification vs. Physical USB Testing

| Verification Scope | Status | Notes & Verification Method |
| :--- | :---: | :--- |
| **Mouse-Only Interactive CAPTCHA Logic** | **VERIFIED (Automated)** | Verified in C++ Test `[3.13]` (symbol match, mismatch decrement, attempt exhaustion, replay block, timeout) and Python `test_23`. |
| **Physical Mouse Interaction on Host Hardware** | **UNVERIFIED (Pending Physical)** | Requires secondary physical USB mouse connected to host while monitoring desktop GUI. |
| **Unknown Device Authorization Workflow** | **VERIFIED (Automated)** | Verified in Python `test_19`, `test_20`, `test_21`, `test_22`. |
| **Physical USB Webcam (`046D:094C`) Connection** | **UNVERIFIED (Pending Physical)** | Verified historical record preservation in database; physical camera plug-in test pending manual hardware connection. |
| **Physical USB Storage (`13FE:1D20`) Connection** | **UNVERIFIED (Pending Physical)** | Historical AV scan and canary tests previously verified on Drive `E:\`; new unknown storage flow verified via automated test harness. |
| **Dashboard Root Route & Risk Explanations** | **VERIFIED (Automated & HTTP)** | Verified HTTP 200 on `http://127.0.0.1:8000/` and `http://127.0.0.1:8000/dashboard`, template rendering, CSS loading, and API schemas. |
| **Security Modules A1–A12 Algorithms** | **VERIFIED (Automated)** | Clean 12/12 pass in `USBIPSClient.exe --verify-algorithms`. |
| **Python Server Test Suite** | **VERIFIED (Automated)** | Clean 25/25 pass in `python -m unittest discover -s server/tests -p "test_*.py" -v`. |

*All automated tests have succeeded with 100% pass rates across both C++ and Python suites. No physical USB tests have been falsely claimed.*
