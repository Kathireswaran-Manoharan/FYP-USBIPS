**USBIPS – Phase 1 Development Plan**

**USB Device Identification, Classification & Allowlist Access Control**

_Windows Client + Central Server | Complete Phase 1 Roadmap_

# 1\. Phase 1 Objective

The objective of Phase 1 is to build the first complete, end-to-end USBIPS access-control system. By the end of this phase, the Windows client will run as a Windows Service, detect USB devices, extract device information, classify the device, make an allowlist-based access decision, record the event, and communicate with the central server. The server will provide allowlist management, client management, and event/log APIs.

# 2\. Phase 1 Final Outcome

The completed flow should be:

**USB Plugged In → Device Detection → Identification → Classification → Allowlist Check → Allow / Block / User Decision → Local Log → Server Synchronization**

# 3\. Recommended Architecture

Build and debug the functionality first as a normal C++ program. Near the end of Phase 1, convert the client into a Windows Service.

The final client should keep security/background processing inside the service. A separate tray/UI application can be added later for user notifications and interactive decisions.

| **Layer**      | **Phase 1 Component**        | **Responsibility**                                                                    |
| -------------- | ---------------------------- | ------------------------------------------------------------------------------------- |
| Windows Client | USB Device Monitor           | Detect USB insertion/removal events                                                   |
| Windows Client | Device Information Extractor | Collect VID, PID, serial, class, description and available storage/volume information |
| Windows Client | Device Classifier            | Classify devices as HID, Storage, Network or Other                                    |
| Windows Client | Allowlist Access Controller  | Compare device identity against local allowlist and decide access                     |
| Windows Client | Local Database               | Cache allowlist and retain essential local records for offline operation              |
| Windows Client | Logger                       | Record device and access-control events                                               |
| Windows Client | REST Client                  | Communicate with the central server using JSON                                        |
| Windows Client | Windows Service              | Run the monitoring and access-control pipeline automatically at Windows startup       |
| Server         | REST API                     | Provide client, device, allowlist and event endpoints                                 |
| Server         | Allowlist Manager            | Add, view, update and remove trusted devices                                          |
| Server         | Client Manager               | Register clients and track basic status/heartbeat                                     |
| Server         | Event/Log API                | Receive and retrieve client events                                                    |
| Server         | Database                     | Store master allowlist, clients and events                                            |

# 4\. Technology Stack

| **Area**                     | **Recommended Technology**                                                     |
| ---------------------------- | ------------------------------------------------------------------------------ |
| Client language              | C++                                                                            |
| IDE / build                  | Visual Studio + Windows SDK; CMake optional                                    |
| USB/device detection         | Windows device notification / Plug and Play APIs                               |
| Device identification        | Windows SetupAPI / Configuration Manager / device property APIs as appropriate |
| Local database               | SQLite                                                                         |
| Client-server communication  | HTTP REST API + JSON                                                           |
| Server                       | Python + FastAPI + Uvicorn                                                     |
| Server database              | SQLite initially; PostgreSQL can be considered later                           |
| Windows background execution | Windows Service                                                                |
| Version control              | Git                                                                            |

# 5\. Development Strategy

- Do not begin with the Windows Service. First make the USB detection and decision pipeline work as a normal C++ console/desktop application.
- Use a local SQLite allowlist before depending on the server. This makes the client functional even when the server is unavailable.
- Build the server and client as one vertical slice rather than completing the entire server first.
- After the end-to-end allowlist flow is stable, convert the client process into a Windows Service.
- Behavior-based detection (HID, storage and network) is outside Phase 1 and should be integrated only after the Phase 1 interfaces are stable.

# 6\. Detailed Development Steps

## 1\. Development Environment Setup

- Install Visual Studio with C++ desktop development and the required Windows SDK.
- Create the C++ USBIPS Client solution.
- Create a Python virtual environment and FastAPI Server project.
- Create a Git repository with separate client and server directories.
- Define a common JSON data model for USB devices, clients and events.

**Deliverable: Both projects build and run independently.**

## 2\. USB Device Monitor

- Implement USB device arrival and removal notifications.
- Create a device-event callback/handler.
- On arrival, obtain the device interface/path required for further inspection.
- On removal, identify the device if possible and generate a removal event.
- Keep this module independent from the allowlist logic.

**Deliverable: The client prints/logs every USB insertion and removal.**

## 3\. Device Information Extraction

- Create a USBDevice data structure.
- Extract VID and PID.
- Extract serial number when the device exposes one.
- Extract device class/type and human-readable description.
- For storage devices, collect drive/volume information available through Windows.
- Store all fields in one normalized USBDevice object.

**Deliverable: A connected device produces a complete structured record.**

## 4\. Device Classification

- Implement an initial classifier with four categories: HID, STORAGE, NETWORK and OTHER.
- Map Windows device/interface information to the internal DeviceType enum.
- Test with a keyboard, mouse, USB flash drive and USB network adapter if available.
- Record the classification result in the event log.

**Deliverable: Each tested USB device is assigned a category.**

## 5\. Local SQLite Allowlist

- Create the local database.
- Create a devices/allowlist table.
- Store identity fields such as VID, PID, serial, device type and relevant volume identity.
- Implement add, find, update and delete operations.
- Define what constitutes an allowlist match and keep the rule deterministic.
- Support local decisions so the client can operate when the server is unavailable.

**Deliverable: The client can determine whether a device is trusted using its local database.**

## 6\. Access-Control Decision Engine

- Connect Device Information → Classifier → Allowlist lookup.
- If a device matches the allowlist, return ALLOW.
- If a device does not match, enter the unknown-device policy.
- For the first implementation, support ASK/ALLOW/BLOCK.
- If the user approves an unknown device, add it to the local allowlist.
- If the user rejects it, record BLOCK.
- Keep the decision engine independent from the UI.

**Deliverable: A real USB device receives a deterministic access-control decision.**

## 7\. Client Event Logging

- Define event types: DEVICE_CONNECTED, DEVICE_REMOVED, ALLOWLIST_MATCH, UNKNOWN_DEVICE, USER_APPROVED, USER_REJECTED and DEVICE_BLOCKED.
- Record timestamp, client ID, device identity, classification, decision and reason.
- Store events locally before attempting server synchronization.
- Use a consistent event ID so duplicate uploads can be handled later.

**Deliverable: Every important Phase 1 action is auditable.**

## 8\. FastAPI Server Foundation

- Create the FastAPI application.
- Create the server database.
- Create client registration and heartbeat structures.
- Create the master allowlist table.
- Create the event table.
- Implement basic API validation and error responses.

**Deliverable: The server can store clients, allowlist records and events.**

## 9\. Allowlist Management API

- GET /api/devices – list allowlisted devices.
- POST /api/devices – add an allowlist record.
- GET /api/devices/{id} – retrieve a device.
- PUT/PATCH /api/devices/{id} – update a device.
- DELETE /api/devices/{id} – revoke/remove a device.
- POST /api/device/check – allow the client to query the central policy when required.

**Deliverable: The server can centrally manage trusted devices.**

## 10\. Client ↔ Server Integration

- Implement the C++ REST client.
- Send device information to the server when required by the policy.
- Receive a structured decision response.
- Synchronize allowlist changes from the server to the client.
- Upload locally queued events.
- Handle server-unavailable conditions without crashing or stopping USB monitoring.

**Deliverable: One USB device can be detected on the client and represented/managed by the server.**

## 11\. Client Management and Heartbeat

- Give every client a unique client ID.
- Register the client with the server.
- Send periodic heartbeats.
- Track last-seen time on the server.
- Return basic client information such as hostname and software version.

**Deliverable: The server knows which USBIPS clients are online.**

## 12\. Convert Client to Windows Service

- Refactor startup/shutdown into a service-compatible structure.
- Move monitoring, identification, classification, access control and logging into the service.
- Register USBIPS Client Service with Windows.
- Configure automatic startup.
- Test service start, stop, restart and failure handling.
- Verify USB monitoring works without a user manually launching the program.

**Deliverable: USBIPS Client runs automatically as a Windows Service.**

## 13\. Final Phase 1 Integration Test

- Boot Windows and confirm the USBIPS service starts automatically.
- Connect an allowlisted USB device and verify ALLOW.
- Connect an unknown device and verify ASK/BLOCK behavior.
- Approve an unknown device and verify it is added to the allowlist.
- Remove/revoke a device from the server and verify synchronization.
- Disconnect a device and verify removal logging.
- Stop the server and verify the client continues using its local policy.
- Reconnect the server and verify queued events synchronize.

**Deliverable: Complete Phase 1 end-to-end demonstration.**

# 7\. Phase 1 Data Model

## USB Device

- device_id
- VID
- PID
- serial_number
- device_type
- description
- device_path
- drive_letter (if applicable)
- volume_serial (if applicable)
- first_seen
- last_seen

## Allowlist Record

- allowlist_id
- device identity fields used for matching
- device_type
- friendly_name
- status
- created_at
- updated_at
- created_by

## Security Event

- event_id
- client_id
- timestamp
- event_type
- device identity
- device_type
- decision
- reason
- synchronization_status

# 8\. API Flow

Recommended initial client/server sequence:

1. Client starts and registers with the server.
2. Client loads/synchronizes its local allowlist.
3. USB device is connected.
4. Client detects the device and extracts identity information.
5. Client classifies the device.
6. Client performs a local allowlist lookup.
7. If required, client queries the server for policy.
8. Client applies ALLOW, ASK, or BLOCK.
9. Client records the event locally.
10. Client uploads the event to the server.
11. Server updates the central event history.

# 9\. Phase 1 Testing Plan

| **Test** | **Input**                      | **Expected Result**                          |
| -------- | ------------------------------ | -------------------------------------------- |
| T1       | Known USB storage device       | Correct identification/classification; ALLOW |
| T2       | Known HID keyboard             | Correct HID classification; ALLOW            |
| T3       | Unknown USB device             | Unknown-device policy invoked                |
| T4       | Unknown device → user approves | Device added to allowlist and allowed        |
| T5       | Unknown device → user rejects  | Device blocked and event logged              |
| T6       | Device revoked from server     | Client receives updated policy               |
| T7       | USB unplugged                  | Removal event generated                      |
| T8       | Server unavailable             | Client continues using local policy          |
| T9       | Server restored                | Queued events synchronize                    |
| T10      | Windows reboot                 | USBIPS Service starts automatically          |

# 10\. Phase 1 Completion Criteria

- USB insertion/removal is detected reliably.
- VID/PID/serial and relevant device information can be extracted for the test devices.
- HID, Storage, Network and Other classification works for the selected test devices.
- The client has a functional local SQLite allowlist.
- The access controller can ALLOW, ASK or BLOCK according to policy.
- Unknown-device approval can create a new allowlist record.
- Client events are recorded and synchronized with the server.
- The server can centrally manage allowlist entries.
- The server can register and track clients.
- The client can continue operating with its local policy when the server is unavailable.
- The client runs automatically as a Windows Service after Phase 1 completion.
- A complete end-to-end demonstration can be performed without manually starting the client program.

# 11\. What Is NOT Part of Phase 1

- HID behavioral detection or CAPTCHA.
- Rubber Ducky/Pico attack testing.
- Storage data-exfiltration behavior detection.
- DNS spoofing/network behavior detection.
- Kernel-level custom USB blocking driver.
- Windows Minifilter implementation.
- Machine-learning anomaly detection.
- Enterprise-scale deployment.
- Advanced self-protection/process-injection mechanisms.

These are intentionally postponed. The Phase 1 interfaces should make it possible to add them later without redesigning the basic USB identification and access-control pipeline.

# 12\. Suggested Project Folder Structure

USBIPS/

├── client/

│ ├── src/

│ │ ├── usb/

│ │ ├── device/

│ │ ├── classifier/

│ │ ├── access/

│ │ ├── database/

│ │ ├── logging/

│ │ ├── network/

│ │ └── service/

│ ├── include/

│ └── tests/

├── server/

│ ├── app/

│ │ ├── api/

│ │ ├── models/

│ │ ├── services/

│ │ └── database/

│ └── tests/

├── docs/

└── README.md

# 13\. Recommended Development Order

Do not develop the modules in arbitrary order. Follow this dependency chain:

**USB Detection → Identification → Classification → Local Allowlist → Access Controller → Logging → Server API → Client/Server Sync → Windows Service → Integration Testing**

# 14\. Final Phase 1 Demonstration

The final demonstration should be performed from a clean Windows boot:

- Boot Windows.
- Show that the USBIPS Client Service is running automatically.
- Open the server dashboard.
- Connect a trusted USB device.
- Show identification and classification in the client/server logs.
- Show the allowlist match and ALLOW decision.
- Connect an unknown USB device.
- Show the unknown-device decision flow.
- Approve or reject it.
- Show the resulting allowlist/event change on the server.
- Revoke a device centrally and demonstrate client synchronization.
- Stop the server and demonstrate that local policy still works.
- Restart the server and demonstrate event synchronization.

# 15\. Phase 1 Deliverables

- Working C++ USBIPS client
- USB device identification module
- USB device classifier
- SQLite local allowlist
- Allowlist access-control engine
- Client event logger
- FastAPI server
- Server database
- Allowlist management API
- Client registration/heartbeat API
- Event/log API
- Client-server synchronization
- Windows Service deployment
- Phase 1 test report
- Architecture and API documentation

**Phase 1 milestone: A continuously running Windows USBIPS client with centralized allowlist management and local/offline access control.**