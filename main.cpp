#include <windows.h>
#include <dbt.h>
#include <initguid.h>
#include <usbiodef.h>

#include <iostream>
#include <unordered_set>
#include <mutex>

#include "Models/USBDevice.h"
#include "Extractor/DeviceInfoExtractor.h"
#include "Classifier/DeviceClassifier.h"
#include "Allowlist/AllowlistManager.h"
#include "AccessControl/AccessController.h"
#include "Enforcement/EnforcementManager.h"
#include "Presence/DevicePresenceMonitor.h"
#include "Logging/EventLogger.h"
#include "Network/RestClient.h"
#include "Network/SyncManager.h"

HDEVNOTIFY g_hDeviceNotify = nullptr;
AllowlistManager g_allowlist;
std::unordered_set<std::wstring>
g_expectedRemovalNotifications;

std::unordered_set<std::wstring>
g_expectedArrivalNotifications;

std::mutex g_notificationMutex;

std::unordered_set<std::wstring>
g_recentlyDetectedRemovals;

std::mutex
g_removalMutex;

void ExpectInternalRemoval(
    const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(
        g_notificationMutex
    );

    g_expectedRemovalNotifications.insert(
        devicePath
    );
}


void ExpectInternalArrival(
    const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(
        g_notificationMutex
    );

    g_expectedArrivalNotifications.insert(
        devicePath
    );
}


bool ConsumeExpectedRemoval(
    const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(
        g_notificationMutex
    );

    auto it =
        g_expectedRemovalNotifications.find(
            devicePath
        );

    if (it == g_expectedRemovalNotifications.end())
    {
        return false;
    }

    g_expectedRemovalNotifications.erase(it);

    return true;
}


bool ConsumeExpectedArrival(
    const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(
        g_notificationMutex
    );

    auto it =
        g_expectedArrivalNotifications.find(
            devicePath
        );

    if (it == g_expectedArrivalNotifications.end())
    {
        return false;
    }

    g_expectedArrivalNotifications.erase(it);

    return true;
}

void CancelExpectedRemoval(
    const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(
        g_notificationMutex
    );

    g_expectedRemovalNotifications.erase(
        devicePath
    );
}


void CancelExpectedArrival(
    const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(
        g_notificationMutex
    );

    g_expectedArrivalNotifications.erase(
        devicePath
    );
}


// ============================================================
// Print device
// ============================================================

void PrintUSBDevice(
    const USBDevice& device)
{
    std::wcout
        << L"\n";

    std::wcout
        << L"========================================\n";

    std::wcout
        << L"USB DEVICE INFORMATION\n";

    std::wcout
        << L"========================================\n";

    std::wcout
        << L"Device Interface Path : "
        << device.deviceInterfacePath
        << L"\n";

    std::wcout
        << L"Device ID             : "
        << device.deviceId
        << L"\n";

    std::wcout
        << L"VID                   : "
        << device.vendorId
        << L"\n";

    std::wcout
        << L"PID                   : "
        << device.productId
        << L"\n";

    std::wcout
        << L"Serial / Instance     : "
        << device.serialNumber
        << L"\n";

    std::wcout
        << L"Description           : "
        << device.description
        << L"\n";

    std::wcout
        << L"Manufacturer          : "
        << device.manufacturer
        << L"\n";

    std::wcout
        << L"Hardware IDs          : "
        << device.hardwareIds
        << L"\n";


    // --------------------------------------------------------
    // Classification
    // --------------------------------------------------------

    std::wcout
        << L"\n";

    std::wcout
        << L"----- CLASSIFICATION -------------------\n";

    std::wcout
        << L"Device Type           : "
        << DeviceClassifier::ToString(
            device.type
        )
        << L"\n";

    std::wcout
        << L"HID Capability        : "
        << (device.hasHID ? L"YES" : L"NO")
        << L"\n";

    std::wcout
        << L"Storage Capability    : "
        << (device.hasStorage ? L"YES" : L"NO")
        << L"\n";

    std::wcout
        << L"Network Capability    : "
        << (device.hasNetwork ? L"YES" : L"NO")
        << L"\n";


    std::wcout
        << L"\nDetected Windows Classes:\n";

    for (const auto& className :
        device.detectedClasses)
    {
        std::wcout
            << L"  - "
            << className
            << L"\n";
    }

    std::wcout
        << L"========================================\n";
}


// ============================================================
// Window Procedure
// ============================================================

LRESULT CALLBACK WindowProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam)
{
    switch (message)
    {
    case WM_DEVICECHANGE:
    {
        // ------------------------------------------------
        // Device connected
        // ------------------------------------------------

        if (wParam ==
            DBT_DEVICEARRIVAL)
        {
            PDEV_BROADCAST_HDR header =
                reinterpret_cast<
                PDEV_BROADCAST_HDR
                >(lParam);

            if (header &&
                header->dbch_devicetype ==
                DBT_DEVTYP_DEVICEINTERFACE)
            {
                PDEV_BROADCAST_DEVICEINTERFACE_W
                    deviceInterface =
                    reinterpret_cast<
                    PDEV_BROADCAST_DEVICEINTERFACE_W
                    >(lParam);

                std::wstring devicePath =
                    deviceInterface->dbcc_name;

                if (ConsumeExpectedArrival(devicePath))
                {
                    std::wcout
                        << L"\n[USBIPS] Ignoring internal "
                        << L"device-enable notification.\n";

                    break;
                }

                std::wcout
                    << L"\nUSB DEVICE CONNECTED\n";


                USBDevice device;

                /*
                    STEP 1
                    Extract enough information to identify the device.
                */
                if (!DeviceInfoExtractor::Extract(
                        devicePath,
                        device))
                {
                    std::wcerr
                        << L"[ERROR] Failed to extract USB device information.\n";

                    EventLogger::Instance().LogSimpleEvent(
                        SecurityEventType::DEVICE_CONNECTED,
                        L"",
                        devicePath,
                        L"BLOCK",
                        L"Failed to extract USB device information"
                    );

                    return 0;
                }

                EventLogger::Instance().LogEvent(
                    SecurityEventType::DEVICE_CONNECTED,
                    device,
                    L"-",
                    L"USB device connected"
                );


                /*
                    STEP 2
                    Immediately quarantine the device.

                    The device remains disabled while USBIPS
                    performs classification and allowlist checking.
                */
                std::wcout
                    << L"\n----- INITIAL QUARANTINE -----\n";

                ExpectInternalRemoval(
                    device.deviceInterfacePath
                );

                bool quarantined =
                    EnforcementManager::QuarantineDevice(device);

                if (!quarantined)
                {
                    CancelExpectedRemoval(
                        device.deviceInterfacePath
                    );

                    EventLogger::Instance().LogEvent(
                        SecurityEventType::DEVICE_BLOCKED,
                        device,
                        L"BLOCK",
                        L"Initial quarantine failed; device locked by security policy"
                    );
                }
                else
                {
                    DevicePresenceMonitor::TrackDevice(
                        device
                    );

                    EventLogger::Instance().LogEvent(
                        SecurityEventType::DEVICE_QUARANTINED,
                        device,
                        L"-",
                        L"Device placed in pre-decision zero-trust quarantine"
                    );
                }

                if (!quarantined)
                {
                    std::wcerr
                        << L"[SECURITY] Could not quarantine device.\n";

                    std::wcerr
                        << L"[SECURITY] Device will NOT be automatically released.\n";

                    return 0;
                }


                /*
                    STEP 3
                    Device is now quarantined.

                    Perform classification while it is disabled.
                */
                if (!DeviceClassifier::Classify(device))
                {
                    std::wcerr
                        << L"[ERROR] Device classification failed.\n";

                    std::wcerr
                        << L"[SECURITY] Device will remain quarantined.\n";

                    EventLogger::Instance().LogEvent(
                        SecurityEventType::DEVICE_BLOCKED,
                        device,
                        L"BLOCK",
                        L"Device classification failed; kept in quarantine"
                    );

                    return 0;
                }


                /*
                    STEP 4
                    Display device information.
                */
                PrintUSBDevice(device);


                /*
                    STEP 5
                    Access-control decision.
                */
                std::wcout
                    << L"\n----- ACCESS CONTROL -----\n";

                AccessDecision decision =
                    AccessController::Evaluate(
                        device,
                        g_allowlist
                    );

                std::wcout
                    << L"Initial Decision : "
                    << AccessController::ToString(decision)
                    << L"\n";


                /*
                    STEP 6
                    Trusted device.
                */
                if (decision == AccessDecision::ALLOW)
                {
                    std::wcout
                        << L"Device is already allowlisted.\n";

                    EventLogger::Instance().LogEvent(
                        SecurityEventType::ALLOWLIST_MATCH,
                        device,
                        L"ALLOW",
                        L"Device matches local allowlist"
                    );
                }


                /*
                    STEP 7
                    Unknown device - Central Server Authorization Workflow
                */
                else if (decision == AccessDecision::ASK)
                {
                    std::wcout
                        << L"Device is not in the local allowlist.\n";

                    EventLogger::Instance().LogEvent(
                        SecurityEventType::UNKNOWN_DEVICE,
                        device,
                        L"ASK",
                        L"Device not found in local allowlist; requesting central server authorization"
                    );

                    std::wstring clientId = EventLogger::Instance().GetClientId();
                    std::wcout << L"[SERVER] Querying Central Management Server...\n";

                    DeviceCheckResult checkResult =
                        RestClient::Instance().CheckOrRequestDevice(clientId, device);

                    if (!checkResult.success)
                    {
                        // Central server is offline or unreachable -> Zero-Trust fallback
                        std::wcerr
                            << L"[OFFLINE] Central server unavailable (" << checkResult.message << L").\n"
                            << L"[OFFLINE] Enforcing local zero-trust policy: DEVICE BLOCKED.\n";

                        decision = AccessDecision::BLOCK;

                        EventLogger::Instance().LogEvent(
                            SecurityEventType::DEVICE_BLOCKED,
                            device,
                            L"BLOCK",
                            L"Central server offline; unknown device blocked by local zero-trust policy"
                        );
                    }
                    else if (checkResult.decision == L"ALLOW")
                    {
                        // Server immediately returned ALLOW (device is in server master allowlist)
                        std::wcout
                            << L"[SERVER] Authorization granted by Central Server: "
                            << checkResult.message << L"\n";

                        g_allowlist.AddDevice(device);
                        decision = AccessDecision::ALLOW;

                        EventLogger::Instance().LogEvent(
                            SecurityEventType::USER_APPROVED,
                            device,
                            L"ALLOW",
                            L"Central server master allowlist match"
                        );
                    }
                    else if (checkResult.decision == L"BLOCK")
                    {
                        std::wcout
                            << L"[SERVER] Authorization DENIED by Central Server policy: "
                            << checkResult.message << L"\n";

                        decision = AccessDecision::BLOCK;

                        EventLogger::Instance().LogEvent(
                            SecurityEventType::DEVICE_BLOCKED,
                            device,
                            L"BLOCK",
                            L"Central server policy denied authorization"
                        );
                    }
                    else // decision == L"ASK", requestStatus == L"PENDING"
                    {
                        std::wstring reqId = checkResult.requestId;
                        std::wcout << L"--------------------------------------------------\n";
                        std::wcout << L"[SERVER] Authorization request submitted to Central Server.\n";
                        std::wcout << L"[SERVER] Request ID : " << reqId << L"\n";
                        std::wcout << L"[SERVER] Status     : PENDING ADMINISTRATOR DECISION\n";
                        std::wcout << L"[SERVER] Dashboard  : http://" << RestClient::Instance().GetServerHost()
                                   << L":" << RestClient::Instance().GetServerPort() << L"\n";
                        std::wcout << L"[SECURITY] Peripheral remains quarantined in zero-trust state.\n";
                        std::wcout << L"[SERVER] Waiting for administrator decision on Web Dashboard";

                        const int maxPollSeconds = 120; // 2 minutes timeout
                        const int pollIntervalMs = 2000; // poll every 2 seconds
                        int elapsedSeconds = 0;
                        bool decided = false;

                        while (elapsedSeconds < maxPollSeconds)
                        {
                            // 1. Process any pending window messages so removal/arrival notifications aren't blocked
                            MSG msg;
                            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
                            {
                                TranslateMessage(&msg);
                                DispatchMessageW(&msg);
                            }

                            // 2. Check if device was physically disconnected while waiting
                            if (!DevicePresenceMonitor::IsDevicePresent(device.deviceId))
                            {
                                std::wcout << L"\n[NOTICE] Device was physically disconnected while awaiting approval.\n";
                                decision = AccessDecision::BLOCK;
                                decided = true;
                                break;
                            }

                            // 3. Poll server for request status
                            DeviceCheckResult pollResult = RestClient::Instance().PollRequestStatus(reqId);
                            if (pollResult.success)
                            {
                                if (pollResult.requestStatus == L"APPROVED")
                                {
                                    std::wcout << L"\n[SERVER] >>> AUTHORIZATION APPROVED BY ADMINISTRATOR! <<<\n";
                                    std::wcout << L"[SERVER] Adding device to local allowlist cache.\n";

                                    g_allowlist.AddDevice(device);
                                    decision = AccessDecision::ALLOW;

                                    EventLogger::Instance().LogEvent(
                                        SecurityEventType::USER_APPROVED,
                                        device,
                                        L"ALLOW",
                                        L"Administrator approved authorization request on Central Dashboard"
                                    );

                                    decided = true;
                                    break;
                                }
                                else if (pollResult.requestStatus == L"DECLINED")
                                {
                                    std::wcout << L"\n[SERVER] >>> AUTHORIZATION DECLINED BY ADMINISTRATOR! <<<\n";
                                    std::wcout << L"[SERVER] Device will remain blocked.\n";

                                    decision = AccessDecision::BLOCK;

                                    EventLogger::Instance().LogEvent(
                                        SecurityEventType::USER_REJECTED,
                                        device,
                                        L"BLOCK",
                                        L"Administrator declined authorization request on Central Dashboard"
                                    );

                                    decided = true;
                                    break;
                                }
                            }

                            std::wcout << L"." << std::flush;
                            Sleep(pollIntervalMs);
                            elapsedSeconds += (pollIntervalMs / 1000);
                        }

                        if (!decided)
                        {
                            std::wcout << L"\n[SERVER] Authorization request timed out (" << maxPollSeconds << L"s).\n";
                            std::wcout << L"[SERVER] Device will remain quarantined.\n";
                            decision = AccessDecision::BLOCK;

                            EventLogger::Instance().LogEvent(
                                SecurityEventType::DEVICE_BLOCKED,
                                device,
                                L"BLOCK",
                                L"Authorization request timed out while awaiting administrator approval"
                            );
                        }
                    }
                }


                /*
                    STEP 8
                    Final decision.
                */
                std::wcout
                    << L"\n----- FINAL DECISION -----\n";

                std::wcout
                    << L"Decision : "
                    << AccessController::ToString(decision)
                    << L"\n";


                /*
                    STEP 9
                    Release trusted device.
                */
                if (decision == AccessDecision::ALLOW)
                {
                    std::wcout
                        << L"\n----- ENFORCEMENT -----\n";

                    ExpectInternalArrival(
                        device.deviceInterfacePath
                    );

                    bool released =
                        EnforcementManager::ReleaseDevice(device);

                    if (!released)
                    {
                        CancelExpectedArrival(
                            device.deviceInterfacePath
                        );
                    }

                    if (released)
                    {
                        DevicePresenceMonitor::SetDeviceState(
                            device.deviceId,
                            DeviceTrackingState::RELEASED
                        );

                        std::wcout
                            << L"Enforcement Status : "
                            << L"DEVICE RELEASED\n";

                        EventLogger::Instance().LogEvent(
                            SecurityEventType::DEVICE_RELEASED,
                            device,
                            L"ALLOW",
                            L"Device released from quarantine and operational"
                        );
                    }
                    else
                    {
                        std::wcerr
                            << L"Enforcement Status : "
                            << L"RELEASE FAILED\n";

                        std::wcerr
                            << L"[SECURITY] Device remains quarantined.\n";

                        EventLogger::Instance().LogEvent(
                            SecurityEventType::DEVICE_BLOCKED,
                            device,
                            L"BLOCK",
                            L"Device release failed; device remains quarantined"
                        );
                    }
                }


                /*
                    STEP 10
                    Blocked device remains disabled.
                */
                else
                {
                    std::wcout
                        << L"\n----- ENFORCEMENT -----\n";

                    std::wcout
                        << L"Enforcement Status : "
                        << L"DEVICE REMAINS QUARANTINED\n";

                    EventLogger::Instance().LogEvent(
                        SecurityEventType::DEVICE_BLOCKED,
                        device,
                        L"BLOCK",
                        L"Device access blocked by policy; remains disabled"
                    );
                }
            }
        }


        // ------------------------------------------------
        // Device removed
        // ------------------------------------------------

        else if (
            wParam ==
            DBT_DEVICEREMOVECOMPLETE)
        {
            PDEV_BROADCAST_HDR header =
                reinterpret_cast<
                PDEV_BROADCAST_HDR
                >(lParam);

            if (header &&
                header->dbch_devicetype ==
                DBT_DEVTYP_DEVICEINTERFACE)
            {
                PDEV_BROADCAST_DEVICEINTERFACE_W
                    deviceInterface =
                    reinterpret_cast<
                    PDEV_BROADCAST_DEVICEINTERFACE_W
                    >(lParam);

                std::wstring devicePath =
                    deviceInterface->dbcc_name;

                if (ConsumeExpectedRemoval(devicePath))
                {
                    std::wcout
                        << L"\n[USBIPS] Ignoring internal "
                        << L"device-disable notification.\n";

                    break;
                }

                std::wcout
                    << L"\nUSB DEVICE REMOVED\n";

                std::wcout
                    << L"Device Interface: "
                    << devicePath
                    << L"\n";

                EventLogger::Instance().LogSimpleEvent(
                    SecurityEventType::DEVICE_REMOVED,
                    L"",
                    devicePath,
                    L"-",
                    L"USB device interface disconnected (OS notification)"
                );
            }
        }

        break;
    }


    case WM_DESTROY:

        PostQuitMessage(0);

        return 0;
    }

    return DefWindowProcW(
        hwnd,
        message,
        wParam,
        lParam
    );
}


// ============================================================
// MAIN
// ============================================================

int main()
{
    std::wcout << L"========================================\n";
    std::wcout << L"       USBIPS CLIENT - PHASE 1D\n";
    std::wcout << L"========================================\n\n";

    if (!g_allowlist.Initialize(L"usbips.db"))
    {
        std::wcerr
            << L"Failed to initialize allowlist database.\n";

        return 1;
    }

    if (!EventLogger::Instance().Initialize(L"usbips.db"))
    {
        std::wcerr
            << L"[WARNING] Failed to initialize event logging database.\n";
    }

    // --------------------------------------------------------
    // Start Background Sync Engine (Task 10 & 11)
    // --------------------------------------------------------
    SyncManager::Instance().Start(&g_allowlist, L"127.0.0.1", 8000, 5);


    // --------------------------------------------------------
    // Register window class
    // --------------------------------------------------------

    const wchar_t CLASS_NAME[] =
        L"USBIPSDeviceMonitor";

    WNDCLASSW wc{};

    wc.lpfnWndProc =
        WindowProc;

    wc.hInstance =
        GetModuleHandleW(nullptr);

    wc.lpszClassName =
        CLASS_NAME;

    RegisterClassW(&wc);


    // --------------------------------------------------------
    // Create message-only window
    // --------------------------------------------------------

    HWND hwnd =
        CreateWindowExW(
            0,
            CLASS_NAME,
            L"USBIPS",
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            nullptr,
            GetModuleHandleW(nullptr),
            nullptr
        );

    if (!hwnd)
    {
        std::wcerr
            << L"Failed to create window.\n";

        return 1;
    }


    // --------------------------------------------------------
    // Register USB notifications
    // --------------------------------------------------------

    DEV_BROADCAST_DEVICEINTERFACE_W filter{};

    filter.dbcc_size =
        sizeof(
            DEV_BROADCAST_DEVICEINTERFACE_W
            );

    filter.dbcc_devicetype =
        DBT_DEVTYP_DEVICEINTERFACE;

    filter.dbcc_classguid =
        GUID_DEVINTERFACE_USB_DEVICE;


    g_hDeviceNotify =
        RegisterDeviceNotificationW(
            hwnd,
            &filter,
            DEVICE_NOTIFY_WINDOW_HANDLE
        );


    if (!g_hDeviceNotify)
    {
        std::wcerr
            << L"Failed to register "
            L"device notifications.\n";

        DestroyWindow(hwnd);

        return 1;
    }


    std::wcout
        << L"USB monitoring started.\n";

    DevicePresenceMonitor::Start();

    std::wcout
        << L"Connect USB devices to test "
        L"classification.\n\n";


    // --------------------------------------------------------
    // Message loop
    // --------------------------------------------------------

    MSG msg{};

    while (GetMessageW(
        &msg,
        nullptr,
        0,
        0))
    {
        TranslateMessage(&msg);

        DispatchMessageW(&msg);
    }


    // --------------------------------------------------------
    // Cleanup
    // --------------------------------------------------------

    if (g_hDeviceNotify)
    {
        UnregisterDeviceNotification(
            g_hDeviceNotify
        );
    }

    SyncManager::Instance().Stop();
    DevicePresenceMonitor::Stop();
    EventLogger::Instance().Close();

    DestroyWindow(hwnd);

    return 0;
}