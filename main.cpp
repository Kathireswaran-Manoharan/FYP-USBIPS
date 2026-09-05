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

                    return 0;
                }


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
                }
                else
                {
                    DevicePresenceMonitor::TrackDevice(
                        device.deviceId,
                        device.deviceInterfacePath
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
                }


                /*
                    STEP 7
                    Unknown device.
                */
                else if (decision == AccessDecision::ASK)
                {
                    std::wcout
                        << L"Device is not in the allowlist.\n";

                    std::wcout
                        << L"Add this device to the allowlist? (Y/N): ";

                    wchar_t answer;

                    std::wcin >> answer;

                    if (answer == L'Y' ||
                        answer == L'y')
                    {
                        if (g_allowlist.AddDevice(device))
                        {
                            decision =
                                AccessDecision::ALLOW;

                            std::wcout
                                << L"Device approved.\n";
                        }
                        else
                        {
                            decision =
                                AccessDecision::BLOCK;

                            std::wcerr
                                << L"Failed to add device "
                                << L"to allowlist.\n";
                        }
                    }
                    else
                    {
                        decision =
                            AccessDecision::BLOCK;
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
                        DevicePresenceMonitor::UntrackDevice(
                            device.deviceId
                        );

                        std::wcout
                            << L"Enforcement Status : "
                            << L"DEVICE RELEASED\n";
                    }
                    else
                    {
                        std::wcerr
                            << L"Enforcement Status : "
                            << L"RELEASE FAILED\n";

                        std::wcerr
                            << L"[SECURITY] Device remains quarantined.\n";
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

    DevicePresenceMonitor::Stop();

    DestroyWindow(hwnd);

    return 0;
}