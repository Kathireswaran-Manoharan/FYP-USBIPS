#include "DevicePresenceMonitor.h"
#include "../Logging/EventLogger.h"

#include <iostream>

#pragma comment(lib, "cfgmgr32.lib")


std::vector<TrackedDevice>
DevicePresenceMonitor::g_trackedDevices;

std::mutex
DevicePresenceMonitor::g_mutex;

std::thread
DevicePresenceMonitor::g_monitorThread;

std::atomic<bool>
DevicePresenceMonitor::g_running(false);


// ============================================================
// Start
// ============================================================

bool DevicePresenceMonitor::Start()
{
    if (g_running)
        return true;

    g_running = true;

    g_monitorThread =
        std::thread(
            MonitorLoop
        );

    std::wcout
        << L"[PRESENCE] Device presence monitor started.\n";

    return true;
}


// ============================================================
// Stop
// ============================================================

void DevicePresenceMonitor::Stop()
{
    if (!g_running)
        return;

    g_running = false;

    if (g_monitorThread.joinable())
    {
        g_monitorThread.join();
    }

    std::wcout
        << L"[PRESENCE] Device presence monitor stopped.\n";
}


// ============================================================
// Track
// ============================================================

void DevicePresenceMonitor::TrackDevice(
    const USBDevice& device)
{
    if (device.deviceId.empty())
        return;

    std::lock_guard<std::mutex> lock(
        g_mutex
    );

    for (const auto& d : g_trackedDevices)
    {
        if (d.deviceId == device.deviceId)
            return;
    }

    TrackedDevice tracked;
    tracked.deviceId = device.deviceId;
    tracked.deviceInterfacePath = device.deviceInterfacePath;
    tracked.device = device;
    tracked.trackingStart = std::chrono::steady_clock::now();
    tracked.missingChecks = 0;

    g_trackedDevices.push_back(tracked);

    std::wcout
        << L"[PRESENCE] Tracking quarantined device: "
        << device.deviceId
        << L"\n";
}


void DevicePresenceMonitor::TrackDevice(
    const std::wstring& deviceId,
    const std::wstring& deviceInterfacePath)
{
    if (deviceId.empty())
        return;

    std::lock_guard<std::mutex> lock(
        g_mutex
    );

    // Prevent duplicate tracking.
    for (const auto& device :
        g_trackedDevices)
    {
        if (device.deviceId == deviceId)
            return;
    }

    TrackedDevice tracked;

    tracked.deviceId =
        deviceId;

    tracked.deviceInterfacePath =
        deviceInterfacePath;

    tracked.trackingStart =
        std::chrono::steady_clock::now();

    tracked.missingChecks = 0;

    g_trackedDevices.push_back(
        tracked
    );

    std::wcout
        << L"[PRESENCE] Tracking quarantined device: "
        << deviceId
        << L"\n";
}


// ============================================================
// Untrack
// ============================================================

void DevicePresenceMonitor::UntrackDevice(
    const std::wstring& deviceId)
{
    std::lock_guard<std::mutex> lock(
        g_mutex
    );

    for (auto it = g_trackedDevices.begin();
        it != g_trackedDevices.end();
        ++it)
    {
        if (it->deviceId == deviceId)
        {
            g_trackedDevices.erase(it);
            return;
        }
    }
}


void DevicePresenceMonitor::SetDeviceState(
    const std::wstring& deviceId,
    DeviceTrackingState state)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto& d : g_trackedDevices)
    {
        if (d.deviceId == deviceId)
        {
            d.state = state;
            return;
        }
    }

    TrackedDevice tracked;
    tracked.deviceId = deviceId;
    tracked.state = state;
    tracked.trackingStart = std::chrono::steady_clock::now();
    g_trackedDevices.push_back(tracked);
}

bool DevicePresenceMonitor::GetDeviceState(
    const std::wstring& deviceId,
    DeviceTrackingState& outState)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    for (const auto& d : g_trackedDevices)
    {
        if (d.deviceId == deviceId)
        {
            outState = d.state;
            return true;
        }
    }
    return false;
}


std::vector<TrackedDevice> DevicePresenceMonitor::GetTrackedDevices()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_trackedDevices;
}


// ============================================================
// Check presence
// ============================================================

bool DevicePresenceMonitor::IsDevicePresent(
    const std::wstring& deviceId)
{
    if (deviceId.empty())
    {
        return false;
    }

    DEVINST devInst = 0;

    // 1. Check for active/started devnode in hardware tree
    CONFIGRET result =
        CM_Locate_DevNodeW(
            &devInst,
            const_cast<DEVINSTID_W>(
                deviceId.c_str()
                ),
            CM_LOCATE_DEVNODE_NORMAL
        );

    if (result == CR_SUCCESS)
    {
        return true;
    }

    // 2. If devnode was disabled/quarantined by policy, CM_LOCATE_DEVNODE_NORMAL may fail.
    // Locate with CM_LOCATE_DEVNODE_PHANTOM and check hardware attachment via CM_Get_DevNode_Status.
    // When physically attached (even if disabled with CM_PROB_DISABLED), CM_Get_DevNode_Status returns CR_SUCCESS.
    // When physically disconnected, CM_Get_DevNode_Status returns CR_NO_SUCH_DEVINST.
    result =
        CM_Locate_DevNodeW(
            &devInst,
            const_cast<DEVINSTID_W>(
                deviceId.c_str()
                ),
            CM_LOCATE_DEVNODE_PHANTOM
        );

    if (result != CR_SUCCESS)
    {
        return false;
    }

    ULONG status = 0;
    ULONG problem = 0;
    CONFIGRET statusResult = CM_Get_DevNode_Status(&status, &problem, devInst, 0);

    return (statusResult == CR_SUCCESS);
}


// ============================================================
// Monitor
// ============================================================

void DevicePresenceMonitor::MonitorLoop()
{
    while (g_running)
    {
        {
            std::lock_guard<std::mutex> lock(
                g_mutex
            );

            auto now =
                std::chrono::steady_clock::now();

            for (auto it =
                g_trackedDevices.begin();
                it != g_trackedDevices.end();)
            {
                // Give Windows 2 seconds after tracking
                // before considering disappearance.
                auto elapsed =
                    std::chrono::duration_cast<
                    std::chrono::seconds
                    >(
                        now -
                        it->trackingStart
                    ).count();

                if (elapsed < 2)
                {
                    ++it;
                    continue;
                }


                if (IsDevicePresent(
                    it->deviceId))
                {
                    it->missingChecks = 0;

                    ++it;
                    continue;
                }


                // Device wasn't found.
                it->missingChecks++;


                // Require two consecutive
                // missing checks.
                if (it->missingChecks >= 2)
                {
                    std::wcout
                        << L"\nUSB DEVICE REMOVED\n";

                    std::wcout
                        << L"Device Interface: "
                        << it->deviceInterfacePath
                        << L"\n";

                    if (!it->device.deviceId.empty())
                    {
                        EventLogger::Instance().LogEvent(
                            SecurityEventType::DEVICE_REMOVED,
                            it->device,
                            L"-",
                            L"Physical disconnect of quarantined device detected by presence monitor"
                        );
                    }
                    else
                    {
                        EventLogger::Instance().LogSimpleEvent(
                            SecurityEventType::DEVICE_REMOVED,
                            it->deviceId,
                            it->deviceInterfacePath,
                            L"-",
                            L"Physical disconnect of quarantined device detected by presence monitor"
                        );
                    }

                    it =
                        g_trackedDevices.erase(
                            it
                        );
                }
                else
                {
                    ++it;
                }
            }
        }


        std::this_thread::sleep_for(
            std::chrono::milliseconds(500)
        );
    }
}