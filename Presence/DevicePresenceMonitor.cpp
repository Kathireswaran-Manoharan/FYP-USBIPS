#include "DevicePresenceMonitor.h"

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


// ============================================================
// Check presence
// ============================================================

bool DevicePresenceMonitor::IsDevicePresent(
    const std::wstring& deviceId)
{
    DEVINST devInst = 0;

    CONFIGRET result =
        CM_Locate_DevNodeW(
            &devInst,
            const_cast<DEVINSTID_W>(
                deviceId.c_str()
                ),
            CM_LOCATE_DEVNODE_NORMAL
        );

    return result == CR_SUCCESS;
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