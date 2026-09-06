#pragma once

#include <windows.h>
#include <cfgmgr32.h>

#include <string>
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>
#include "../Models/USBDevice.h"

enum class DeviceTrackingState
{
    QUARANTINED,
    RELEASED
};

struct TrackedDevice
{
    std::wstring deviceId;
    std::wstring deviceInterfacePath;
    USBDevice device;
    DeviceTrackingState state = DeviceTrackingState::QUARANTINED;

    std::chrono::steady_clock::time_point trackingStart;
    int missingChecks = 0;
};


class DevicePresenceMonitor
{
public:

    static bool Start();

    static void Stop();

    static void TrackDevice(
        const USBDevice& device
    );

    static void TrackDevice(
        const std::wstring& deviceId,
        const std::wstring& deviceInterfacePath
    );

    static void SetDeviceState(
        const std::wstring& deviceId,
        DeviceTrackingState state
    );

    static void UntrackDevice(
        const std::wstring& deviceId
    );

    static bool IsDevicePresent(
        const std::wstring& deviceId
    );

    static std::vector<TrackedDevice> GetTrackedDevices();

private:

    static void MonitorLoop();

private:

    static std::vector<TrackedDevice>
        g_trackedDevices;

    static std::mutex
        g_mutex;

    static std::thread
        g_monitorThread;

    static std::atomic<bool>
        g_running;
};