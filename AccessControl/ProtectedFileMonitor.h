#pragma once

// ProtectedFileMonitor.h
// Algorithm 4: Protected-File & Multi-Folder Policy Access Monitoring
//
// SCOPE:
//   Detection only. This module watches admin-configured protected directories
//   using Win32 ReadDirectoryChangesW. It correlates file events with active
//   connected USB storage devices.
//
// ENFORCEMENT & ATTRIBUTION:
//   When a policy violation is DEFINITIVELY attributed to an active USB peripheral
//   (e.g. process executing from removable storage accesses protected data),
//   the client immediately executes OS-level disablement via EnforcementManager
//   (CM_Disable_DevNode), drops the device from the local allowlist, and submits
//   a revocation incident to the Central Management Server.
//   If attribution is UNCERTAIN, a high-severity alert is logged without falsely
//   blocking the connected device.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <map>
#include <functional>

#include "../Models/USBDevice.h"
#include "../Models/SecurityEvent.h"
#include "ProtectedFolderPolicy.h"

class AllowlistManager;

struct FileAccessEvent
{
    std::wstring timestamp;
    std::wstring filePath;
    std::wstring action;        // "MODIFIED", "CREATED", "DELETED", "RENAMED"
    bool         isCanaryFile;
    std::wstring attributionTier; // "DEFINITIVE", "PROBABILISTIC", "UNCERTAIN"
};

struct FolderWatchContext
{
    int folderId = 0;
    std::wstring folderPath;
    HANDLE dirHandle = INVALID_HANDLE_VALUE;
    OVERLAPPED ovl{};
    alignas(DWORD) BYTE notifyBuffer[8192]{};
};

class ProtectedFileMonitor
{
public:
    static ProtectedFileMonitor& Instance();

    // Start watching default protectedDir and canary
    bool Start(const std::wstring& protectedDir,
               const std::wstring& canaryFileName);

    void Stop();

    bool IsRunning() const;

    // Set the current USB device context for event correlation
    void SetActiveDevice(const USBDevice& device);
    void ClearActiveDevice();

    // Allowlist manager reference for immediate local revocation upon confirmed violation
    void SetAllowlistManager(AllowlistManager* allowlist);

    // Update list of protected folders synchronized from central server
    void UpdateWatchedFolders(const std::vector<ProtectedFolder>& folders);

    // Return accumulated events since last call (clears internal list)
    std::vector<FileAccessEvent> DrainEvents();

    // Module A8 Correlation: Canary touch tracking
    bool IsCanaryAccessCorrelated() const;
    void SimulateCanaryTouch();
    void ClearCanaryCorrelation();

    // Testing & Simulation routine
    void TriggerSimulatedViolation(const std::wstring& folderPath, const std::wstring& operation, const std::wstring& attributionTier);

private:
    ProtectedFileMonitor();
    ~ProtectedFileMonitor();

    ProtectedFileMonitor(const ProtectedFileMonitor&) = delete;
    ProtectedFileMonitor& operator=(const ProtectedFileMonitor&) = delete;

    void MonitorLoop();
    void EnsureCanaryFile(const std::wstring& path);
    std::wstring CurrentTimestamp() const;
    void CloseWatchContexts(std::vector<FolderWatchContext*>& contexts);

    std::wstring        m_defaultProtectedDir;
    std::wstring        m_canaryPath;
    std::wstring        m_canaryFileName;
    std::thread         m_thread;
    std::mutex          m_mutex;
    std::atomic<bool>   m_running;

    HANDLE              m_hStopEvent = nullptr;
    HANDLE              m_hReloadEvent = nullptr;

    USBDevice           m_activeDevice;
    bool                m_hasActiveDevice = false;
    AllowlistManager*   m_allowlist = nullptr;

    std::vector<ProtectedFolder> m_configuredFolders;
    std::vector<FileAccessEvent> m_pendingEvents;
    std::atomic<bool>            m_canaryAccessCorrelated{false};
    std::chrono::steady_clock::time_point m_lastCanaryAccessTime;
    std::map<std::wstring, std::chrono::steady_clock::time_point> m_recentFileAlerts;
};
