#pragma once

// ProtectedFileMonitor.h
// Protected-folder NTFS enforcement
//
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <mutex>
#include <atomic>
#include <vector>
#include <map>

#include "../Models/USBDevice.h"
#include "ProtectedFolderPolicy.h"

class ProtectedFileMonitor
{
public:
    static ProtectedFileMonitor& Instance();

    // Initialize the protected-folder policy used by NTFS enforcement.
    bool Start(const std::wstring& protectedDir);

    void Stop();

    void UpdateProtectedFolders(const std::vector<ProtectedFolder>& folders);

    // ============================================================
    // OS-Level Protected-Folder Access Restrictions
    // ============================================================

    // Physical USB arrival / removal lifecycle hooks
    void OnUsbDeviceConnected(const USBDevice& device);
    void OnUsbDeviceDisconnected(const std::wstring& devicePath);

    // Explicit enforcement controls (NTFS DACL Security Enforcement)
    bool ActivateEnforcement(const USBDevice* triggeringDevice = nullptr);
    bool DeactivateEnforcement(const USBDevice* triggeringDevice = nullptr);
    bool IsEnforcementActive() const;

    int GetActiveUsbDeviceCount() const;

    bool VerifySelfTest();

    // Direct folder protection helpers (applies/restores native Windows NTFS Deny ACEs)
    static bool EnforceNativeFolderProtection(const std::wstring& folderPath, const std::wstring& userName, std::wstring& outOriginalSddl);
    static bool RestoreNativeFolderProtection(const std::wstring& folderPath, const std::wstring& originalSddl);
    static bool RevokeUserDenyAce(const std::wstring& folderPath, const std::wstring& userName);
    static std::wstring GetCurrentUserNameStr();

private:
    ProtectedFileMonitor();
    ~ProtectedFileMonitor();

    ProtectedFileMonitor(const ProtectedFileMonitor&) = delete;
    ProtectedFileMonitor& operator=(const ProtectedFileMonitor&) = delete;

    std::wstring        m_defaultProtectedDir;
    mutable std::mutex  m_mutex;

    std::vector<ProtectedFolder> m_configuredFolders;

    // OS-level NTFS enforcement state
    std::atomic<bool>            m_isEnforcementActive{false};
    std::map<std::wstring, std::wstring> m_savedFolderSddls;
    std::map<std::wstring, USBDevice> m_connectedUsbDevices;
    int m_activeUsbDeviceCount = 0;
};
