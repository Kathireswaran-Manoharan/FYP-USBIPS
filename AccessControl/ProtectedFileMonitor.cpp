#include "ProtectedFileMonitor.h"
#include "PolicyConfig.h"
#include "../Logging/EventLogger.h"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <iostream>

#pragma comment(lib, "advapi32.lib")

ProtectedFileMonitor& ProtectedFileMonitor::Instance()
{
    static ProtectedFileMonitor instance;
    return instance;
}

ProtectedFileMonitor::ProtectedFileMonitor()
    : m_isEnforcementActive(false)
{
}

ProtectedFileMonitor::~ProtectedFileMonitor()
{
    Stop();
}

bool ProtectedFileMonitor::Start(const std::wstring& protectedDir)
{
    if (protectedDir.empty())
    {
        std::wcerr << L"[PFMON-ENFORCE] Protected directory path is empty.\n";
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_defaultProtectedDir = protectedDir;
    if (m_configuredFolders.empty())
    {
        ProtectedFolder def;
        def.id = 1;
        def.folderPath = protectedDir;
        def.description = L"Default protected folder";
        def.isEnabled = true;
        m_configuredFolders.push_back(def);
    }

    std::wcout << L"[PFMON-ENFORCE] Protected-folder NTFS enforcement initialized.\n"
               << L"[PFMON-ENFORCE] No filesystem watcher is running; ACLs are the access-control mechanism.\n";
    return true;
}

void ProtectedFileMonitor::Stop()
{
    if (m_isEnforcementActive.load())
    {
        DeactivateEnforcement(nullptr);
    }
}

void ProtectedFileMonitor::UpdateProtectedFolders(const std::vector<ProtectedFolder>& folders)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_configuredFolders = folders;
}

std::wstring ProtectedFileMonitor::GetCurrentUserNameStr()
{
    wchar_t name[256] = {};
    DWORD size = 256;
    return GetUserNameW(name, &size) ? std::wstring(name) : std::wstring();
}

bool ProtectedFileMonitor::EnforceNativeFolderProtection(
    const std::wstring& folderPath,
    const std::wstring& userName,
    std::wstring& outOriginalSddl)
{
    if (folderPath.empty() || userName.empty())
        return false;

    DWORD attr = GetFileAttributesW(folderPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES && !CreateDirectoryW(folderPath.c_str(), nullptr))
    {
        attr = GetFileAttributesW(folderPath.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES)
        {
            std::wcerr << L"[PFMON-ACL] Cannot create protected folder: " << folderPath << L"\n";
            return false;
        }
    }

    PSECURITY_DESCRIPTOR oldSd = nullptr;
    PACL oldDacl = nullptr;
    DWORD result = GetNamedSecurityInfoW(
        folderPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &oldDacl, nullptr, &oldSd);
    if (result != ERROR_SUCCESS)
    {
        std::wcerr << L"[PFMON-ACL] GetNamedSecurityInfoW failed: " << result
                   << L" for " << folderPath << L"\n";
        return false;
    }

    LPWSTR sddl = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            oldSd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, nullptr))
    {
        LocalFree(oldSd);
        std::wcerr << L"[PFMON-ACL] Failed to save original ACL for " << folderPath << L"\n";
        return false;
    }
    outOriginalSddl = sddl;
    LocalFree(sddl);

    EXPLICIT_ACCESS_W deny = {};
    deny.grfAccessPermissions =
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE |
        DELETE | FILE_DELETE_CHILD;
    deny.grfAccessMode = DENY_ACCESS;
    deny.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    deny.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    deny.Trustee.TrusteeType = TRUSTEE_IS_USER;
    deny.Trustee.ptstrName = const_cast<LPWSTR>(userName.c_str());

    PACL newDacl = nullptr;
    result = SetEntriesInAclW(1, &deny, oldDacl, &newDacl);
    if (result == ERROR_SUCCESS)
    {
        result = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(folderPath.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl, nullptr);
    }

    if (newDacl)
        LocalFree(newDacl);
    LocalFree(oldSd);

    if (result != ERROR_SUCCESS)
    {
        std::wcerr << L"[PFMON-ACL] Failed to apply deny ACL to " << folderPath
                   << L": " << result << L"\n";
        return false;
    }
    return true;
}

bool ProtectedFileMonitor::RestoreNativeFolderProtection(
    const std::wstring& folderPath,
    const std::wstring& originalSddl)
{
    if (folderPath.empty() || originalSddl.empty())
        return false;

    PSECURITY_DESCRIPTOR restoredSd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            originalSddl.c_str(), SDDL_REVISION_1, &restoredSd, nullptr))
    {
        return false;
    }

    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    PACL dacl = nullptr;
    BOOL daclOk = GetSecurityDescriptorDacl(
        restoredSd, &daclPresent, &dacl, &daclDefaulted);
    DWORD result = daclOk
        ? SetNamedSecurityInfoW(
              const_cast<LPWSTR>(folderPath.c_str()), SE_FILE_OBJECT,
              DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr)
        : ERROR_INVALID_SECURITY_DESCR;
    LocalFree(restoredSd);
    return result == ERROR_SUCCESS;
}

bool ProtectedFileMonitor::RevokeUserDenyAce(
    const std::wstring& folderPath,
    const std::wstring& userName)
{
    if (folderPath.empty() || userName.empty())
        return false;

    PSECURITY_DESCRIPTOR oldSd = nullptr;
    PACL oldDacl = nullptr;
    DWORD result = GetNamedSecurityInfoW(
        folderPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &oldDacl, nullptr, &oldSd);
    if (result != ERROR_SUCCESS)
        return false;

    EXPLICIT_ACCESS_W revoke = {};
    revoke.grfAccessMode = REVOKE_ACCESS;
    revoke.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    revoke.Trustee.TrusteeType = TRUSTEE_IS_USER;
    revoke.Trustee.ptstrName = const_cast<LPWSTR>(userName.c_str());

    PACL newDacl = nullptr;
    result = SetEntriesInAclW(1, &revoke, oldDacl, &newDacl);
    if (result == ERROR_SUCCESS)
    {
        result = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(folderPath.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl, nullptr);
    }
    if (newDacl)
        LocalFree(newDacl);
    LocalFree(oldSd);
    return result == ERROR_SUCCESS;
}

bool ProtectedFileMonitor::ActivateEnforcement(const USBDevice* triggeringDevice)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_isEnforcementActive.load())
        return true;

    const std::wstring userName = GetCurrentUserNameStr();
    if (userName.empty())
    {
        std::wcerr << L"[PFMON-ENFORCE] Cannot determine current user for ACL enforcement.\n";
        return false;
    }

    std::vector<std::wstring> targets;
    for (const auto& folder : m_configuredFolders)
    {
        if (folder.isEnabled)
            targets.push_back(folder.folderPath);
    }
    if (targets.empty() && !m_defaultProtectedDir.empty())
        targets.push_back(m_defaultProtectedDir);
    if (targets.empty())
    {
        std::wcerr << L"[PFMON-ENFORCE] No protected folders configured.\n";
        return false;
    }

    bool allSucceeded = true;
    for (const auto& path : targets)
    {
        std::wstring savedSddl;
        if (EnforceNativeFolderProtection(path, userName, savedSddl))
        {
            m_savedFolderSddls[path] = savedSddl;
            std::wcout << L"[PFMON-ENFORCE] NTFS protection ACTIVATED on: " << path << L"\n"
                       << L"                 Read, copy, create, paste, overwrite, rename, and delete denied.\n";
        }
        else
        {
            allSucceeded = false;
        }
    }

    if (!allSucceeded)
    {
        std::wcerr << L"[PFMON-ENFORCE] Protection was not applied to all configured folders.\n";
        return false;
    }

    m_isEnforcementActive.store(true);
    EventLogger::Instance().LogSimpleEvent(
        SecurityEventType::PROTECTED_FILE_ACCESS,
        triggeringDevice ? triggeringDevice->deviceId : L"",
        m_defaultProtectedDir,
        L"ENFORCE_ACTIVE",
        L"USB presence activated NTFS protected-folder restrictions.");
    return true;
}

bool ProtectedFileMonitor::DeactivateEnforcement(const USBDevice* triggeringDevice)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_isEnforcementActive.load())
        return true;

    const std::wstring userName = GetCurrentUserNameStr();
    bool allSucceeded = true;
    for (const auto& pair : m_savedFolderSddls)
    {
        bool restored = RestoreNativeFolderProtection(pair.first, pair.second);
        if (!restored && !userName.empty())
            restored = RevokeUserDenyAce(pair.first, userName);
        if (restored)
            std::wcout << L"[PFMON-ENFORCE] NTFS protection DEACTIVATED on: " << pair.first << L"\n"
                       << L"                 Normal filesystem access restored.\n";
        else
        {
            allSucceeded = false;
            std::wcerr << L"[PFMON-ENFORCE] Failed to restore ACL on: " << pair.first << L"\n";
        }
    }

    if (allSucceeded)
    {
        m_savedFolderSddls.clear();
        m_isEnforcementActive.store(false);
    }

    EventLogger::Instance().LogSimpleEvent(
        SecurityEventType::PROTECTED_FILE_ACCESS,
        triggeringDevice ? triggeringDevice->deviceId : L"",
        m_defaultProtectedDir,
        allSucceeded ? L"ENFORCE_DEACTIVATED" : L"ENFORCE_RESTORE_FAILED",
        allSucceeded
            ? L"USB removal restored the original protected-folder ACLs."
            : L"USB removal could not restore all protected-folder ACLs.");
    return allSucceeded;
}

bool ProtectedFileMonitor::IsEnforcementActive() const
{
    return m_isEnforcementActive.load();
}

int ProtectedFileMonitor::GetActiveUsbDeviceCount() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_activeUsbDeviceCount;
}

void ProtectedFileMonitor::OnUsbDeviceConnected(const USBDevice& device)
{
    bool doEnforce = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        ++m_activeUsbDeviceCount;
        m_connectedUsbDevices[device.deviceInterfacePath] = device;
        doEnforce = PolicyConfig::Instance().enforceFolderProtectionOnUsb &&
                    !m_isEnforcementActive.load();
    }
    if (doEnforce)
        ActivateEnforcement(&device);
}

void ProtectedFileMonitor::OnUsbDeviceDisconnected(const std::wstring& devicePath)
{
    USBDevice removedDevice;
    bool shouldDeactivate = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_connectedUsbDevices.find(devicePath);
        if (it != m_connectedUsbDevices.end())
        {
            removedDevice = it->second;
            m_connectedUsbDevices.erase(it);
        }
        if (m_activeUsbDeviceCount > 0)
            --m_activeUsbDeviceCount;

        if (m_connectedUsbDevices.empty() || m_activeUsbDeviceCount == 0)
        {
            m_activeUsbDeviceCount = 0;
            shouldDeactivate = PolicyConfig::Instance().deactivateProtectionOnUsbRemoval &&
                               m_isEnforcementActive.load();
        }
    }

    if (shouldDeactivate)
        DeactivateEnforcement(&removedDevice);
    else if (m_isEnforcementActive.load())
        std::wcout << L"[PFMON-ENFORCE] USB removed; protection remains active by policy.\n";
}

bool ProtectedFileMonitor::VerifySelfTest()
{
    std::wcout << L"  [7.1] Native NTFS DACL enforcement check...\n";
    const std::wstring user = GetCurrentUserNameStr();
    if (user.empty())
        return false;

    wchar_t tempPath[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, tempPath))
        return false;
    const std::wstring folder = std::wstring(tempPath) + L"usbips_diag_acl_test";
    CreateDirectoryW(folder.c_str(), nullptr);
    const std::wstring file = folder + L"\\protected.txt";
    HANDLE handle = CreateFileW(
        file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE)
        return false;
    CloseHandle(handle);

    std::wstring originalSddl;
    const bool enforced = EnforceNativeFolderProtection(folder, user, originalSddl);
    HANDLE readHandle = CreateFileW(
        file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    const bool readDenied = readHandle == INVALID_HANDLE_VALUE &&
                            GetLastError() == ERROR_ACCESS_DENIED;
    if (readHandle != INVALID_HANDLE_VALUE)
        CloseHandle(readHandle);

    const bool restored = RestoreNativeFolderProtection(folder, originalSddl);
    DeleteFileW(file.c_str());
    RemoveDirectoryW(folder.c_str());

    std::wcout << L"        Apply deny ACL           : " << (enforced ? L"PASS" : L"FAIL") << L"\n"
               << L"        Read while protected     : " << (readDenied ? L"DENIED [PASS]" : L"ALLOWED [FAIL]") << L"\n"
               << L"        Restore original ACL     : " << (restored ? L"PASS" : L"FAIL") << L"\n";
    return enforced && readDenied && restored;
}
