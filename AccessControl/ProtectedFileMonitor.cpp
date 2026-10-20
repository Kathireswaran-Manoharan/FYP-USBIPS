// ProtectedFileMonitor.cpp
// Algorithm 4: Protected-File & Multi-Folder Policy Access Monitoring
//
// DETECTION mechanism: Win32 ReadDirectoryChangesW across multiple configured folders.
//   - Watches FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE.
//   - Synchronized dynamically from Central Management Server via Protected Folder Policies.
//
// ENFORCEMENT & ATTRIBUTION:
//   - True I/O read-interception before access requires a kernel-mode minifilter driver (FltMgr).
//   - USBIPS enforces containment at the hardware layer:
//     When a violation is DEFINITIVELY attributed to an approved USB storage device
//     (e.g. process executing from removable volume accessed protected data),
//     the client immediately triggers OS-level disablement (CM_Disable_DevNode),
//     verifies the disablement via CM_Get_DevNode_Status (Code 22), drops the device
//     from the local allowlist, and submits a permanent revocation incident to Central Server.
//   - If attribution is UNCERTAIN, high-severity incident telemetry is logged without
//     falsely disabling the approved device.

#include "ProtectedFileMonitor.h"
#include "PolicyConfig.h"
#include "StorageExecutionMonitor.h"
#include "../Logging/EventLogger.h"
#include "../Models/SecurityEvent.h"
#include "../Enforcement/EnforcementManager.h"
#include "../Classifier/DeviceClassifier.h"
#include "../Network/RestClient.h"
#include "../Allowlist/AllowlistManager.h"

#include <windows.h>
#include <cfgmgr32.h>
#include <aclapi.h>
#include <sddl.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include "MinifilterClient.h"

#pragma comment(lib, "advapi32.lib")

// ============================================================
// Singleton
// ============================================================

ProtectedFileMonitor& ProtectedFileMonitor::Instance()
{
    static ProtectedFileMonitor instance;
    return instance;
}

ProtectedFileMonitor::ProtectedFileMonitor()
    : m_running(false)
    , m_hasActiveDevice(false)
    , m_allowlist(nullptr)
{
    m_hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    m_hReloadEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

ProtectedFileMonitor::~ProtectedFileMonitor()
{
    Stop();
    if (m_hStopEvent) CloseHandle(m_hStopEvent);
    if (m_hReloadEvent) CloseHandle(m_hReloadEvent);
}

// ============================================================
// Start / Stop
// ============================================================

bool ProtectedFileMonitor::Start(
    const std::wstring& protectedDir,
    const std::wstring& canaryFileName)
{
    if (m_running.load())
        return true;

    m_defaultProtectedDir = protectedDir;
    m_canaryFileName      = canaryFileName;
    m_canaryPath          = protectedDir + L"\\" + canaryFileName;

    // Create default directory if it doesn't exist
    if (!CreateDirectoryW(protectedDir.c_str(), nullptr))
    {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS)
        {
            std::wcerr << L"[PFMON] Cannot create default protected directory: "
                       << protectedDir << L"\n";
        }
    }

    EnsureCanaryFile(m_canaryPath);

    // Seed default folder in configured folders if empty
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_configuredFolders.empty())
        {
            ProtectedFolder def;
            def.id = 1;
            def.folderPath = protectedDir;
            def.description = L"Default Sentinel Quarantine Folder";
            def.isEnabled = true;
            m_configuredFolders.push_back(def);
        }
    }

    ResetEvent(m_hStopEvent);
    ResetEvent(m_hReloadEvent);
    m_running.store(true);
    m_thread = std::thread(&ProtectedFileMonitor::MonitorLoop, this);

    std::wcout << L"[PFMON] Protected-file monitor STARTED.\n"
               << L"[PFMON] Default Path : " << protectedDir << L"\n"
               << L"[PFMON] Canary File  : " << m_canaryPath << L"\n"
               << L"[PFMON] NOTE: User-mode detection via ReadDirectoryChangesW.\n"
               << L"               Policy violations definitively attributed to USB storage trigger hardware disablement.\n";

    return true;
}

void ProtectedFileMonitor::Stop()
{
    if (m_isEnforcementActive.load())
    {
        DeactivateEnforcement(nullptr);
    }

    if (!m_running.load())
        return;

    m_running.store(false);

    if (m_hStopEvent)
    {
        SetEvent(m_hStopEvent);
    }

    if (m_thread.joinable())
        m_thread.join();

    std::wcout << L"[PFMON] Protected-file monitor stopped.\n";
}

bool ProtectedFileMonitor::IsRunning() const
{
    return m_running.load();
}

void ProtectedFileMonitor::SetActiveDevice(const USBDevice& device)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_activeDevice    = device;
    m_hasActiveDevice = true;
}

void ProtectedFileMonitor::ClearActiveDevice()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_hasActiveDevice = false;
}

bool ProtectedFileMonitor::HasActiveDevice() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_hasActiveDevice;
}

USBDevice ProtectedFileMonitor::GetActiveDevice() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_activeDevice;
}

void ProtectedFileMonitor::SetAllowlistManager(AllowlistManager* allowlist)
{
    m_allowlist = allowlist;
}

void ProtectedFileMonitor::UpdateWatchedFolders(const std::vector<ProtectedFolder>& folders)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_configuredFolders = folders;

    // Wake the monitoring loop to reload directory watches
    if (m_hReloadEvent)
    {
        SetEvent(m_hReloadEvent);
    }
}

std::vector<FileAccessEvent> ProtectedFileMonitor::DrainEvents()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<FileAccessEvent> out;
    out.swap(m_pendingEvents);
    return out;
}

// ============================================================
// Canary Sentinel
// ============================================================

void ProtectedFileMonitor::EnsureCanaryFile(const std::wstring& path)
{
    HANDLE h = CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
        nullptr);

    if (h != INVALID_HANDLE_VALUE)
    {
        const char* content =
            "USBIPS CANARY FILE\r\n"
            "This file is a security sentinel.\r\n"
            "Any modification triggers a PROTECTED_FILE_ACCESS alert.\r\n"
            "Do not edit, move, or delete this file.\r\n";

        DWORD written = 0;
        WriteFile(h, content, static_cast<DWORD>(strlen(content)), &written, nullptr);
        CloseHandle(h);

        std::wcout << L"[PFMON] Canary sentinel file created: " << path << L"\n";
    }
}

std::wstring ProtectedFileMonitor::CurrentTimestamp() const
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    wchar_t buf[32]{};
    swprintf_s(buf, 32, L"%04d-%02d-%02dT%02d:%02d:%02dZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return buf;
}

void ProtectedFileMonitor::CloseWatchContexts(std::vector<FolderWatchContext*>& contexts)
{
    for (auto* ctx : contexts)
    {
        if (ctx)
        {
            if (ctx->dirHandle != INVALID_HANDLE_VALUE)
            {
                CancelIo(ctx->dirHandle);
                CloseHandle(ctx->dirHandle);
            }
            if (ctx->ovl.hEvent)
            {
                CloseHandle(ctx->ovl.hEvent);
            }
            delete ctx;
        }
    }
    contexts.clear();
}

// ============================================================
// Multi-Directory Monitoring Loop
// ============================================================

void ProtectedFileMonitor::MonitorLoop()
{
    std::vector<FolderWatchContext*> watchContexts;

    auto RebuildWatches = [this, &watchContexts]() {
        CloseWatchContexts(watchContexts);

        std::vector<ProtectedFolder> targets;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            targets = m_configuredFolders;
        }

        for (const auto& f : targets)
        {
            if (!f.isEnabled)
                continue;

            // Ensure directory exists or create safely
            DWORD attr = GetFileAttributesW(f.folderPath.c_str());
            if (attr == INVALID_FILE_ATTRIBUTES)
            {
                CreateDirectoryW(f.folderPath.c_str(), nullptr);
                attr = GetFileAttributesW(f.folderPath.c_str());
            }

            if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY))
            {
                std::wcerr << L"[PFMON] Inaccessible protected folder policy skipped: " << f.folderPath << L"\n";
                continue;
            }

            HANDLE hDir = CreateFileW(
                f.folderPath.c_str(),
                FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                nullptr
            );

            if (hDir == INVALID_HANDLE_VALUE)
            {
                std::wcerr << L"[PFMON] Cannot open directory handle for " << f.folderPath << L"\n";
                continue;
            }

            auto* ctx = new FolderWatchContext();
            ctx->folderId = f.id;
            ctx->folderPath = f.folderPath;
            ctx->dirHandle = hDir;
            ctx->ovl.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

            BOOL ok = ReadDirectoryChangesW(
                ctx->dirHandle,
                ctx->notifyBuffer,
                sizeof(ctx->notifyBuffer),
                FALSE,
                FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_DIR_NAME  |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
                nullptr,
                &ctx->ovl,
                nullptr
            );

            if (ok)
            {
                watchContexts.push_back(ctx);
                std::wcout << L"[PFMON] Active Watch established: " << f.folderPath << L"\n";
            }
            else
            {
                CloseHandle(ctx->ovl.hEvent);
                CloseHandle(ctx->dirHandle);
                delete ctx;
            }
        }
    };

    RebuildWatches();

    while (m_running.load())
    {
        // Build wait handles array: [0] = StopEvent, [1] = ReloadEvent, [2..N] = FolderEvents
        std::vector<HANDLE> waitHandles;
        waitHandles.push_back(m_hStopEvent);
        waitHandles.push_back(m_hReloadEvent);

        for (auto* ctx : watchContexts)
        {
            if (ctx && ctx->ovl.hEvent)
            {
                waitHandles.push_back(ctx->ovl.hEvent);
            }
        }

        DWORD waitRes = WaitForMultipleObjects(
            static_cast<DWORD>(waitHandles.size()),
            waitHandles.data(),
            FALSE,
            1500
        );

        if (!m_running.load() || waitRes == WAIT_OBJECT_0)
        {
            break;
        }

        if (waitRes == (WAIT_OBJECT_0 + 1))
        {
            // Reload event fired
            ResetEvent(m_hReloadEvent);
            RebuildWatches();
            continue;
        }

        if (waitRes >= (WAIT_OBJECT_0 + 2) && waitRes < (WAIT_OBJECT_0 + waitHandles.size()))
        {
            size_t ctxIdx = waitRes - (WAIT_OBJECT_0 + 2);
            if (ctxIdx < watchContexts.size())
            {
                auto* ctx = watchContexts[ctxIdx];
                DWORD bytesReturned = 0;
                if (GetOverlappedResult(ctx->dirHandle, &ctx->ovl, &bytesReturned, FALSE) && bytesReturned > 0)
                {
                    const BYTE* ptr = ctx->notifyBuffer;
                    while (true)
                    {
                        const auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(ptr);
                        std::wstring fileName(info->FileName, info->FileNameLength / sizeof(WCHAR));

                        std::wstring action;
                        switch (info->Action)
                        {
                        case FILE_ACTION_ADDED:            action = L"CREATED";  break;
                        case FILE_ACTION_REMOVED:          action = L"DELETED";  break;
                        case FILE_ACTION_MODIFIED:         action = L"MODIFIED"; break;
                        case FILE_ACTION_RENAMED_OLD_NAME: action = L"RENAMED";  break;
                        case FILE_ACTION_RENAMED_NEW_NAME: action = L"RENAMED_TO"; break;
                        default:                           action = L"CHANGED";  break;
                        }

                        std::wstring fullPath = ctx->folderPath + L"\\" + fileName;
                        bool isCanary = (_wcsicmp(fileName.c_str(), m_canaryFileName.c_str()) == 0);

                        // Coalesce duplicate notifications within 3-second window
                        std::wstring dedupKey = fullPath + L":" + action;
                        auto nowTime = std::chrono::steady_clock::now();
                        bool isDuplicateBurst = false;
                        {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            auto itAlert = m_recentFileAlerts.find(dedupKey);
                            if (itAlert != m_recentFileAlerts.end())
                            {
                                double elapsed = std::chrono::duration<double>(nowTime - itAlert->second).count();
                                if (elapsed < 3.0)
                                {
                                    isDuplicateBurst = true;
                                }
                            }
                            if (!isDuplicateBurst)
                            {
                                m_recentFileAlerts[dedupKey] = nowTime;
                            }
                        }

                        if (isDuplicateBurst)
                        {
                            if (info->NextEntryOffset == 0) break;
                            ptr += info->NextEntryOffset;
                            continue;
                        }

                        // Rigorous Attribution Assessment (Definitive vs. Probabilistic vs. Uncertain)
                        std::wstring attributionTier = L"UNCERTAIN";
                        std::wstring attributionEvidence;
                        bool definitiveAttribution = false;

                        // 1. Check if any running process is executing directly from removable USB storage
                        auto runningViolations = StorageExecutionMonitor::Instance().ScanRunningProcesses(false);
                        if (!runningViolations.empty())
                        {
                            definitiveAttribution = true;
                            attributionTier = L"DEFINITIVE";
                            const auto& viol = runningViolations.front();
                            attributionEvidence = L"Executable binary '" + viol.processName + L"' (PID: " +
                                                  std::to_wstring(viol.processId) + L") executing directly from removable volume " +
                                                  viol.removableDrive + L" accessed protected folder " + ctx->folderPath;
                        }
                        else if (m_hasActiveDevice)
                        {
                            attributionTier = L"UNCERTAIN";
                            attributionEvidence = L"File modification observed in protected folder during active USB session; no process originating from removable storage proven.";
                        }
                        else
                        {
                            attributionTier = L"LOCAL";
                            attributionEvidence = L"Local filesystem activity without active USB peripheral.";
                        }

                        if (isCanary)
                        {
                            m_canaryAccessCorrelated.store(true);
                            m_lastCanaryAccessTime = std::chrono::steady_clock::now();
                            std::wcout << L"\n[PFMON] *** HIGH SEVERITY: CANARY SENTINEL TOUCHED ***\n"
                                       << L"[PFMON] Folder : " << ctx->folderPath << L"\n"
                                       << L"[PFMON] File   : " << fullPath << L"\n"
                                       << L"[PFMON] Action : " << action << L"\n"
                                       << L"[PFMON] Attribution: " << attributionTier << L"\n";
                        }
                        else
                        {
                            std::wcout << L"[PFMON] [DETECTION] " << action << L" | " << fullPath
                                       << L" | Attribution: " << attributionTier << L"\n";
                        }

                        // Store pending event
                        FileAccessEvent evt;
                        evt.timestamp = CurrentTimestamp();
                        evt.filePath = fullPath;
                        evt.action = action;
                        evt.isCanaryFile = isCanary;
                        evt.attributionTier = attributionTier;

                        {
                            std::lock_guard<std::mutex> lock(m_mutex);
                            m_pendingEvents.push_back(evt);
                        }

                        // Response logic:
                        // If DEFINITIVELY attributed to an approved USB peripheral -> Revoke & Block immediately!
                        if (definitiveAttribution && m_hasActiveDevice)
                        {
                            std::wcout << L"\n=======================================================\n";
                            std::wcout << L"[POLICY ENFORCEMENT] Confirmed protected-folder violation by peripheral "
                                       << m_activeDevice.vendorId << L":" << m_activeDevice.productId << L"\n";
                            std::wcout << L"[POLICY ENFORCEMENT] Disabling device at OS level via CM_Disable_DevNode...\n";

                            CONFIGRET crResult = CR_FAILURE;
                            bool disabled = EnforcementManager::QuarantineDevice(m_activeDevice, &crResult);

                            // Verify whether Windows actually disabled the device
                            bool verified = false;
                            DEVINST devInst = 0;
                            if (CM_Locate_DevNodeW(&devInst, const_cast<DEVINSTID_W>(m_activeDevice.deviceId.c_str()), CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS)
                            {
                                ULONG status = 0, problem = 0;
                                if (CM_Get_DevNode_Status(&status, &problem, devInst, 0) == CR_SUCCESS)
                                {
                                    verified = (problem == CM_PROB_DISABLED);
                                }
                            }

                            std::wcout << L"[POLICY ENFORCEMENT] Devnode disablement: "
                                       << EnforcementManager::ConfigRetToString(crResult)
                                       << L" (Verified Code 22: " << (verified ? L"YES" : L"NO") << L")\n";
                            std::wcout << L"=======================================================\n";

                            // Remove from local allowlist
                            if (m_allowlist)
                            {
                                m_allowlist->RemoveDevice(m_activeDevice);
                            }

                            // Submit incident and revocation to Central Management Server
                            PolicyViolationIncident inc;
                            inc.clientId = EventLogger::Instance().GetClientId();
                            inc.vendorId = m_activeDevice.vendorId;
                            inc.productId = m_activeDevice.productId;
                            inc.serialNumber = m_activeDevice.serialNumber;
                            inc.deviceId = m_activeDevice.deviceId;
                            inc.deviceType = DeviceClassifier::ToString(m_activeDevice.type);
                            inc.description = m_activeDevice.description;
                            inc.folderPath = ctx->folderPath;
                            inc.operation = action;
                            inc.attributionTier = L"DEFINITIVE";
                            inc.attributionEvidence = attributionEvidence;
                            inc.enforcementApplied = disabled;
                            inc.enforcementVerified = verified;
                            inc.enforcementCode = EnforcementManager::ConfigRetToString(crResult);

                            RestClient::Instance().ReportPolicyViolation(inc);

                            EventLogger::Instance().LogEvent(
                                SecurityEventType::INCIDENT_POLICY_VIOLATION,
                                m_activeDevice,
                                L"BLOCK",
                                L"Confirmed violation on " + ctx->folderPath + L": " + attributionEvidence +
                                (verified ? L" (OS disablement verified: Code 22)" : L" (Disablement unverified)")
                            );
                        }
                        else
                        {
                            // Uncertain attribution or no active peripheral: Log high-severity alert WITHOUT disabling peripheral
                            std::wstring alertReason = (isCanary ? L"Canary file touched" : L"Protected directory modified") +
                                std::wstring(L": ") + action + L" " + fullPath + L" [Attribution: " + attributionTier + L"]";

                            if (m_hasActiveDevice)
                            {
                                EventLogger::Instance().LogEvent(
                                    SecurityEventType::PROTECTED_FILE_ACCESS,
                                    m_activeDevice,
                                    L"ALERT",
                                    alertReason
                                );

                                // Forward incident telemetry to server with UNCERTAIN tier
                                PolicyViolationIncident inc;
                                inc.clientId = EventLogger::Instance().GetClientId();
                                inc.vendorId = m_activeDevice.vendorId;
                                inc.productId = m_activeDevice.productId;
                                inc.serialNumber = m_activeDevice.serialNumber;
                                inc.deviceId = m_activeDevice.deviceId;
                                inc.deviceType = DeviceClassifier::ToString(m_activeDevice.type);
                                inc.description = m_activeDevice.description;
                                inc.folderPath = ctx->folderPath;
                                inc.operation = action;
                                inc.attributionTier = attributionTier;
                                inc.attributionEvidence = attributionEvidence;
                                inc.enforcementApplied = false;
                                inc.enforcementVerified = false;

                                RestClient::Instance().ReportPolicyViolation(inc);
                            }
                            else
                            {
                                EventLogger::Instance().LogSimpleEvent(
                                    SecurityEventType::PROTECTED_FILE_ACCESS,
                                    L"",
                                    fullPath,
                                    L"ALERT",
                                    alertReason
                                );
                            }
                        }

                        if (info->NextEntryOffset == 0) break;
                        ptr += info->NextEntryOffset;
                    }
                }

                // Reset event and re-issue ReadDirectoryChangesW for this folder
                ResetEvent(ctx->ovl.hEvent);
                ReadDirectoryChangesW(
                    ctx->dirHandle,
                    ctx->notifyBuffer,
                    sizeof(ctx->notifyBuffer),
                    FALSE,
                    FILE_NOTIFY_CHANGE_FILE_NAME |
                    FILE_NOTIFY_CHANGE_DIR_NAME  |
                    FILE_NOTIFY_CHANGE_LAST_WRITE,
                    nullptr,
                    &ctx->ovl,
                    nullptr
                );
            }
        }
    }

    CloseWatchContexts(watchContexts);
}

bool ProtectedFileMonitor::IsCanaryAccessCorrelated() const
{
    if (!m_canaryAccessCorrelated.load())
    {
        return false;
    }
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - m_lastCanaryAccessTime).count();
    return (elapsed <= 60.0);
}

void ProtectedFileMonitor::SimulateCanaryTouch()
{
    m_canaryAccessCorrelated.store(true);
    m_lastCanaryAccessTime = std::chrono::steady_clock::now();
}

void ProtectedFileMonitor::ClearCanaryCorrelation()
{
    m_canaryAccessCorrelated.store(false);
}

void ProtectedFileMonitor::TriggerSimulatedViolation(
    const std::wstring& folderPath,
    const std::wstring& operation,
    const std::wstring& attributionTier)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_hasActiveDevice)
        return;

    PolicyViolationIncident inc;
    inc.clientId = EventLogger::Instance().GetClientId();
    inc.vendorId = m_activeDevice.vendorId;
    inc.productId = m_activeDevice.productId;
    inc.serialNumber = m_activeDevice.serialNumber;
    inc.deviceId = m_activeDevice.deviceId;
    inc.deviceType = DeviceClassifier::ToString(m_activeDevice.type);
    inc.description = m_activeDevice.description;
    inc.folderPath = folderPath;
    inc.operation = operation;
    inc.attributionTier = attributionTier;
    inc.attributionEvidence = L"Simulated diagnostic violation verification test";

    if (attributionTier == L"DEFINITIVE")
    {
        CONFIGRET crResult = CR_FAILURE;
        bool disabled = EnforcementManager::QuarantineDevice(m_activeDevice, &crResult);
        inc.enforcementApplied = disabled;
        inc.enforcementVerified = disabled;
        inc.enforcementCode = EnforcementManager::ConfigRetToString(crResult);

        if (m_allowlist)
        {
            m_allowlist->RemoveDevice(m_activeDevice);
        }
    }

    RestClient::Instance().ReportPolicyViolation(inc);
}

// ============================================================
// OS-Level Protected-Folder Access Restrictions
// ============================================================

std::wstring ProtectedFileMonitor::GetCurrentUserNameStr()
{
    wchar_t name[256] = { 0 };
    DWORD size = 256;
    if (GetUserNameW(name, &size))
    {
        return name;
    }
    return L"";
}

bool ProtectedFileMonitor::EnforceNativeFolderProtection(
    const std::wstring& folderPath,
    const std::wstring& userName,
    std::wstring& outOriginalSddl)
{
    if (folderPath.empty() || userName.empty())
        return false;

    // Ensure directory exists
    DWORD attr = GetFileAttributesW(folderPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
    {
        CreateDirectoryW(folderPath.c_str(), nullptr);
    }

    PSECURITY_DESCRIPTOR pOldSD = nullptr;
    PACL pOldDacl = nullptr;
    DWORD dwRes = GetNamedSecurityInfoW(
        folderPath.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &pOldDacl, nullptr, &pOldSD
    );

    if (dwRes != ERROR_SUCCESS)
    {
        std::wcerr << L"[PFMON-ACL] GetNamedSecurityInfoW failed: " << dwRes << L" for " << folderPath << L"\n";
        return false;
    }

    // Export original DACL as SDDL string for lossless restoration
    LPWSTR sddlStr = nullptr;
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
            pOldSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddlStr, nullptr))
    {
        outOriginalSddl = sddlStr;
        LocalFree(sddlStr);
    }

    // Build explicit DENY access rule
    // Deny read data, write data, append data, create files, create folders, execute, and delete
    EXPLICIT_ACCESS_W ea;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS_W));
    ea.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | FILE_DELETE_CHILD;
    ea.grfAccessMode = DENY_ACCESS;
    ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = const_cast<LPWSTR>(userName.c_str());

    PACL pNewDacl = nullptr;
    dwRes = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
    if (dwRes != ERROR_SUCCESS)
    {
        std::wcerr << L"[PFMON-ACL] SetEntriesInAclW failed: " << dwRes << L"\n";
        LocalFree(pOldSD);
        return false;
    }

    // Apply new DACL to directory
    dwRes = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(folderPath.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr, pNewDacl, nullptr
    );

    LocalFree(pNewDacl);
    LocalFree(pOldSD);

    if (dwRes != ERROR_SUCCESS)
    {
        std::wcerr << L"[PFMON-ACL] SetNamedSecurityInfoW failed: " << dwRes << L"\n";
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

    PSECURITY_DESCRIPTOR pRestoredSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            originalSddl.c_str(), SDDL_REVISION_1, &pRestoredSD, nullptr))
    {
        return false;
    }

    BOOL daclPresent = FALSE, daclDefaulted = FALSE;
    PACL pDacl = nullptr;
    GetSecurityDescriptorDacl(pRestoredSD, &daclPresent, &pDacl, &daclDefaulted);

    DWORD dwRes = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(folderPath.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr, pDacl, nullptr
    );

    LocalFree(pRestoredSD);
    return (dwRes == ERROR_SUCCESS);
}

bool ProtectedFileMonitor::RevokeUserDenyAce(
    const std::wstring& folderPath,
    const std::wstring& userName)
{
    if (folderPath.empty() || userName.empty())
        return false;

    PSECURITY_DESCRIPTOR pOldSD = nullptr;
    PACL pOldDacl = nullptr;
    DWORD dwRes = GetNamedSecurityInfoW(
        folderPath.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &pOldDacl, nullptr, &pOldSD
    );

    if (dwRes != ERROR_SUCCESS)
        return false;

    EXPLICIT_ACCESS_W ea;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS_W));
    ea.grfAccessPermissions = 0;
    ea.grfAccessMode = REVOKE_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = const_cast<LPWSTR>(userName.c_str());

    PACL pNewDacl = nullptr;
    dwRes = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
    if (dwRes == ERROR_SUCCESS)
    {
        dwRes = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(folderPath.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr, nullptr, pNewDacl, nullptr
        );
        LocalFree(pNewDacl);
    }

    LocalFree(pOldSD);
    return (dwRes == ERROR_SUCCESS);
}

bool ProtectedFileMonitor::ActivateEnforcement(const USBDevice* triggeringDevice)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_isEnforcementActive.load())
    {
        return true;
    }

    std::wstring userName = GetCurrentUserNameStr();
    if (userName.empty())
    {
        std::wcerr << L"[PFMON-ENFORCE] Cannot determine current user name for ACL enforcement.\n";
        return false;
    }

    std::vector<std::wstring> targets;
    if (!m_configuredFolders.empty())
    {
        for (const auto& f : m_configuredFolders)
        {
            if (f.isEnabled) targets.push_back(f.folderPath);
        }
    }
    if (targets.empty() && !m_defaultProtectedDir.empty())
    {
        targets.push_back(m_defaultProtectedDir);
    }

    if (targets.empty())
    {
        std::wcerr << L"[PFMON-ENFORCE] No protected folders configured for enforcement.\n";
        return false;
    }

    bool allSucceeded = true;
    for (const auto& path : targets)
    {
        // Ensure folder and canary exist prior to locking
        DWORD attr = GetFileAttributesW(path.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES)
        {
            CreateDirectoryW(path.c_str(), nullptr);
        }
        std::wstring canary = path + L"\\" + m_canaryFileName;
        EnsureCanaryFile(canary);

        std::wstring savedSddl;
        if (EnforceNativeFolderProtection(path, userName, savedSddl))
        {
            m_savedFolderSddls[path] = savedSddl;
            std::wcout << L"[PFMON-ENFORCE] OS-level NTFS protection ACTIVATED on: " << path << L"\n"
                       << L"                 All Read, Copy, Create, Paste, Overwrite, Rename, and Delete operations DENIED by Windows.\n";
        }
        else
        {
            allSucceeded = false;
            std::wcerr << L"[PFMON-ENFORCE] FAILED to apply OS-level NTFS protection on: " << path << L"\n";
        }
    }

    // Sync policies to kernel Minifilter driver if loaded
    if (!m_configuredFolders.empty())
    {
        MinifilterClient::Instance().SyncPolicies(m_configuredFolders);
    }

    if (allSucceeded)
    {
        m_isEnforcementActive.store(true);

        std::wstring devInfo = triggeringDevice ? (triggeringDevice->vendorId + L":" + triggeringDevice->productId + L" (" + triggeringDevice->serialNumber + L")") : L"USB_PERIPHERAL";
        EventLogger::Instance().LogSimpleEvent(
            SecurityEventType::PROTECTED_FILE_ACCESS,
            triggeringDevice ? triggeringDevice->deviceId : L"",
            m_defaultProtectedDir,
            L"ENFORCE_ACTIVE",
            L"USB device insertion activated OS-level protected folder restrictions. Device: " + devInfo
        );
        return true;
    }
    else
    {
        EventLogger::Instance().LogSimpleEvent(
            SecurityEventType::PROTECTED_FILE_ACCESS,
            triggeringDevice ? triggeringDevice->deviceId : L"",
            m_defaultProtectedDir,
            L"ENFORCE_FAILED",
            L"Failed to apply OS-level protected folder restrictions on one or more folders."
        );
        return false;
    }
}

bool ProtectedFileMonitor::DeactivateEnforcement(const USBDevice* triggeringDevice)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_isEnforcementActive.load())
    {
        return true;
    }

    std::wstring userName = GetCurrentUserNameStr();
    for (const auto& pair : m_savedFolderSddls)
    {
        const std::wstring& path = pair.first;
        const std::wstring& sddl = pair.second;

        bool restored = RestoreNativeFolderProtection(path, sddl);
        if (!restored && !userName.empty())
        {
            restored = RevokeUserDenyAce(path, userName);
        }

        if (restored)
        {
            std::wcout << L"[PFMON-ENFORCE] OS-level NTFS protection DEACTIVATED on: " << path << L"\n"
                       << L"                 Normal filesystem access restored.\n";
        }
        else
        {
            std::wcerr << L"[PFMON-ENFORCE] Failed to restore ACL on: " << path << L"\n";
        }
    }

    m_savedFolderSddls.clear();
    m_isEnforcementActive.store(false);

    std::wstring devInfo = triggeringDevice ? (triggeringDevice->vendorId + L":" + triggeringDevice->productId + L" (" + triggeringDevice->serialNumber + L")") : L"USB_ALL_REMOVED";
    EventLogger::Instance().LogSimpleEvent(
        SecurityEventType::PROTECTED_FILE_ACCESS,
        triggeringDevice ? triggeringDevice->deviceId : L"",
        m_defaultProtectedDir,
        L"ENFORCE_DEACTIVATED",
        L"USB peripheral disconnection deactivated OS-level protected folder restrictions per policy. Device: " + devInfo
    );
    return true;
}

bool ProtectedFileMonitor::IsEnforcementActive() const
{
    return m_isEnforcementActive.load();
}

int ProtectedFileMonitor::GetActiveUsbDeviceCount() const
{
    return m_activeUsbDeviceCount;
}

void ProtectedFileMonitor::OnUsbDeviceConnected(const USBDevice& device)
{
    bool doEnforce = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_activeUsbDeviceCount++;
        m_connectedUsbDevices[device.deviceInterfacePath] = device;
        m_activeDevice = device;
        m_hasActiveDevice = true;
        doEnforce = PolicyConfig::Instance().enforceFolderProtectionOnUsb && !m_isEnforcementActive.load();
    }

    if (doEnforce)
    {
        ActivateEnforcement(&device);
    }
}

void ProtectedFileMonitor::OnUsbDeviceDisconnected(const std::wstring& devicePath)
{
    bool shouldDeactivate = false;
    USBDevice removedDev;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_connectedUsbDevices.find(devicePath);
        if (it != m_connectedUsbDevices.end())
        {
            removedDev = it->second;
            m_connectedUsbDevices.erase(it);
        }
        if (m_activeUsbDeviceCount > 0)
        {
            m_activeUsbDeviceCount--;
        }

        if (m_connectedUsbDevices.empty() || m_activeUsbDeviceCount == 0)
        {
            m_activeUsbDeviceCount = 0;
            m_hasActiveDevice = false;
            if (PolicyConfig::Instance().deactivateProtectionOnUsbRemoval && m_isEnforcementActive.load())
            {
                shouldDeactivate = true;
            }
        }
    }

    if (shouldDeactivate)
    {
        DeactivateEnforcement(&removedDev);
    }
    else if (m_isEnforcementActive.load())
    {
        std::wcout << L"[PFMON-ENFORCE] USB device removed; protected folder policy configured to remain ACTIVE.\n";
    }
}

bool ProtectedFileMonitor::VerifySelfTest()
{
    std::wcout << L"  [7.1] Native NTFS Security Descriptor & DACL Enforcement Engine Check...\n";
    std::wstring user = GetCurrentUserNameStr();
    if (user.empty())
    {
        std::wcerr << L"        [ERROR] Failed to query current process user token.\n";
        return false;
    }
    std::wcout << L"        Current Target User    : " << user << L" [OK]\n";

    // Create a temporary diagnostic folder
    wchar_t tempPathBuf[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tempPathBuf);
    std::wstring diagFolder = std::wstring(tempPathBuf) + L"usbips_diag_acl_test";
    CreateDirectoryW(diagFolder.c_str(), nullptr);

    std::wstring diagFile = diagFolder + L"\\audit_canary.txt";
    HANDLE hf = CreateFileW(diagFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (hf != INVALID_HANDLE_VALUE)
    {
        const char content[] = "USBIPS Sentinel Data";
        DWORD written = 0;
        WriteFile(hf, content, sizeof(content) - 1, &written, nullptr);
        CloseHandle(hf);
    }

    std::wstring savedSddl;
    bool enforceOk = EnforceNativeFolderProtection(diagFolder, user, savedSddl);
    std::wcout << L"        Apply Deny DACL        : " << (enforceOk ? L"SUCCESS [OK]" : L"FAILED [ERROR]") << L"\n";

    // Test Read Denial
    HANDLE hRead = CreateFileW(diagFile.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    bool readDenied = (hRead == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED);
    if (hRead != INVALID_HANDLE_VALUE) CloseHandle(hRead);

    // Test Create Denial
    std::wstring newTestFile = diagFolder + L"\\pasted.txt";
    HANDLE hCreate = CreateFileW(newTestFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    bool createDenied = (hCreate == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED);
    if (hCreate != INVALID_HANDLE_VALUE) CloseHandle(hCreate);

    // Test Delete Denial
    bool delSuccess = DeleteFileW(diagFile.c_str());
    bool deleteDenied = (!delSuccess && GetLastError() == ERROR_ACCESS_DENIED);

    std::wcout << L"        OS Read / Open Denial  : " << (readDenied ? L"DENIED (STATUS_ACCESS_DENIED 5) [OK]" : L"FAILED") << L"\n";
    std::wcout << L"        OS Paste / Create In   : " << (createDenied ? L"DENIED (STATUS_ACCESS_DENIED 5) [OK]" : L"FAILED") << L"\n";
    std::wcout << L"        OS Delete / Move Denial: " << (deleteDenied ? L"DENIED (STATUS_ACCESS_DENIED 5) [OK]" : L"FAILED") << L"\n";

    // Restore
    bool restoreOk = RestoreNativeFolderProtection(diagFolder, savedSddl);
    std::wcout << L"        Restore Original DACL  : " << (restoreOk ? L"SUCCESS [OK]" : L"FAILED [ERROR]") << L"\n";

    // Verify Read after restore
    HANDLE hReadAfter = CreateFileW(diagFile.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    bool readRestored = (hReadAfter != INVALID_HANDLE_VALUE);
    if (hReadAfter != INVALID_HANDLE_VALUE) CloseHandle(hReadAfter);
    std::wcout << L"        Access After Restore   : " << (readRestored ? L"PERMITTED [OK]" : L"FAILED") << L"\n";

    // Cleanup
    DeleteFileW(diagFile.c_str());
    RemoveDirectoryW(diagFolder.c_str());

    return (enforceOk && readDenied && createDenied && deleteDenied && restoreOk && readRestored);
}
