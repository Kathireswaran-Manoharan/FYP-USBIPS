#include <winsock2.h>
#include <ws2tcpip.h>

#include "SyncManager.h"
#include "../Enforcement/EnforcementManager.h"
#include "../Presence/DevicePresenceMonitor.h"
#include "../AccessControl/PolicyConfig.h"
#include "../AccessControl/ProtectedFileMonitor.h"
#include "../AccessControl/StorageExecutionMonitor.h"
#include "../AccessControl/TrustAssessmentEngine.h"

#include <iostream>

#pragma comment(lib, "ws2_32.lib")

SyncManager& SyncManager::Instance()
{
    static SyncManager instance;
    return instance;
}

SyncManager::SyncManager()
    : m_allowlist(nullptr)
    , m_intervalSeconds(5)
    , m_running(false)
    , m_serverConnected(false)
    , m_clientRegistered(false)
{
}

SyncManager::~SyncManager()
{
    Stop();
}

std::wstring SyncManager::GetSystemHostname()
{
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(buffer, &size))
    {
        return std::wstring(buffer, size);
    }
    return L"Windows-Host";
}

std::wstring SyncManager::GetSystemIpAddress()
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        return L"UNAVAILABLE";
    }

    char hostname[256] = { 0 };
    if (gethostname(hostname, sizeof(hostname)) == 0)
    {
        struct addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo(hostname, nullptr, &hints, &res) == 0 && res != nullptr)
        {
            char ipStr[INET_ADDRSTRLEN] = { 0 };
            struct sockaddr_in* ipv4 = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);
            inet_ntop(AF_INET, &(ipv4->sin_addr), ipStr, sizeof(ipStr));
            freeaddrinfo(res);
            WSACleanup();

            if (strlen(ipStr) > 0)
            {
                return RestClient::Utf8ToWide(ipStr);
            }
        }
    }

    WSACleanup();
    return L"UNAVAILABLE";
}

std::wstring SyncManager::GetSystemOsVersion()
{
    return L"Windows 10/11 x64";
}

bool SyncManager::Start(
    AllowlistManager* allowlist,
    const std::wstring& host,
    int port,
    int intervalSeconds)
{
    if (m_running.load())
    {
        return true;
    }

    m_allowlist = allowlist;
    m_intervalSeconds = intervalSeconds > 0 ? intervalSeconds : 15;


    RestClient::Instance().Configure(host, port);

    m_running.store(true);
    m_workerThread = std::thread(&SyncManager::WorkerLoop, this);

    std::wcout << L"[OK] Background Sync Engine initialized (Host: "
               << host << L":" << port << L", Interval: "
               << m_intervalSeconds << L"s)\n";

    return true;
}

void SyncManager::Stop()
{
    if (!m_running.load())
    {
        return;
    }

    m_running.store(false);
    m_cv.notify_all();

    // Gracefully inform central server that client is disconnecting
    if (m_serverConnected.load())
    {
        std::wstring clientId = EventLogger::Instance().GetClientId();
        RestClient::Instance().SendHeartbeat(clientId, L"OFFLINE");
    }

    if (m_workerThread.joinable())
    {
        m_workerThread.join();
    }

    std::wcout << L"[SYNC] Background Sync Engine stopped.\n";
}

void SyncManager::TriggerImmediateSync()
{
    m_cv.notify_all();
}

bool SyncManager::IsServerConnected() const
{
    return m_serverConnected.load();
}

bool SyncManager::PerformSyncCycle()
{
    std::wstring clientId = EventLogger::Instance().GetClientId();
    bool isOnline = RestClient::Instance().IsServerOnline();

    if (isOnline)
    {
        if (!m_serverConnected.load())
        {
            std::wcout << L"\n[SYNC] Central Management Server is ONLINE. Synchronizing...\n";
            m_serverConnected.store(true);
        }

        // 1. Client Registration
        if (!m_clientRegistered.load())
        {
            std::wstring hostname = GetSystemHostname();
            std::wstring ipAddress = GetSystemIpAddress();
            std::wstring osVersion = GetSystemOsVersion();
            if (RestClient::Instance().RegisterClient(clientId, hostname, ipAddress, osVersion, L"1.0.0"))
            {
                m_clientRegistered.store(true);
                std::wcout << L"[SYNC] Client successfully registered with Central Server.\n"
                           << L"       Client ID   : " << clientId << L"\n"
                           << L"       Hostname    : " << hostname << L"\n"
                           << L"       IP Address  : " << ipAddress << L"\n"
                           << L"       OS Version  : " << osVersion << L"\n";
            }
        }

        // 2. Heartbeat
        RestClient::Instance().SendHeartbeat(clientId, L"ONLINE");

        // 3. Allowlist Synchronization
        if (m_allowlist)
        {
            std::vector<AllowedDevice> remoteDevices;
            if (RestClient::Instance().FetchMasterAllowlist(remoteDevices))
            {
                m_allowlist->SyncWithRemote(remoteDevices);

                // Check all currently active/connected devices to enforce real-time revocation
                auto tracked = DevicePresenceMonitor::GetTrackedDevices();
                for (const auto& item : tracked)
                {
                    if (item.state == DeviceTrackingState::RELEASED)
                    {
                        if (!m_allowlist->IsAllowed(item.device))
                        {
                            std::wcout << L"\n=======================================================\n";
                            std::wcout << L"[SECURITY ALERT] Device " << item.device.vendorId
                                       << L":" << item.device.productId
                                       << L" (Serial: " << item.device.serialNumber
                                       << L") was REVOKED by Central Server!\n";
                            std::wcout << L"[SECURITY] Disabling physical peripheral internally via CM_Disable_DevNode...\n";

                            CONFIGRET crResult = CR_FAILURE;
                            bool disabled = EnforcementManager::QuarantineDevice(item.device, &crResult);
                            if (disabled)
                            {
                                DevicePresenceMonitor::SetDeviceState(item.deviceId, DeviceTrackingState::QUARANTINED);
                                std::wcout << L"[OK] Revocation enforced. Peripheral is now DISABLED at OS level.\n";
                                std::wcout << L"=======================================================\n";

                                EventLogger::Instance().LogEvent(
                                    SecurityEventType::DEVICE_BLOCKED,
                                    item.device,
                                    L"BLOCK",
                                    L"Central server revoked authorization; physical peripheral disabled in real-time"
                                );
                            }
                            else
                            {
                                std::wcerr << L"[ERROR] Failed to disable revoked device at OS level ("
                                           << EnforcementManager::ConfigRetToString(crResult) << L").\n";
                                std::wcout << L"=======================================================\n";

                                EventLogger::Instance().LogEvent(
                                    SecurityEventType::DEVICE_BLOCKED,
                                    item.device,
                                    L"BLOCK",
                                    L"Central server revoked authorization; OS disablement failed (" +
                                    std::wstring(EnforcementManager::ConfigRetToString(crResult)) +
                                    L"); locked by policy"
                                );
                            }
                        }
                    }
                    else if (item.state == DeviceTrackingState::QUARANTINED)
                    {
                        // Requirement 4: Automatic allowlist refresh cannot reauthorize a device after a confirmed critical threat
                        if (m_allowlist->HasActiveCriticalThreat(item.device))
                        {
                            continue;
                        }

                        if (m_allowlist->IsAllowed(item.device))
                        {
                            std::wcout << L"\n=======================================================\n";
                            std::wcout << L"[SECURITY] Device " << item.device.vendorId
                                       << L":" << item.device.productId
                                       << L" (Serial: " << item.device.serialNumber
                                       << L") was APPROVED by Central Server!\n";
                            std::wcout << L"[SECURITY] Enabling physical peripheral via CM_Enable_DevNode...\n";

                            CONFIGRET crResult = CR_FAILURE;
                            bool released = EnforcementManager::ReleaseDevice(item.device, &crResult);
                            if (released)
                            {
                                if (!item.device.hasStorage)
                                {
                                    DevicePresenceMonitor::SetDeviceState(item.deviceId, DeviceTrackingState::RELEASED);
                                    std::wcout << L"[OK] Authorization enforced. Peripheral is now ENABLED at OS level.\n";
                                    std::wcout << L"=======================================================\n";

                                    EventLogger::Instance().LogEvent(
                                        SecurityEventType::DEVICE_RELEASED,
                                        item.device,
                                        L"ALLOW",
                                        L"Central server approved authorization; physical peripheral enabled in real-time"
                                    );

                                }
                                else
                                {
                                    // Storage device must undergo pre-release executable inspection
                                    std::wcout << L"[SECURITY] Storage device approved by Central Server; performing pre-release executable inspection...\n";
                                    bool storageClean = InspectStorageMedia(item.device, 2000);

                                    TrustAssessmentReport postReport;
                                    TrustAssessmentEngine::Instance().GetActiveAssessment(item.deviceId, postReport);

                                    bool isThreat = (postReport.executablePolicyStatus == L"BLOCKED" ||
                                                     postReport.malwareScanResult == L"INFECTED" ||
                                                     postReport.recommendation == TrustRecommendation::REJECT);

                                    if (storageClean && !isThreat)
                                    {
                                        DevicePresenceMonitor::SetDeviceState(item.deviceId, DeviceTrackingState::RELEASED);
                                        std::wcout << L"[OK] Storage inspection CLEAN. Device is now RELEASED at OS level.\n";
                                        std::wcout << L"=======================================================\n";

                                        EventLogger::Instance().LogEvent(
                                            SecurityEventType::DEVICE_RELEASED,
                                            item.device,
                                            L"ALLOW",
                                            L"Central server approved authorization; storage inspection clean, released at OS level"
                                        );

                                        RestClient::Instance().CheckOrRequestDevice(EventLogger::Instance().GetClientId(), item.device, &postReport);
                                    }
                                    else if (isThreat)
                                    {
                                        std::wcerr << L"[SECURITY] Critical threat detected during pre-release inspection of approved device! Revoking and quarantining.\n";
                                        std::vector<std::wstring> reasons = postReport.explainableReasons;
                                        if (!postReport.exactThreatEvidence.empty())
                                        {
                                            reasons.push_back(postReport.exactThreatEvidence);
                                        }

                                        EnforcementManager::EnforceCriticalThreat(
                                            item.device,
                                            postReport.executablePolicyStatus == L"BLOCKED" ? L"STORAGE_EXECUTION_BLOCKED" : L"MALWARE_DETECTED",
                                            postReport.exactThreatEvidence,
                                            postReport.totalRiskScore,
                                            reasons,
                                            m_allowlist
                                        );

                                        CONFIGRET qCr = CR_FAILURE;
                                        EnforcementManager::QuarantineDevice(item.device, &qCr);
                                        DevicePresenceMonitor::SetDeviceState(item.deviceId, DeviceTrackingState::QUARANTINED);
                                        std::wcout << L"=======================================================\n";

                                        RestClient::Instance().CheckOrRequestDevice(EventLogger::Instance().GetClientId(), item.device, &postReport);
                                    }
                                    else
                                    {
                                        // Volume not yet mounted or inspection pending
                                        std::wcout << L"[SECURITY] Storage volume pending mount. Keeping device restricted.\n";
                                        std::wcout << L"[SECURITY] Registering bounded retry mechanism...\n";
                                        std::wcout << L"=======================================================\n";

                                        CONFIGRET qCr = CR_FAILURE;
                                        EnforcementManager::QuarantineDevice(item.device, &qCr);
                                        DevicePresenceMonitor::SetDeviceState(item.deviceId, DeviceTrackingState::QUARANTINED);
                                        PendingStorageInspectionManager::Instance().RegisterPendingDevice(item.device);

                                        RestClient::Instance().CheckOrRequestDevice(EventLogger::Instance().GetClientId(), item.device, &postReport);
                                    }
                                }
                            }
                            else
                            {
                                std::wcerr << L"[ERROR] Failed to enable approved device at OS level ("
                                           << EnforcementManager::ConfigRetToString(crResult) << L").\n";
                                std::wcout << L"=======================================================\n";

                                EventLogger::Instance().LogEvent(
                                    SecurityEventType::DEVICE_BLOCKED,
                                    item.device,
                                    L"BLOCK",
                                    L"Central server approved device, but OS enablement failed (" +
                                    std::wstring(EnforcementManager::ConfigRetToString(crResult)) +
                                    L"); check elevation"
                                );
                            }
                        }
                    }
                }
            }
        }

        // 4. Central Policy Synchronization
        PolicyConfig remotePolicy;
        if (RestClient::Instance().FetchPolicyConfig(remotePolicy))
        {
            PolicyConfig::Instance() = remotePolicy;
        }

        // 4b. Protected Folder Policies Synchronization
        std::vector<ProtectedFolder> remoteFolders;
        if (RestClient::Instance().FetchProtectedFolderPolicies(remoteFolders))
        {
            ProtectedFileMonitor::Instance().UpdateProtectedFolders(remoteFolders);
        }

        // 5. Periodic storage execution surveillance
        if (PolicyConfig::Instance().blockStorageExecution)
        {
            StorageExecutionMonitor::Instance().ScanRunningProcesses(
                PolicyConfig::Instance().autoTerminateStorageProcesses
            );
        }

        // 6. Batch Upload Pending Events
        auto pendingEvents = EventLogger::Instance().GetPendingSyncEvents(100);
        if (!pendingEvents.empty())
        {
            int ingestedCount = 0;
            if (RestClient::Instance().UploadEventsBatch(pendingEvents, ingestedCount))
            {
                std::vector<std::wstring> syncedIds;
                syncedIds.reserve(pendingEvents.size());
                for (const auto& evt : pendingEvents)
                {
                    syncedIds.push_back(evt.eventId);
                }
                EventLogger::Instance().MarkEventsSynced(syncedIds);
            }
        }

        return true;
    }
    else
    {
        if (m_serverConnected.load())
        {
            std::wcout << L"\n[SYNC] Central Server is UNREACHABLE. Continuing in local zero-trust mode.\n";
            m_serverConnected.store(false);
            m_clientRegistered.store(false);
        }
        return false;
    }
}

void SyncManager::WorkerLoop()
{
    // Initial sync immediately upon starting
    PerformSyncCycle();

    while (m_running.load())
    {
        std::unique_lock<std::mutex> lock(m_cvMutex);
        m_cv.wait_for(lock, std::chrono::seconds(m_intervalSeconds), [this]() {
            return !m_running.load();
        });

        if (!m_running.load())
        {
            break;
        }

        PerformSyncCycle();
    }
}
