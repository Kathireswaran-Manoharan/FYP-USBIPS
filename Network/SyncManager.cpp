#include "SyncManager.h"

#include <iostream>

SyncManager& SyncManager::Instance()
{
    static SyncManager instance;
    return instance;
}

SyncManager::SyncManager()
    : m_allowlist(nullptr)
    , m_intervalSeconds(15)
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
            std::wstring osVersion = GetSystemOsVersion();
            if (RestClient::Instance().RegisterClient(clientId, hostname, osVersion, L"1.0.0"))
            {
                m_clientRegistered.store(true);
                std::wcout << L"[SYNC] Client successfully registered with Central Server. Client ID: "
                           << clientId << L"\n";
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
            }
        }

        // 4. Batch Upload Pending Events
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
