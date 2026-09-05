#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>

#include "RestClient.h"
#include "../Allowlist/AllowlistManager.h"
#include "../Logging/EventLogger.h"

class SyncManager
{
public:
    static SyncManager& Instance();

    bool Start(
        AllowlistManager* allowlist,
        const std::wstring& host = L"127.0.0.1",
        int port = 8000,
        int intervalSeconds = 15
    );

    void Stop();

    void TriggerImmediateSync();

    bool IsServerConnected() const;

    bool PerformSyncCycle();

private:
    SyncManager();
    ~SyncManager();

    SyncManager(const SyncManager&) = delete;
    SyncManager& operator=(const SyncManager&) = delete;

    void WorkerLoop();
    std::wstring GetSystemHostname();
    std::wstring GetSystemOsVersion();

    AllowlistManager* m_allowlist;
    int m_intervalSeconds;

    std::atomic<bool> m_running;
    std::atomic<bool> m_serverConnected;
    std::atomic<bool> m_clientRegistered;

    std::thread m_workerThread;
    std::mutex m_cvMutex;
    std::condition_variable m_cv;
};
