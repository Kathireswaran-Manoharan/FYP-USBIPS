#pragma once

// MinifilterClient.h
// User-Mode Communication Interface for USBIPSFilter Minifilter Driver
// Module: Scenario 3 Protected-File Pre-Access Denial

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>

#include "ProtectedFolderPolicy.h"
#include "../Minifilter/USBIPSFilter.h"

class MinifilterClient
{
public:
    static MinifilterClient& Instance()
    {
        static MinifilterClient instance;
        return instance;
    }

    // Connects to the kernel minifilter communication port
    bool Connect();

    // Disconnects from port
    void Disconnect();

    // Returns true if kernel driver port is connected and active
    bool IsConnected() const;

    // Synchronizes current active protected folder policies with the kernel driver
    bool SyncPolicies(const std::vector<ProtectedFolder>& folders);

    // Self-test diagnostic check for Scenario 3
    bool VerifySelfTest();

private:
    MinifilterClient();
    ~MinifilterClient();
    MinifilterClient(const MinifilterClient&) = delete;
    MinifilterClient& operator=(const MinifilterClient&) = delete;

    void StartListener();
    void StopListener();
    void ListenerLoop();

    HANDLE m_hPort = INVALID_HANDLE_VALUE;
    bool   m_connected = false;
    std::atomic<bool> m_listening{ false };
    std::thread m_listenerThread;
    mutable std::mutex m_mutex;
};
