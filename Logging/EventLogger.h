#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <mutex>

#include "../Models/USBDevice.h"
#include "../Models/SecurityEvent.h"
#include "../ThirdParty/SQLite/sqlite3.h"

class EventLogger
{
public:
    static EventLogger& Instance();

    bool Initialize(const std::wstring& databasePath = L"usbips.db");
    void Close();

    bool LogEvent(
        SecurityEventType type,
        const USBDevice& device,
        const std::wstring& decision,
        const std::wstring& reason
    );

    bool LogSimpleEvent(
        SecurityEventType type,
        const std::wstring& deviceId,
        const std::wstring& devicePath,
        const std::wstring& decision,
        const std::wstring& reason,
        const std::wstring& vendorId = L"",
        const std::wstring& productId = L"",
        const std::wstring& serialNumber = L"",
        const std::wstring& deviceType = L"",
        const std::wstring& description = L""
    );

    std::vector<SecurityEvent> GetRecentEvents(int limit = 50);
    std::vector<SecurityEvent> GetPendingSyncEvents(int limit = 100);
    bool MarkEventsSynced(const std::vector<std::wstring>& eventIds);

    std::wstring GetClientId() const;

private:
    EventLogger();
    ~EventLogger();

    EventLogger(const EventLogger&) = delete;
    EventLogger& operator=(const EventLogger&) = delete;

    bool CreateTables();
    std::wstring ResolveClientId();
    std::wstring GenerateEventId();
    std::wstring GetCurrentUtcTimestamp();

    bool InsertEventRecord(const SecurityEvent& evt);

private:
    sqlite3* m_db;
    std::wstring m_clientId;
    std::mutex m_mutex;
    bool m_initialized;
};
