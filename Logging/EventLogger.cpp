#include "EventLogger.h"
#include "../Classifier/DeviceClassifier.h"

#include <iostream>
#include <iomanip>
#include <objbase.h>

EventLogger& EventLogger::Instance()
{
    static EventLogger instance;
    return instance;
}

EventLogger::EventLogger()
    : m_db(nullptr)
    , m_initialized(false)
{
}

EventLogger::~EventLogger()
{
    Close();
}

bool EventLogger::Initialize(const std::wstring& databasePath)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_initialized)
    {
        return true;
    }

    int result = sqlite3_open16(databasePath.c_str(), &m_db);
    if (result != SQLITE_OK)
    {
        std::wcerr << L"[ERROR] EventLogger could not open database: " << databasePath << L"\n";
        return false;
    }

    if (!CreateTables())
    {
        std::wcerr << L"[ERROR] EventLogger failed to create event tables.\n";
        return false;
    }

    m_clientId = ResolveClientId();
    m_initialized = true;

    std::wcout << L"[OK] EventLogger initialized. Client ID: " << m_clientId << L"\n";
    return true;
}

void EventLogger::Close()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_db)
    {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
    m_initialized = false;
}

bool EventLogger::CreateTables()
{
    const char* sql = R"SQL(
        CREATE TABLE IF NOT EXISTS security_events (
            event_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            vendor_id TEXT,
            product_id TEXT,
            serial_number TEXT,
            device_id TEXT,
            device_type TEXT,
            description TEXT,
            decision TEXT,
            reason TEXT,
            sync_status TEXT DEFAULT 'PENDING'
        );

        CREATE INDEX IF NOT EXISTS idx_events_sync ON security_events(sync_status);
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);

        CREATE TABLE IF NOT EXISTS client_metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    )SQL";

    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK)
    {
        if (errMsg)
        {
            std::cerr << "[ERROR] SQLite EventLogger CreateTables error: " << errMsg << "\n";
            sqlite3_free(errMsg);
        }
        return false;
    }

    return true;
}

std::wstring EventLogger::ResolveClientId()
{
    // 1. Check if client_id exists in client_metadata table
    const wchar_t* selectSql = L"SELECT value FROM client_metadata WHERE key = 'client_id';";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare16_v2(m_db, selectSql, -1, &stmt, nullptr) == SQLITE_OK)
    {
        if (sqlite3_step(stmt) == SQLITE_ROW)
        {
            const void* val = sqlite3_column_text16(stmt, 0);
            if (val)
            {
                std::wstring id = static_cast<const wchar_t*>(val);
                sqlite3_finalize(stmt);
                if (!id.empty())
                {
                    return id;
                }
            }
        }
        sqlite3_finalize(stmt);
    }

    // 2. Try to read MachineGuid from Windows Registry
    std::wstring machineGuid;
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
    {
        wchar_t buf[256]{};
        DWORD bufSize = sizeof(buf);
        if (RegQueryValueExW(hKey, L"MachineGuid", nullptr, nullptr, reinterpret_cast<LPBYTE>(buf), &bufSize) == ERROR_SUCCESS)
        {
            machineGuid = buf;
        }
        RegCloseKey(hKey);
    }

    if (machineGuid.empty())
    {
        machineGuid = GenerateEventId();
    }

    // 3. Persist to client_metadata table
    const wchar_t* insertSql = L"INSERT OR REPLACE INTO client_metadata (key, value) VALUES ('client_id', ?);";
    if (sqlite3_prepare16_v2(m_db, insertSql, -1, &stmt, nullptr) == SQLITE_OK)
    {
        sqlite3_bind_text16(stmt, 1, machineGuid.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    return machineGuid;
}

std::wstring EventLogger::GenerateEventId()
{
    GUID guid{};
    if (CoCreateGuid(&guid) == S_OK)
    {
        wchar_t guidBuffer[64]{};
        swprintf_s(guidBuffer, sizeof(guidBuffer) / sizeof(wchar_t),
            L"%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        return guidBuffer;
    }
    return L"00000000-0000-0000-0000-000000000000";
}

std::wstring EventLogger::GetCurrentUtcTimestamp()
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    wchar_t timeBuffer[32]{};
    swprintf_s(timeBuffer, sizeof(timeBuffer) / sizeof(wchar_t),
        L"%04d-%02d-%02dT%02d:%02d:%02dZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return timeBuffer;
}

std::wstring EventLogger::GetClientId() const
{
    return m_clientId;
}

bool EventLogger::InsertEventRecord(const SecurityEvent& evt)
{
    const wchar_t* sql = LR"SQL(
        INSERT INTO security_events (
            event_id, client_id, timestamp, event_type,
            vendor_id, product_id, serial_number, device_id,
            device_type, description, decision, reason, sync_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )SQL";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
        std::wcerr << L"[ERROR] EventLogger prepare failed.\n";
        return false;
    }

    std::wstring typeStr = SecurityEventTypeToString(evt.eventType);

    sqlite3_bind_text16(stmt, 1, evt.eventId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 2, evt.clientId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 3, evt.timestamp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 4, typeStr.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 5, evt.vendorId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 6, evt.productId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 7, evt.serialNumber.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 8, evt.deviceId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 9, evt.deviceType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 10, evt.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 11, evt.decision.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 12, evt.reason.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 13, evt.syncStatus.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE);
    sqlite3_finalize(stmt);

    return success;
}

bool EventLogger::LogEvent(
    SecurityEventType type,
    const USBDevice& device,
    const std::wstring& decision,
    const std::wstring& reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_initialized || !m_db)
    {
        return false;
    }

    SecurityEvent evt;
    evt.eventId = GenerateEventId();
    evt.clientId = m_clientId;
    evt.timestamp = GetCurrentUtcTimestamp();
    evt.eventType = type;
    evt.vendorId = device.vendorId;
    evt.productId = device.productId;
    evt.serialNumber = device.serialNumber;
    evt.deviceId = device.deviceId;
    evt.deviceType = DeviceClassifier::ToString(device.type);
    evt.description = device.description;
    evt.decision = decision;
    evt.reason = reason;
    evt.syncStatus = L"PENDING";

    bool stored = InsertEventRecord(evt);

    // Formatted console output
    std::wcout << L"[AUDIT] [" << evt.timestamp << L"] "
               << SecurityEventTypeToString(type)
               << L" | VID: " << (evt.vendorId.empty() ? L"N/A" : evt.vendorId)
               << L" PID: " << (evt.productId.empty() ? L"N/A" : evt.productId)
               << L" | Decision: " << (evt.decision.empty() ? L"-" : evt.decision)
               << L" | Reason: " << evt.reason
               << L"\n";

    return stored;
}

bool EventLogger::LogSimpleEvent(
    SecurityEventType type,
    const std::wstring& deviceId,
    const std::wstring& devicePath,
    const std::wstring& decision,
    const std::wstring& reason,
    const std::wstring& vendorId,
    const std::wstring& productId,
    const std::wstring& serialNumber,
    const std::wstring& deviceType,
    const std::wstring& description)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_initialized || !m_db)
    {
        return false;
    }

    SecurityEvent evt;
    evt.eventId = GenerateEventId();
    evt.clientId = m_clientId;
    evt.timestamp = GetCurrentUtcTimestamp();
    evt.eventType = type;
    evt.vendorId = vendorId;
    evt.productId = productId;
    evt.serialNumber = serialNumber;
    evt.deviceId = deviceId;
    evt.deviceType = deviceType.empty() ? L"OTHER" : deviceType;
    evt.description = description;
    evt.decision = decision;
    evt.reason = reason;
    evt.syncStatus = L"PENDING";

    bool stored = InsertEventRecord(evt);

    std::wcout << L"[AUDIT] [" << evt.timestamp << L"] "
               << SecurityEventTypeToString(type)
               << L" | DeviceID: " << (deviceId.empty() ? devicePath : deviceId)
               << L" | Decision: " << (decision.empty() ? L"-" : decision)
               << L" | Reason: " << reason
               << L"\n";

    return stored;
}

std::vector<SecurityEvent> EventLogger::GetRecentEvents(int limit)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<SecurityEvent> events;

    if (!m_initialized || !m_db)
    {
        return events;
    }

    const wchar_t* sql = LR"SQL(
        SELECT event_id, client_id, timestamp, event_type,
               vendor_id, product_id, serial_number, device_id,
               device_type, description, decision, reason, sync_status
        FROM security_events
        ORDER BY rowid DESC
        LIMIT ?;
    )SQL";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return events;
    }

    sqlite3_bind_int(stmt, 1, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        SecurityEvent evt;
        auto getCol = [&](int col) -> std::wstring {
            const void* text = sqlite3_column_text16(stmt, col);
            return text ? static_cast<const wchar_t*>(text) : L"";
        };

        evt.eventId = getCol(0);
        evt.clientId = getCol(1);
        evt.timestamp = getCol(2);

        std::wstring typeStr = getCol(3);
        if (typeStr == L"DEVICE_CONNECTED") evt.eventType = SecurityEventType::DEVICE_CONNECTED;
        else if (typeStr == L"DEVICE_QUARANTINED") evt.eventType = SecurityEventType::DEVICE_QUARANTINED;
        else if (typeStr == L"DEVICE_RELEASED") evt.eventType = SecurityEventType::DEVICE_RELEASED;
        else if (typeStr == L"DEVICE_REMOVED") evt.eventType = SecurityEventType::DEVICE_REMOVED;
        else if (typeStr == L"ALLOWLIST_MATCH") evt.eventType = SecurityEventType::ALLOWLIST_MATCH;
        else if (typeStr == L"UNKNOWN_DEVICE") evt.eventType = SecurityEventType::UNKNOWN_DEVICE;
        else if (typeStr == L"USER_APPROVED") evt.eventType = SecurityEventType::USER_APPROVED;
        else if (typeStr == L"USER_REJECTED") evt.eventType = SecurityEventType::USER_REJECTED;
        else if (typeStr == L"DEVICE_BLOCKED") evt.eventType = SecurityEventType::DEVICE_BLOCKED;

        evt.vendorId = getCol(4);
        evt.productId = getCol(5);
        evt.serialNumber = getCol(6);
        evt.deviceId = getCol(7);
        evt.deviceType = getCol(8);
        evt.description = getCol(9);
        evt.decision = getCol(10);
        evt.reason = getCol(11);
        evt.syncStatus = getCol(12);

        events.push_back(evt);
    }

    sqlite3_finalize(stmt);
    return events;
}

std::vector<SecurityEvent> EventLogger::GetPendingSyncEvents(int limit)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<SecurityEvent> events;

    if (!m_initialized || !m_db)
    {
        return events;
    }

    const wchar_t* sql = LR"SQL(
        SELECT event_id, client_id, timestamp, event_type,
               vendor_id, product_id, serial_number, device_id,
               device_type, description, decision, reason, sync_status
        FROM security_events
        WHERE sync_status = 'PENDING'
        ORDER BY rowid ASC
        LIMIT ?;
    )SQL";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return events;
    }

    sqlite3_bind_int(stmt, 1, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        SecurityEvent evt;
        auto getCol = [&](int col) -> std::wstring {
            const void* text = sqlite3_column_text16(stmt, col);
            return text ? static_cast<const wchar_t*>(text) : L"";
        };

        evt.eventId = getCol(0);
        evt.clientId = getCol(1);
        evt.timestamp = getCol(2);

        std::wstring typeStr = getCol(3);
        if (typeStr == L"DEVICE_CONNECTED") evt.eventType = SecurityEventType::DEVICE_CONNECTED;
        else if (typeStr == L"DEVICE_QUARANTINED") evt.eventType = SecurityEventType::DEVICE_QUARANTINED;
        else if (typeStr == L"DEVICE_RELEASED") evt.eventType = SecurityEventType::DEVICE_RELEASED;
        else if (typeStr == L"DEVICE_REMOVED") evt.eventType = SecurityEventType::DEVICE_REMOVED;
        else if (typeStr == L"ALLOWLIST_MATCH") evt.eventType = SecurityEventType::ALLOWLIST_MATCH;
        else if (typeStr == L"UNKNOWN_DEVICE") evt.eventType = SecurityEventType::UNKNOWN_DEVICE;
        else if (typeStr == L"USER_APPROVED") evt.eventType = SecurityEventType::USER_APPROVED;
        else if (typeStr == L"USER_REJECTED") evt.eventType = SecurityEventType::USER_REJECTED;
        else if (typeStr == L"DEVICE_BLOCKED") evt.eventType = SecurityEventType::DEVICE_BLOCKED;

        evt.vendorId = getCol(4);
        evt.productId = getCol(5);
        evt.serialNumber = getCol(6);
        evt.deviceId = getCol(7);
        evt.deviceType = getCol(8);
        evt.description = getCol(9);
        evt.decision = getCol(10);
        evt.reason = getCol(11);
        evt.syncStatus = getCol(12);

        events.push_back(evt);
    }

    sqlite3_finalize(stmt);
    return events;
}

bool EventLogger::MarkEventsSynced(const std::vector<std::wstring>& eventIds)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_initialized || !m_db || eventIds.empty())
    {
        return false;
    }

    const wchar_t* sql = L"UPDATE security_events SET sync_status = 'SYNCED' WHERE event_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare16_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }

    sqlite3_exec(m_db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    for (const auto& id : eventIds)
    {
        sqlite3_bind_text16(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }

    sqlite3_exec(m_db, "COMMIT;", nullptr, nullptr, nullptr);
    sqlite3_finalize(stmt);
    return true;
}
