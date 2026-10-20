#include "AllowlistManager.h"
#include "../Classifier/DeviceClassifier.h"
#include "../Logging/EventLogger.h"

#include <windows.h>
#include <iostream>


AllowlistManager::AllowlistManager()
    : db(nullptr)
{
}


AllowlistManager::~AllowlistManager()
{
    Close();
}


bool AllowlistManager::Initialize(const std::wstring& databasePath)
{
    if (db != nullptr)
    {
        return true;
    }

    int result =
        sqlite3_open16(
            databasePath.c_str(),
            &db
        );

    if (result != SQLITE_OK)
    {
        std::wcerr
            << L"[ERROR] Could not open SQLite database.\n";

        if (db != nullptr)
        {
            std::wcerr
                << L"SQLite Error: "
                << GetLastErrorMessage()
                << L"\n";
        }

        return false;
    }

    std::wcout
        << L"[OK] SQLite database opened.\n";

    if (!CreateTables())
    {
        std::wcerr
            << L"[ERROR] Could not create database tables.\n";

        return false;
    }

    return true;
}


bool AllowlistManager::CreateTables()
{
    const char* sql = R"SQL(

        CREATE TABLE IF NOT EXISTS allowed_devices
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            vendor_id TEXT NOT NULL,
            product_id TEXT NOT NULL,
            serial_number TEXT NOT NULL,

            device_type TEXT,
            description TEXT,
            manufacturer TEXT,

            duration_minutes INTEGER,
            expires_at DATETIME,
            decision_reason TEXT,

            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            UNIQUE(vendor_id, product_id, serial_number)
        );

    )SQL";

    char* errorMessage = nullptr;

    int result =
        sqlite3_exec(
            db,
            sql,
            nullptr,
            nullptr,
            &errorMessage
        );

    if (result != SQLITE_OK)
    {
        std::wcerr
            << L"[ERROR] Failed to create table.\n";

        if (errorMessage != nullptr)
        {
            std::cerr
                << "SQLite Error: "
                << errorMessage
                << "\n";

            sqlite3_free(errorMessage);
        }

        return false;
    }

    // Ensure columns exist if table was created in previous runs
    sqlite3_exec(db, "ALTER TABLE allowed_devices ADD COLUMN duration_minutes INTEGER;", nullptr, nullptr, nullptr);
    sqlite3_exec(db, "ALTER TABLE allowed_devices ADD COLUMN expires_at DATETIME;", nullptr, nullptr, nullptr);
    sqlite3_exec(db, "ALTER TABLE allowed_devices ADD COLUMN decision_reason TEXT;", nullptr, nullptr, nullptr);

    // Create persistent revoked_threat_devices table (Requirement 4)
    const char* threatTableSql = R"SQL(
        CREATE TABLE IF NOT EXISTS revoked_threat_devices
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_id TEXT NOT NULL,
            product_id TEXT NOT NULL,
            serial_number TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            threat_evidence TEXT,
            risk_score INTEGER DEFAULT 85,
            revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(vendor_id, product_id, serial_number)
        );
    )SQL";
    sqlite3_exec(db, threatTableSql, nullptr, nullptr, nullptr);

    std::wcout
        << L"[OK] Allowlist table ready.\n";

    return true;
}


bool AllowlistManager::IsAllowed(
    const USBDevice& device)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (db == nullptr)
    {
        return false;
    }

    // Step 1: Check if device has an active confirmed critical threat record (Requirement 4)
    const wchar_t* threatSql =
        L"SELECT COUNT(*) FROM revoked_threat_devices "
        L"WHERE vendor_id = ? COLLATE NOCASE "
        L"AND product_id = ? COLLATE NOCASE "
        L"AND serial_number = ? COLLATE NOCASE;";

    sqlite3_stmt* threatStmt = nullptr;
    if (sqlite3_prepare16_v2(db, threatSql, -1, &threatStmt, nullptr) == SQLITE_OK)
    {
        sqlite3_bind_text16(threatStmt, 1, device.vendorId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(threatStmt, 2, device.productId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(threatStmt, 3, device.serialNumber.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(threatStmt) == SQLITE_ROW && sqlite3_column_int(threatStmt, 0) > 0)
        {
            sqlite3_finalize(threatStmt);
            return false; // Active critical threat: strictly prohibited!
        }
        sqlite3_finalize(threatStmt);
    }

    const wchar_t* sql =
        L"SELECT COUNT(*) "
        L"FROM allowed_devices "
        L"WHERE vendor_id = ? COLLATE NOCASE "
        L"AND product_id = ? COLLATE NOCASE "
        L"AND serial_number = ? COLLATE NOCASE "
        L"AND (expires_at IS NULL OR expires_at = '' OR datetime(expires_at) > datetime('now'));";

    sqlite3_stmt* statement = nullptr;

    int result =
        sqlite3_prepare16_v2(
            db,
            sql,
            -1,
            &statement,
            nullptr
        );

    if (result != SQLITE_OK)
    {
        std::wcerr
            << L"[ERROR] Failed to prepare allowlist query.\n";

        return false;
    }

    sqlite3_bind_text16(
        statement,
        1,
        device.vendorId.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        2,
        device.productId.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        3,
        device.serialNumber.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    bool allowed = false;

    result = sqlite3_step(statement);

    if (result == SQLITE_ROW)
    {
        int count =
            sqlite3_column_int(statement, 0);

        allowed = (count > 0);
    }

    sqlite3_finalize(statement);

    return allowed;
}


bool AllowlistManager::AddDevice(
    const USBDevice& device,
    int durationMinutes,
    const std::wstring& expiresAt,
    const std::wstring& decisionReason)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (db == nullptr)
    {
        return false;
    }

    const wchar_t* sql =
        L"INSERT OR REPLACE INTO allowed_devices "
        L"(vendor_id, product_id, serial_number, "
        L"device_type, description, manufacturer, "
        L"duration_minutes, expires_at, decision_reason) "
        L"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* statement = nullptr;

    int result =
        sqlite3_prepare16_v2(
            db,
            sql,
            -1,
            &statement,
            nullptr
        );

    if (result != SQLITE_OK)
    {
        std::wcerr
            << L"[ERROR] Failed to prepare INSERT statement.\n";

        return false;
    }

    std::wstring deviceType =
        DeviceClassifier::ToString(device.type);

    sqlite3_bind_text16(
        statement,
        1,
        device.vendorId.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        2,
        device.productId.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        3,
        device.serialNumber.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        4,
        deviceType.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        5,
        device.description.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        6,
        device.manufacturer.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_int(
        statement,
        7,
        durationMinutes
    );

    sqlite3_bind_text16(
        statement,
        8,
        expiresAt.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        9,
        decisionReason.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    result = sqlite3_step(statement);

    bool success =
        (result == SQLITE_DONE);

    sqlite3_finalize(statement);

    if (success)
    {
        std::wcout
            << L"[OK] Device added to allowlist.\n";
    }
    else
    {
        std::wcerr
            << L"[ERROR] Failed to add device to allowlist.\n";
    }

    return success;
}


bool AllowlistManager::RemoveDevice(
    const USBDevice& device)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (db == nullptr)
    {
        return false;
    }

    const wchar_t* sql =
        L"DELETE FROM allowed_devices "
        L"WHERE vendor_id = ? COLLATE NOCASE "
        L"AND product_id = ? COLLATE NOCASE "
        L"AND serial_number = ? COLLATE NOCASE;";

    sqlite3_stmt* statement = nullptr;

    int result =
        sqlite3_prepare16_v2(
            db,
            sql,
            -1,
            &statement,
            nullptr
        );

    if (result != SQLITE_OK)
    {
        return false;
    }

    sqlite3_bind_text16(
        statement,
        1,
        device.vendorId.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        2,
        device.productId.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        3,
        device.serialNumber.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    result = sqlite3_step(statement);

    bool success =
        (result == SQLITE_DONE);

    sqlite3_finalize(statement);

    if (success)
    {
        std::wcout
            << L"[OK] Device removed from allowlist.\n";
    }

    return success;
}


bool AllowlistManager::RecordCriticalThreat(
    const USBDevice& device,
    const std::wstring& threatType,
    const std::wstring& threatEvidence,
    int riskScore)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (db == nullptr) return false;

    // 1. Insert into revoked_threat_devices
    const wchar_t* insertSql =
        L"INSERT OR REPLACE INTO revoked_threat_devices "
        L"(vendor_id, product_id, serial_number, threat_type, threat_evidence, risk_score) "
        L"VALUES (?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare16_v2(db, insertSql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }

    sqlite3_bind_text16(stmt, 1, device.vendorId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 2, device.productId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 3, device.serialNumber.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 4, threatType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 5, threatEvidence.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, riskScore);

    int res = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // 2. Remove from allowed_devices
    const wchar_t* delSql =
        L"DELETE FROM allowed_devices "
        L"WHERE vendor_id = ? COLLATE NOCASE "
        L"AND product_id = ? COLLATE NOCASE "
        L"AND serial_number = ? COLLATE NOCASE;";

    sqlite3_stmt* delStmt = nullptr;
    if (sqlite3_prepare16_v2(db, delSql, -1, &delStmt, nullptr) == SQLITE_OK)
    {
        sqlite3_bind_text16(delStmt, 1, device.vendorId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(delStmt, 2, device.productId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(delStmt, 3, device.serialNumber.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(delStmt);
        sqlite3_finalize(delStmt);
    }

    std::wcout << L"[ALLOWLIST] Device " << device.vendorId << L":" << device.productId
               << L" (" << device.serialNumber << L") permanently recorded as CRITICAL_THREAT_REVOKED.\n";

    return (res == SQLITE_DONE);
}

bool AllowlistManager::HasActiveCriticalThreat(const USBDevice& device) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (db == nullptr) return false;

    const wchar_t* sql =
        L"SELECT COUNT(*) FROM revoked_threat_devices "
        L"WHERE vendor_id = ? COLLATE NOCASE "
        L"AND product_id = ? COLLATE NOCASE "
        L"AND serial_number = ? COLLATE NOCASE;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare16_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }

    sqlite3_bind_text16(stmt, 1, device.vendorId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 2, device.productId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 3, device.serialNumber.c_str(), -1, SQLITE_TRANSIENT);

    bool hasThreat = false;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        hasThreat = (sqlite3_column_int(stmt, 0) > 0);
    }
    sqlite3_finalize(stmt);
    return hasThreat;
}

bool AllowlistManager::ClearCriticalThreat(const USBDevice& device)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (db == nullptr) return false;

    const wchar_t* sql =
        L"DELETE FROM revoked_threat_devices "
        L"WHERE vendor_id = ? COLLATE NOCASE "
        L"AND product_id = ? COLLATE NOCASE "
        L"AND serial_number = ? COLLATE NOCASE;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare16_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }

    sqlite3_bind_text16(stmt, 1, device.vendorId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 2, device.productId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 3, device.serialNumber.c_str(), -1, SQLITE_TRANSIENT);

    int res = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (res == SQLITE_DONE);
}

std::vector<RevokedThreatRecord> AllowlistManager::GetRevokedThreatDevices() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<RevokedThreatRecord> list;
    if (db == nullptr) return list;

    const wchar_t* sql =
        L"SELECT id, vendor_id, product_id, serial_number, threat_type, threat_evidence, risk_score, revoked_at "
        L"FROM revoked_threat_devices ORDER BY id;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare16_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return list;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        RevokedThreatRecord r;
        r.id = sqlite3_column_int(stmt, 0);
        const wchar_t* v = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(stmt, 1));
        const wchar_t* p = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(stmt, 2));
        const wchar_t* s = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(stmt, 3));
        const wchar_t* tt = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(stmt, 4));
        const wchar_t* te = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(stmt, 5));
        r.riskScore = sqlite3_column_int(stmt, 6);
        const wchar_t* ra = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(stmt, 7));

        if (v) r.vendorId = v;
        if (p) r.productId = p;
        if (s) r.serialNumber = s;
        if (tt) r.threatType = tt;
        if (te) r.threatEvidence = te;
        if (ra) r.revokedAt = ra;

        r.isUnverifiedScanError = IsRevocationDueToUnverifiedScanError(r);
        list.push_back(r);
    }
    sqlite3_finalize(stmt);
    return list;
}

bool AllowlistManager::GetCriticalThreat(const USBDevice& device, RevokedThreatRecord& outRecord) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (db == nullptr) return false;

    const wchar_t* sql =
        L"SELECT id, vendor_id, product_id, serial_number, threat_type, threat_evidence, risk_score, revoked_at "
        L"FROM revoked_threat_devices "
        L"WHERE vendor_id = ? COLLATE NOCASE "
        L"AND product_id = ? COLLATE NOCASE "
        L"AND serial_number = ? COLLATE NOCASE;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare16_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }

    sqlite3_bind_text16(stmt, 1, device.vendorId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 2, device.productId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(stmt, 3, device.serialNumber.c_str(), -1, SQLITE_TRANSIENT);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        found = true;
        outRecord.id = sqlite3_column_int(stmt, 0);
        const wchar_t* v = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(stmt, 1));
        const wchar_t* p = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(stmt, 2));
        const wchar_t* s = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(stmt, 3));
        const wchar_t* tt = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(stmt, 4));
        const wchar_t* te = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(stmt, 5));
        outRecord.riskScore = sqlite3_column_int(stmt, 6);
        const wchar_t* ra = reinterpret_cast<const wchar_t*>(sqlite3_column_text16(stmt, 7));

        if (v) outRecord.vendorId = v;
        if (p) outRecord.productId = p;
        if (s) outRecord.serialNumber = s;
        if (tt) outRecord.threatType = tt;
        if (te) outRecord.threatEvidence = te;
        if (ra) outRecord.revokedAt = ra;

        outRecord.isUnverifiedScanError = IsRevocationDueToUnverifiedScanError(outRecord);
    }
    sqlite3_finalize(stmt);
    return found;
}

bool AllowlistManager::IsRevocationDueToUnverifiedScanError(const RevokedThreatRecord& record)
{
    // Must be an antivirus/malware scan revocation
    if (record.threatType != L"AntivirusMalwareScan" &&
        record.threatType != L"MalwareScan" &&
        record.threatType != L"MpCmdRun")
    {
        return false;
    }

    const std::wstring& ev = record.threatEvidence;
    // Check if evidence exhibits hallmarks of unverified scan errors or incorrect drive attribution:
    // 1. Generic synthesized placeholder with no specific infected file path
    // 2. Drive A: or B: (floppy drive / nonexistent media)
    // 3. Defender error 0x80508023 (MP_E_SCAN_NOT_FOUND) or Completion Failed
    // 4. Inaccessible drive / timeout / failed status
    if (ev.find(L"Win32/MalwareSignature.Generic") != std::wstring::npos ||
        ev.find(L"0x80508023") != std::wstring::npos ||
        ev.find(L"MP_E_SCAN_NOT_FOUND") != std::wstring::npos ||
        ev.find(L"drive A:") != std::wstring::npos ||
        ev.find(L"drive A:\\") != std::wstring::npos ||
        ev.find(L"drive B:") != std::wstring::npos ||
        ev.find(L"drive B:\\") != std::wstring::npos ||
        ev.find(L"Completion Failed") != std::wstring::npos ||
        ev.find(L"NOT_SCANNED") != std::wstring::npos ||
        ev.find(L"SCAN_FAILED") != std::wstring::npos ||
        ev.find(L"SCAN_TIMEOUT") != std::wstring::npos)
    {
        return true;
    }

    return false;
}

bool AllowlistManager::AdminRecoverDevice(
    const USBDevice& device,
    const std::wstring& adminReason,
    bool forceOverride,
    std::wstring* outError)
{
    RevokedThreatRecord record;
    if (!GetCriticalThreat(device, record))
    {
        if (outError) *outError = L"Device is not recorded in critical threat revocation list.";
        return false;
    }

    bool isUnverified = IsRevocationDueToUnverifiedScanError(record);
    if (!isUnverified && !forceOverride)
    {
        std::wstring err = L"Device has confirmed threat revocation (" + record.threatType +
                           L": " + record.threatEvidence +
                           L"). Automatic unverified-error recovery rejected. Administrator override required.";
        if (outError) *outError = err;
        std::wcerr << L"[RECOVERY-DENIED] " << err << L"\n";
        return false;
    }

    // Perform the clearing
    bool cleared = ClearCriticalThreat(device);
    if (!cleared)
    {
        if (outError) *outError = L"Database operation failed while clearing critical threat tombstone.";
        return false;
    }

    std::wcout << L"[RECOVERY-SUCCESS] Device " << device.vendorId << L":" << device.productId
               << L" (" << device.serialNumber << L") cleared from revoked_threat_devices tombstone.\n"
               << L"                   Reason: " << adminReason << L"\n";

    EventLogger::Instance().LogEvent(
        SecurityEventType::USER_APPROVED,
        device,
        L"ALLOW",
        L"Administrator cleared " +
        std::wstring(isUnverified ? L"unverified scan error revocation" : L"revocation under administrative override") +
        L". Original evidence: " + record.threatEvidence +
        L" | Justification: " + adminReason
    );

    return true;
}


std::vector<AllowedDevice>
AllowlistManager::GetAllDevices()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<AllowedDevice> devices;

    if (db == nullptr)
    {
        return devices;
    }

    const wchar_t* sql =
        L"SELECT id, vendor_id, product_id, "
        L"serial_number, device_type, "
        L"description, manufacturer, "
        L"duration_minutes, expires_at, decision_reason "
        L"FROM allowed_devices "
        L"ORDER BY id;";

    sqlite3_stmt* statement = nullptr;

    int result =
        sqlite3_prepare16_v2(
            db,
            sql,
            -1,
            &statement,
            nullptr
        );

    if (result != SQLITE_OK)
    {
        return devices;
    }

    while (sqlite3_step(statement) == SQLITE_ROW)
    {
        AllowedDevice device;

        device.id =
            sqlite3_column_int(statement, 0);

        const void* vendor =
            sqlite3_column_text16(statement, 1);

        const void* product =
            sqlite3_column_text16(statement, 2);

        const void* serial =
            sqlite3_column_text16(statement, 3);

        const void* type =
            sqlite3_column_text16(statement, 4);

        const void* description =
            sqlite3_column_text16(statement, 5);

        const void* manufacturer =
            sqlite3_column_text16(statement, 6);

        device.durationMinutes = sqlite3_column_int(statement, 7);

        const void* expires =
            sqlite3_column_text16(statement, 8);

        const void* reason =
            sqlite3_column_text16(statement, 9);

        if (vendor)
            device.vendorId =
                static_cast<const wchar_t*>(vendor);

        if (product)
            device.productId =
                static_cast<const wchar_t*>(product);

        if (serial)
            device.serialNumber =
                static_cast<const wchar_t*>(serial);

        if (type)
            device.deviceType =
                static_cast<const wchar_t*>(type);

        if (description)
            device.description =
                static_cast<const wchar_t*>(description);

        if (manufacturer)
            device.manufacturer =
                static_cast<const wchar_t*>(manufacturer);

        if (expires)
            device.expiresAt =
                static_cast<const wchar_t*>(expires);

        if (reason)
            device.decisionReason =
                static_cast<const wchar_t*>(reason);

        devices.push_back(device);
    }

    sqlite3_finalize(statement);

    return devices;
}


bool AllowlistManager::AddAllowedDevice(const AllowedDevice& device)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (db == nullptr)
    {
        return false;
    }

    const wchar_t* sql =
        L"INSERT OR REPLACE INTO allowed_devices "
        L"(vendor_id, product_id, serial_number, device_type, description, manufacturer, duration_minutes, expires_at, decision_reason) "
        L"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare16_v2(db, sql, -1, &statement, nullptr) != SQLITE_OK)
    {
        return false;
    }

    sqlite3_bind_text16(statement, 1, device.vendorId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(statement, 2, device.productId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(statement, 3, device.serialNumber.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(statement, 4, device.deviceType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(statement, 5, device.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(statement, 6, device.manufacturer.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(statement, 7, device.durationMinutes);
    sqlite3_bind_text16(statement, 8, device.expiresAt.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text16(statement, 9, device.decisionReason.c_str(), -1, SQLITE_TRANSIENT);

    int result = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return (result == SQLITE_DONE);
}


bool AllowlistManager::SyncWithRemote(const std::vector<AllowedDevice>& remoteDevices)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (db == nullptr)
    {
        return false;
    }

    char* err = nullptr;
    if (sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &err) != SQLITE_OK)
    {
        if (err) sqlite3_free(err);
        return false;
    }

    if (sqlite3_exec(db, "DELETE FROM allowed_devices;", nullptr, nullptr, &err) != SQLITE_OK)
    {
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    const wchar_t* insertSql =
        L"INSERT OR REPLACE INTO allowed_devices "
        L"(vendor_id, product_id, serial_number, device_type, description, manufacturer, duration_minutes, expires_at, decision_reason) "
        L"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare16_v2(db, insertSql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    const wchar_t* checkThreatSql =
        L"SELECT COUNT(*) FROM revoked_threat_devices "
        L"WHERE vendor_id = ? COLLATE NOCASE "
        L"AND product_id = ? COLLATE NOCASE "
        L"AND serial_number = ? COLLATE NOCASE;";

    sqlite3_stmt* checkThreatStmt = nullptr;
    sqlite3_prepare16_v2(db, checkThreatSql, -1, &checkThreatStmt, nullptr);

    for (const auto& dev : remoteDevices)
    {
        // Skip devices with active confirmed critical threats (Requirement 4)
        if (checkThreatStmt)
        {
            sqlite3_bind_text16(checkThreatStmt, 1, dev.vendorId.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text16(checkThreatStmt, 2, dev.productId.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text16(checkThreatStmt, 3, dev.serialNumber.c_str(), -1, SQLITE_TRANSIENT);
            bool isThreat = false;
            if (sqlite3_step(checkThreatStmt) == SQLITE_ROW)
            {
                isThreat = (sqlite3_column_int(checkThreatStmt, 0) > 0);
            }
            sqlite3_reset(checkThreatStmt);

            if (isThreat)
            {
                std::wcout << L"[ALLOWLIST-SYNC] Skipping remote allowlist device "
                           << dev.vendorId << L":" << dev.productId << L" (" << dev.serialNumber
                           << L") - Device has confirmed critical threat locally!\n";
                continue;
            }
        }

        sqlite3_bind_text16(stmt, 1, dev.vendorId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(stmt, 2, dev.productId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(stmt, 3, dev.serialNumber.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(stmt, 4, dev.deviceType.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(stmt, 5, dev.description.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(stmt, 6, dev.manufacturer.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 7, dev.durationMinutes);
        sqlite3_bind_text16(stmt, 8, dev.expiresAt.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text16(stmt, 9, dev.decisionReason.c_str(), -1, SQLITE_TRANSIENT);

        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }

    if (checkThreatStmt)
    {
        sqlite3_finalize(checkThreatStmt);
    }

    sqlite3_finalize(stmt);
    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, nullptr);
    return true;
}


std::wstring
AllowlistManager::GetLastErrorMessage() const
{
    if (db == nullptr)
    {
        return L"Unknown SQLite error";
    }

    const char* error =
        sqlite3_errmsg(db);

    if (error == nullptr)
    {
        return L"Unknown SQLite error";
    }

    int requiredSize =
        MultiByteToWideChar(
            CP_UTF8,
            0,
            error,
            -1,
            nullptr,
            0
        );

    if (requiredSize <= 0)
    {
        return L"SQLite error";
    }

    std::wstring result(requiredSize, L'\0');

    MultiByteToWideChar(
        CP_UTF8,
        0,
        error,
        -1,
        &result[0],
        requiredSize
    );

    if (!result.empty() &&
        result.back() == L'\0')
    {
        result.pop_back();
    }

    return result;
}


void AllowlistManager::Close()
{
    if (db != nullptr)
    {
        sqlite3_close(db);
        db = nullptr;
    }
}