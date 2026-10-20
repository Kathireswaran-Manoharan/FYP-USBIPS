#pragma once

#include "../Models/USBDevice.h"
#include "../ThirdParty/SQLite/sqlite3.h"

#include <string>
#include <vector>
#include <mutex>

struct AllowedDevice
{
    int id = 0;

    std::wstring vendorId;
    std::wstring productId;
    std::wstring serialNumber;

    std::wstring deviceType;
    std::wstring description;
    std::wstring manufacturer;

    int durationMinutes = 0;
    std::wstring expiresAt;
    std::wstring decisionReason;
};

struct RevokedThreatRecord
{
    int id = 0;
    std::wstring vendorId;
    std::wstring productId;
    std::wstring serialNumber;
    std::wstring threatType;
    std::wstring threatEvidence;
    int riskScore = 85;
    std::wstring revokedAt;
    bool isUnverifiedScanError = false;
};

class AllowlistManager
{
public:

    AllowlistManager();
    ~AllowlistManager();

    bool Initialize(const std::wstring& databasePath);

    bool IsAllowed(const USBDevice& device);

    bool AddDevice(
        const USBDevice& device,
        int durationMinutes = 0,
        const std::wstring& expiresAt = L"",
        const std::wstring& decisionReason = L""
    );

    bool AddAllowedDevice(const AllowedDevice& device);

    bool RemoveDevice(const USBDevice& device);

    // Critical Threat Tracking (Requirement 4)
    bool RecordCriticalThreat(
        const USBDevice& device,
        const std::wstring& threatType,
        const std::wstring& threatEvidence,
        int riskScore = 85
    );

    bool HasActiveCriticalThreat(const USBDevice& device) const;

    bool ClearCriticalThreat(const USBDevice& device);

    // Explicit Administrator Recovery (Task 2 & 4)
    std::vector<RevokedThreatRecord> GetRevokedThreatDevices() const;

    bool GetCriticalThreat(const USBDevice& device, RevokedThreatRecord& outRecord) const;

    static bool IsRevocationDueToUnverifiedScanError(const RevokedThreatRecord& record);

    bool AdminRecoverDevice(
        const USBDevice& device,
        const std::wstring& adminReason,
        bool forceOverride = false,
        std::wstring* outError = nullptr
    );

    bool SyncWithRemote(const std::vector<AllowedDevice>& remoteDevices);

    std::vector<AllowedDevice> GetAllDevices();

    void Close();

private:

    sqlite3* db;
    mutable std::mutex m_mutex;

    bool CreateTables();

    std::wstring GetLastErrorMessage() const;
};