#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include <chrono>
#include <mutex>

enum class ExfiltrationRisk
{
    NORMAL,
    SUSPICIOUS_VOLUME,
    CRITICAL_CANARY_CORRELATED
};

inline const wchar_t* ExfiltrationRiskToString(ExfiltrationRisk risk)
{
    switch (risk)
    {
    case ExfiltrationRisk::NORMAL:
        return L"NORMAL";
    case ExfiltrationRisk::SUSPICIOUS_VOLUME:
        return L"SUSPICIOUS_VOLUME";
    case ExfiltrationRisk::CRITICAL_CANARY_CORRELATED:
        return L"CRITICAL_CANARY_CORRELATED";
    default:
        return L"UNKNOWN";
    }
}

struct FileWriteRecord
{
    std::wstring driveLetter;
    std::wstring fileName;
    uint64_t fileSize = 0;
    std::chrono::steady_clock::time_point timestamp;
    bool isSensitiveExtension = false;
};

class DataExfiltrationMonitor
{
public:
    static DataExfiltrationMonitor& Instance();

    // Module A8: Record and evaluate file write events on removable storage
    void RecordFileWrite(const std::wstring& driveLetter, const std::wstring& fileName, uint64_t fileSize = 0);
    ExfiltrationRisk EvaluateRisk(const std::wstring& driveLetter, std::wstring& outDetails);

    // OS-level write protection support (Registry StorageDevicePolicies)
    bool IsOsWriteProtectionEnabled() const;
    bool SetOsWriteProtection(bool enable);

    // Reset tracking state
    void ResetState();

    // Self-test diagnostic routine
    bool VerifySelfTest();

private:
    DataExfiltrationMonitor() = default;
    ~DataExfiltrationMonitor() = default;

    DataExfiltrationMonitor(const DataExfiltrationMonitor&) = delete;
    DataExfiltrationMonitor& operator=(const DataExfiltrationMonitor&) = delete;

    bool IsSensitiveFileExtension(const std::wstring& fileName) const;

private:
    mutable std::mutex m_mutex;
    std::vector<FileWriteRecord> m_writeHistory;
    ExfiltrationRisk m_latestRisk = ExfiltrationRisk::NORMAL;
    std::wstring m_latestDetails;
};
