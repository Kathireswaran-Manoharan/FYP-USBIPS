#include "DataExfiltrationMonitor.h"
#include "PolicyConfig.h"
#include "../Logging/EventLogger.h"

#include <iostream>
#include <sstream>
#include <algorithm>

DataExfiltrationMonitor& DataExfiltrationMonitor::Instance()
{
    static DataExfiltrationMonitor instance;
    return instance;
}

static std::wstring ToLower(const std::wstring& s)
{
    std::wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::towlower);
    return out;
}

bool DataExfiltrationMonitor::IsSensitiveFileExtension(const std::wstring& fileName) const
{
    std::wstring lower = ToLower(fileName);
    static const std::vector<std::wstring> sensitiveExts = {
        L".doc", L".docx", L".pdf", L".xls", L".xlsx", L".kdbx",
        L".key", L".db", L".pem", L".csv", L".sql", L".bak", L".pst"
    };

    for (const auto& ext : sensitiveExts)
    {
        if (lower.size() >= ext.size() && lower.rfind(ext) == (lower.size() - ext.size()))
        {
            return true;
        }
    }
    return false;
}

void DataExfiltrationMonitor::RecordFileWrite(const std::wstring& driveLetter, const std::wstring& fileName, uint64_t fileSize)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    FileWriteRecord rec;
    rec.driveLetter = driveLetter;
    rec.fileName = fileName;
    rec.fileSize = fileSize;
    rec.timestamp = std::chrono::steady_clock::now();
    rec.isSensitiveExtension = IsSensitiveFileExtension(fileName);

    m_writeHistory.push_back(rec);

    std::wstring details;
    EvaluateRisk(driveLetter, details);
}

ExfiltrationRisk DataExfiltrationMonitor::EvaluateRisk(const std::wstring& driveLetter, std::wstring& outDetails)
{
    auto now = std::chrono::steady_clock::now();
    const PolicyConfig& cfg = PolicyConfig::Instance();
    auto windowDur = std::chrono::seconds(cfg.exfiltrationWindowSeconds);

    // Prune expired records
    while (!m_writeHistory.empty() && (now - m_writeHistory.front().timestamp) > windowDur)
    {
        m_writeHistory.erase(m_writeHistory.begin());
    }

    int driveWriteCount = 0;
    int sensitiveCount = 0;
    for (const auto& rec : m_writeHistory)
    {
        if (rec.driveLetter == driveLetter || driveLetter.empty())
        {
            driveWriteCount++;
            if (rec.isSensitiveExtension)
            {
                sensitiveCount++;
            }
        }
    }

    ExfiltrationRisk risk = ExfiltrationRisk::NORMAL;
    std::wostringstream ss;

    if (driveWriteCount >= cfg.exfiltrationMaxFileTouches || sensitiveCount >= 3)
    {
        risk = ExfiltrationRisk::SUSPICIOUS_VOLUME;
        ss << L"SUSPICIOUS COPY: High-volume write burst detected on removable volume " << driveLetter
           << L" (" << driveWriteCount << L" writes, " << sensitiveCount << L" sensitive file types in "
           << cfg.exfiltrationWindowSeconds << L"s window)";
    }
    else
    {
        risk = ExfiltrationRisk::NORMAL;
        ss << L"Normal activity (" << driveWriteCount << L" write(s) in window)";
    }

    outDetails = ss.str();
    m_latestRisk = risk;
    m_latestDetails = outDetails;

    if (risk != ExfiltrationRisk::NORMAL)
    {
        EventLogger::Instance().LogSimpleEvent(
            SecurityEventType::DATA_EXFILTRATION_DETECTED,
            L"",
            driveLetter,
            L"ASK",
            L"[ALG8] " + outDetails
        );
    }

    return risk;
}

bool DataExfiltrationMonitor::IsOsWriteProtectionEnabled() const
{
    HKEY hKey = nullptr;
    LSTATUS status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies",
        0,
        KEY_QUERY_VALUE,
        &hKey
    );

    if (status != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD dwValue = 0;
    DWORD dwSize = sizeof(DWORD);
    status = RegQueryValueExW(hKey, L"WriteProtect", nullptr, nullptr, reinterpret_cast<LPBYTE>(&dwValue), &dwSize);
    RegCloseKey(hKey);

    return (status == ERROR_SUCCESS && dwValue == 1);
}

bool DataExfiltrationMonitor::SetOsWriteProtection(bool enable)
{
    HKEY hKey = nullptr;
    LSTATUS status = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies",
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        nullptr,
        &hKey,
        nullptr
    );

    if (status != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD dwValue = enable ? 1 : 0;
    status = RegSetValueExW(hKey, L"WriteProtect", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dwValue), sizeof(DWORD));
    RegCloseKey(hKey);

    return (status == ERROR_SUCCESS);
}

void DataExfiltrationMonitor::ResetState()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_writeHistory.clear();
    m_latestRisk = ExfiltrationRisk::NORMAL;
    m_latestDetails.clear();
}

bool DataExfiltrationMonitor::VerifySelfTest()
{
    ResetState();

    std::wcout << L"  [8.1] Testing normal single-file write baseline...\n";
    std::wstring details;
    RecordFileWrite(L"E:", L"test_note.txt", 1024);
    ExfiltrationRisk r1 = EvaluateRisk(L"E:", details);
    bool t1 = (r1 == ExfiltrationRisk::NORMAL);
    std::wcout << L"        Single file write -> " << ExfiltrationRiskToString(r1) << (t1 ? L" [OK]" : L" [FAIL]") << L"\n";

    std::wcout << L"  [8.2] Testing rapid volume write burst anomaly (12 files in window)...\n";
    for (int i = 0; i < 12; i++)
    {
        RecordFileWrite(L"E:", L"data_" + std::to_wstring(i) + L".csv", 2048);
    }
    ExfiltrationRisk r2 = EvaluateRisk(L"E:", details);
    bool t2 = (r2 == ExfiltrationRisk::SUSPICIOUS_VOLUME);
    std::wcout << L"        12 file burst -> " << ExfiltrationRiskToString(r2) << (t2 ? L" [OK]" : L" [FAIL]") << L"\n";

    std::wcout << L"  [8.3] Checking Windows OS WriteProtect registry configuration...\n";
    bool wp = IsOsWriteProtectionEnabled();
    std::wcout << L"        StorageDevicePolicies\\WriteProtect : " << (wp ? L"ENABLED (Read-Only)" : L"DISABLED (Standard R/W)") << L" [OK]\n";
    std::wcout << L"        Enforcement Scope : Observable user-mode file rate detection;\n"
               << L"                            OS-level write blocking requires StorageDevicePolicies or minifilter driver.\n";

    ResetState();
    return (t1 && t2);
}
