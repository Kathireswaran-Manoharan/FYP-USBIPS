#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>

enum class FileRiskLevel
{
    CLEAN,
    SUSPICIOUS,
    MALICIOUS
};

inline const wchar_t* FileRiskLevelToString(FileRiskLevel risk)
{
    switch (risk)
    {
    case FileRiskLevel::CLEAN:
        return L"CLEAN";
    case FileRiskLevel::SUSPICIOUS:
        return L"SUSPICIOUS";
    case FileRiskLevel::MALICIOUS:
        return L"MALICIOUS";
    default:
        return L"UNKNOWN";
    }
}

struct SuspiciousFileFinding
{
    std::wstring filePath;
    std::wstring fileName;
    std::wstring ruleName;
    std::wstring reason;
    FileRiskLevel risk = FileRiskLevel::CLEAN;
};

struct FileInspectionReport
{
    FileRiskLevel overallRisk = FileRiskLevel::CLEAN;
    int filesScanned = 0;
    std::vector<SuspiciousFileFinding> findings;
    std::wstring summary;
    std::wstring timestamp;
};

class SuspiciousFileDetector
{
public:
    static SuspiciousFileDetector& Instance();

    // Module A5: Deep inspect directory / drive mount point
    FileInspectionReport InspectDirectory(const std::wstring& directoryPath);
    bool InspectFile(const std::wstring& filePath, SuspiciousFileFinding& finding);

    // Specific heuristic checks
    bool CheckAutorunInf(const std::wstring& autorunPath, SuspiciousFileFinding& finding);
    bool CheckDoubleExtension(const std::wstring& fileName, SuspiciousFileFinding& finding);
    bool CheckDisguisedExecutable(const std::wstring& filePath, SuspiciousFileFinding& finding);
    bool CheckMaliciousShortcut(const std::wstring& filePath, SuspiciousFileFinding& finding);
    bool CheckHiddenExecutable(const std::wstring& filePath, SuspiciousFileFinding& finding);

    // Self-test diagnostic verification
    bool VerifySelfTest();

private:
    SuspiciousFileDetector() = default;
    ~SuspiciousFileDetector() = default;

    SuspiciousFileDetector(const SuspiciousFileDetector&) = delete;
    SuspiciousFileDetector& operator=(const SuspiciousFileDetector&) = delete;

private:
    mutable std::mutex m_mutex;
};
