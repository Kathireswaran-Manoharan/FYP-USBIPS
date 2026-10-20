#include "SuspiciousFileDetector.h"
#include "PolicyConfig.h"
#include "../Logging/EventLogger.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>

SuspiciousFileDetector& SuspiciousFileDetector::Instance()
{
    static SuspiciousFileDetector instance;
    return instance;
}

static std::wstring ToLower(const std::wstring& s)
{
    std::wstring out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::towlower);
    return out;
}

bool SuspiciousFileDetector::CheckAutorunInf(const std::wstring& autorunPath, SuspiciousFileFinding& finding)
{
    std::ifstream file(autorunPath);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line))
    {
        std::string lowerLine = line;
        std::transform(lowerLine.begin(), lowerLine.end(), lowerLine.begin(), ::tolower);

        if (lowerLine.find("open=") != std::string::npos ||
            lowerLine.find("shellexecute=") != std::string::npos ||
            lowerLine.find("action=") != std::string::npos)
        {
            finding.filePath = autorunPath;
            finding.fileName = L"autorun.inf";
            finding.ruleName = L"AUTORUN_EXECUTION_DIRECTIVE";
            finding.risk = FileRiskLevel::MALICIOUS;
            finding.reason = L"autorun.inf contains automated launch directive: " +
                             std::wstring(line.begin(), line.end());
            return true;
        }
    }
    return false;
}

bool SuspiciousFileDetector::CheckDoubleExtension(const std::wstring& fileName, SuspiciousFileFinding& finding)
{
    std::wstring lower = ToLower(fileName);
    static const std::vector<std::wstring> execExts = {
        L".exe", L".scr", L".bat", L".cmd", L".vbs", L".js", L".wsf", L".ps1", L".hta", L".pif"
    };
    static const std::vector<std::wstring> docExts = {
        L".pdf", L".doc", L".docx", L".xls", L".xlsx", L".jpg", L".png", L".txt", L".zip", L".rar"
    };

    for (const auto& ex : execExts)
    {
        if (lower.size() > ex.size() && lower.rfind(ex) == (lower.size() - ex.size()))
        {
            std::wstring prefix = lower.substr(0, lower.size() - ex.size());
            for (const auto& doc : docExts)
            {
                if (prefix.size() > doc.size() && prefix.rfind(doc) == (prefix.size() - doc.size()))
                {
                    finding.fileName = fileName;
                    finding.ruleName = L"DOUBLE_EXTENSION_DECEPTION";
                    finding.risk = FileRiskLevel::MALICIOUS;
                    finding.reason = L"File uses deceptive double extension masking executable as document (" + fileName + L")";
                    return true;
                }
            }
        }
    }
    return false;
}

bool SuspiciousFileDetector::CheckDisguisedExecutable(const std::wstring& filePath, SuspiciousFileFinding& finding)
{
    std::wstring lower = ToLower(filePath);
    static const std::vector<std::wstring> nonExecExts = {
        L".txt", L".jpg", L".jpeg", L".png", L".pdf", L".docx", L".xlsx", L".mp4", L".bmp", L".wav"
    };

    bool hasNonExecExt = false;
    for (const auto& ext : nonExecExts)
    {
        if (lower.size() > ext.size() && lower.rfind(ext) == (lower.size() - ext.size()))
        {
            hasNonExecExt = true;
            break;
        }
    }

    if (!hasNonExecExt) return false;

    // Check first 2 bytes for DOS/PE header 'M' 'Z' (0x4D 0x5A)
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;

    char header[2] = { 0 };
    file.read(header, 2);
    if (file.gcount() == 2 && header[0] == 'M' && header[1] == 'Z')
    {
        finding.filePath = filePath;
        finding.fileName = std::filesystem::path(filePath).filename().wstring();
        finding.ruleName = L"DISGUISED_PE_HEADER";
        finding.risk = FileRiskLevel::MALICIOUS;
        finding.reason = L"File has document/media extension but contains executable PE header (MZ magic bytes)";
        return true;
    }

    return false;
}

bool SuspiciousFileDetector::CheckMaliciousShortcut(const std::wstring& filePath, SuspiciousFileFinding& finding)
{
    std::wstring lower = ToLower(filePath);
    if (lower.size() < 4 || lower.rfind(L".lnk") != (lower.size() - 4)) return false;

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::string lowerContent = content;
    std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);

    static const std::vector<std::string> triggers = {
        "powershell", "cmd.exe", "wscript", "cscript", "mshta", "certutil", "bitsadmin", "rundll32", "regsvr32"
    };

    for (const auto& trig : triggers)
    {
        if (lowerContent.find(trig) != std::string::npos)
        {
            finding.filePath = filePath;
            finding.fileName = std::filesystem::path(filePath).filename().wstring();
            finding.ruleName = L"SUSPICIOUS_LNK_PAYLOAD";
            finding.risk = FileRiskLevel::MALICIOUS;
            finding.reason = L"Shortcut (.lnk) targets command interpreter or LOLBIN: " + std::wstring(trig.begin(), trig.end());
            return true;
        }
    }

    return false;
}

bool SuspiciousFileDetector::CheckHiddenExecutable(const std::wstring& filePath, SuspiciousFileFinding& finding)
{
    DWORD attr = GetFileAttributesW(filePath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return false;

    if ((attr & FILE_ATTRIBUTE_HIDDEN) || (attr & FILE_ATTRIBUTE_SYSTEM))
    {
        std::wstring lower = ToLower(filePath);
        static const std::vector<std::wstring> execExts = {
            L".exe", L".dll", L".bat", L".cmd", L".vbs", L".ps1", L".scr", L".hta"
        };
        for (const auto& ext : execExts)
        {
            if (lower.size() > ext.size() && lower.rfind(ext) == (lower.size() - ext.size()))
            {
                finding.filePath = filePath;
                finding.fileName = std::filesystem::path(filePath).filename().wstring();
                finding.ruleName = L"HIDDEN_EXECUTABLE_ATTRIBUTE";
                finding.risk = FileRiskLevel::SUSPICIOUS;
                finding.reason = L"Executable file has Hidden or System attribute flag in directory";
                return true;
            }
        }
    }
    return false;
}

bool SuspiciousFileDetector::InspectFile(const std::wstring& filePath, SuspiciousFileFinding& finding)
{
    std::wstring fileName = std::filesystem::path(filePath).filename().wstring();
    std::wstring lowerName = ToLower(fileName);

    if (lowerName == L"autorun.inf" && CheckAutorunInf(filePath, finding))
        return true;

    if (CheckDoubleExtension(fileName, finding))
    {
        finding.filePath = filePath;
        return true;
    }

    if (CheckDisguisedExecutable(filePath, finding))
        return true;

    if (CheckMaliciousShortcut(filePath, finding))
        return true;

    if (CheckHiddenExecutable(filePath, finding))
        return true;

    return false;
}

FileInspectionReport SuspiciousFileDetector::InspectDirectory(const std::wstring& directoryPath)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    FileInspectionReport report;
    report.overallRisk = FileRiskLevel::CLEAN;

    if (!std::filesystem::exists(directoryPath))
    {
        report.summary = L"Target directory does not exist: " + directoryPath;
        return report;
    }

    int filesCount = 0;
    try
    {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(directoryPath, std::filesystem::directory_options::skip_permission_denied))
        {
            if (entry.is_regular_file())
            {
                filesCount++;
                SuspiciousFileFinding finding;
                if (InspectFile(entry.path().wstring(), finding))
                {
                    report.findings.push_back(finding);
                    if (finding.risk == FileRiskLevel::MALICIOUS)
                    {
                        report.overallRisk = FileRiskLevel::MALICIOUS;
                    }
                    else if (finding.risk == FileRiskLevel::SUSPICIOUS && report.overallRisk != FileRiskLevel::MALICIOUS)
                    {
                        report.overallRisk = FileRiskLevel::SUSPICIOUS;
                    }
                }
            }
        }
    }
    catch (...) {}

    report.filesScanned = filesCount;
    std::wostringstream ss;
    ss << L"Scanned " << filesCount << L" file(s); " << report.findings.size() << L" suspicious finding(s).";
    report.summary = ss.str();

    if (!report.findings.empty())
    {
        EventLogger::Instance().LogSimpleEvent(
            SecurityEventType::SUSPICIOUS_FILE_DETECTED,
            L"",
            directoryPath,
            (report.overallRisk == FileRiskLevel::MALICIOUS) ? L"BLOCK" : L"ASK",
            L"[ALG5] " + report.summary + L" Top finding: " + report.findings.front().reason
        );
    }

    return report;
}

bool SuspiciousFileDetector::VerifySelfTest()
{
    std::wcout << L"  [5.1] Testing double-extension deception heuristic...\n";
    SuspiciousFileFinding f1;
    bool t1 = CheckDoubleExtension(L"invoice.pdf.exe", f1);
    bool t1Clean = !CheckDoubleExtension(L"normal_document.pdf", f1);
    std::wcout << L"        invoice.pdf.exe -> " << (t1 ? L"DETECTED [OK]" : L"FAILED") << L"\n";
    std::wcout << L"        normal_document.pdf -> " << (t1Clean ? L"CLEAN [OK]" : L"FAILED") << L"\n";

    std::wcout << L"  [5.2] Testing magic byte disguised executable check...\n";
    // Create temporary mock files in scratch/temp directory
    std::wstring tempDir = L"C:\\USBIPS_Test_Inspect";
    std::filesystem::create_directories(tempDir);

    // Mock disguised PE with MZ header
    std::wstring disguisedFile = tempDir + L"\\fake_image.jpg";
    {
        std::ofstream out(disguisedFile, std::ios::binary);
        out << "MZ" << "TestExecutableBytesFollowHere";
        out.close();
    }

    SuspiciousFileFinding f2;
    bool t2 = CheckDisguisedExecutable(disguisedFile, f2);
    std::wcout << L"        fake_image.jpg (MZ header) -> " << (t2 ? L"DETECTED [OK]" : L"FAILED") << L"\n";

    std::wcout << L"  [5.3] Testing autorun.inf execution parser...\n";
    std::wstring autorunFile = tempDir + L"\\autorun.inf";
    {
        std::ofstream out(autorunFile);
        out << "[AutoRun]\nopen=malware.exe\naction=Open drive\n";
        out.close();
    }
    SuspiciousFileFinding f3;
    bool t3 = CheckAutorunInf(autorunFile, f3);
    std::wcout << L"        autorun.inf (open= directive) -> " << (t3 ? L"DETECTED [OK]" : L"FAILED") << L"\n";

    // Directory batch inspection
    FileInspectionReport rep = InspectDirectory(tempDir);
    bool tBatch = (rep.overallRisk == FileRiskLevel::MALICIOUS && rep.findings.size() >= 2);
    std::wcout << L"  [5.4] Directory heuristic aggregation: " << FileRiskLevelToString(rep.overallRisk)
               << L" (" << rep.findings.size() << L" findings) " << (tBatch ? L"[OK]" : L"[FAILED]") << L"\n";

    // Clean up temporary files
    try {
        std::filesystem::remove_all(tempDir);
    } catch (...) {}

    return (t1 && t1Clean && t2 && t3 && tBatch);
}
