#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <mutex>
#include <chrono>

#include "../Models/USBDevice.h"
#include "../Models/SecurityEvent.h"
#include "../Allowlist/AllowlistManager.h"
#include "MalwareScanner.h"
#include "SuspiciousFileDetector.h"
#include "DataExfiltrationMonitor.h"
#include "HIDBehaviorMonitor.h"
#include "StorageExecutionMonitor.h"

enum class AssessmentStatus
{
    PASS,
    SUSPICIOUS,
    FAIL,
    NOT_APPLICABLE,
    NOT_ASSESSED
};

inline const wchar_t* AssessmentStatusToString(AssessmentStatus status)
{
    switch (status)
    {
    case AssessmentStatus::PASS:
        return L"PASS";
    case AssessmentStatus::SUSPICIOUS:
        return L"SUSPICIOUS";
    case AssessmentStatus::FAIL:
        return L"FAIL";
    case AssessmentStatus::NOT_APPLICABLE:
        return L"NOT_APPLICABLE";
    case AssessmentStatus::NOT_ASSESSED:
        return L"NOT_ASSESSED";
    default:
        return L"UNKNOWN";
    }
}

enum class TrustRecommendation
{
    APPROVE,
    REVIEW,
    REJECT
};

inline const wchar_t* TrustRecommendationToString(TrustRecommendation rec)
{
    switch (rec)
    {
    case TrustRecommendation::APPROVE:
        return L"APPROVE";
    case TrustRecommendation::REVIEW:
        return L"REVIEW";
    case TrustRecommendation::REJECT:
        return L"REJECT";
    default:
        return L"REVIEW";
    }
}

enum class RiskSeverity
{
    LOW,        // 0-25
    MEDIUM,     // 26-50
    HIGH,       // 51-75
    CRITICAL    // 76-100
};

inline const wchar_t* RiskSeverityToString(RiskSeverity sev)
{
    switch (sev)
    {
    case RiskSeverity::LOW:
        return L"LOW";
    case RiskSeverity::MEDIUM:
        return L"MEDIUM";
    case RiskSeverity::HIGH:
        return L"HIGH";
    case RiskSeverity::CRITICAL:
        return L"CRITICAL";
    default:
        return L"UNKNOWN";
    }
}

struct ModuleAssessment
{
    std::wstring moduleId;    // "A1" through "A10"
    std::wstring moduleName;  // "Fingerprinting", "CompositeDetection", etc.
    AssessmentStatus status = AssessmentStatus::NOT_ASSESSED;
    int riskWeight = 0;       // Points added to risk score
    std::wstring evidence;    // Factual, timestamped observation
    std::wstring timestamp;
    bool isCritical = false;  // FAIL triggers critical denial
};

struct TrustAssessmentReport
{
    std::wstring deviceId;
    std::wstring vendorId;
    std::wstring productId;
    std::wstring serialNumber;
    std::wstring deviceType;
    std::wstring sessionId;

    // Distinct evidence categories
    bool deviceIdentityMatch = false;               // A1: Triplet match
    bool adminAuthorized = false;                   // A9: Explicit admin allowlist
    std::wstring malwareScanResult = L"NOT_SCANNED";// A4: CLEAN, DETECTED, FAILED, UNAVAILABLE, NOT_SCANNED
    std::wstring executablePolicyStatus = L"COMPLIANT"; // COMPLIANT, PROHIBITED_EXE_DETECTED, BLOCKED
    std::wstring exactThreatFile;
    std::wstring exactThreatEvidence;
    int behavioralRiskScore = 0;                    // A3, A6, A7, A8
    std::wstring actualWindowsEnforcement = L"PENDING"; // SUCCESS, CR_ACCESS_DENIED, CR_NOT_DISABLEABLE, APP_ZERO_TRUST_LOCK
    HIDVerificationResult hidVerification;          // Stage B-D verification evidence

    USBDevice originalDevice;

    int totalRiskScore = 0;                         // 0-100
    RiskSeverity severity = RiskSeverity::LOW;
    TrustRecommendation recommendation = TrustRecommendation::REVIEW;

    std::vector<std::wstring> criticalViolations;
    std::vector<std::wstring> explainableReasons;
    std::map<std::wstring, ModuleAssessment> moduleResults; // ModuleId -> assessment
    std::wstring summary;
    std::wstring timestamp;
};

class TrustAssessmentEngine
{
public:
    static TrustAssessmentEngine& Instance();

    void SetAllowlistManager(AllowlistManager* allowlist);
    AllowlistManager* GetAllowlistManager() const;

    // Comprehensive initial trust assessment upon device arrival
    TrustAssessmentReport AssessDevice(
        const USBDevice& device,
        AllowlistManager& allowlist,
        const std::wstring& mountedVolumePath = L"",
        const HIDVerificationResult& hidVerification = HIDVerificationResult{},
        const std::wstring& sessionId = L""
    );

    std::wstring SerializeAlgorithmsJson(const TrustAssessmentReport& report) const;

    // Updates active assessment when storage media scan completes
    void UpdateMalwareScanResult(
        const USBDevice& device,
        const ScanResult& scanResult
    );

    // Updates active assessment when executable policy inspection completes
    void UpdateExecutablePolicyResult(
        const USBDevice& device,
        const StorageExecutableInspectionResult& inspectionResult
    );

    // Dynamic re-evaluation when runtime security events occur (post-approval surveillance)
    void UpdateAssessmentWithEvent(
        TrustAssessmentReport& report,
        const SecurityEvent& event
    );

    void UpdateAssessmentWithEvent(
        const std::wstring& deviceId,
        SecurityEventType type,
        const std::wstring& reason
    );

    void UpdateAssessmentWithEvent(
        const USBDevice& device,
        SecurityEventType type,
        const std::wstring& reason
    );

    bool GetActiveAssessment(
        const std::wstring& deviceId,
        TrustAssessmentReport& outReport
    ) const;

    // Rule & Scoring self-test harness (testing boundaries, edge cases, critical denials)
    bool VerifySelfTest();

private:
    TrustAssessmentEngine() = default;
    ~TrustAssessmentEngine() = default;

    TrustAssessmentEngine(const TrustAssessmentEngine&) = delete;
    TrustAssessmentEngine& operator=(const TrustAssessmentEngine&) = delete;

    std::wstring GetCurrentUtcTimestamp() const;
    void FinalizeReport(TrustAssessmentReport& report);
    void InternalUpdateAssessmentWithEvent(TrustAssessmentReport& report, const SecurityEvent& event);

private:
    mutable std::mutex m_mutex;
    AllowlistManager* m_allowlist = nullptr;
    std::unordered_map<std::wstring, TrustAssessmentReport> m_activeReports;
};
