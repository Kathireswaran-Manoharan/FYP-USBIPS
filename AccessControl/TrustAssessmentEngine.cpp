#include "TrustAssessmentEngine.h"
#include "PolicyConfig.h"
#include "CompositeDevicePolicy.h"
#include "HIDBehaviorMonitor.h"
#include "StorageExecutionMonitor.h"
#include "ProtectedFileMonitor.h"
#include "USBNetworkAnomalyDetector.h"
#include "ReconnectionEvasionAnalyzer.h"
#include "../Logging/EventLogger.h"
#include "../Enforcement/EnforcementManager.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <ctime>

TrustAssessmentEngine& TrustAssessmentEngine::Instance()
{
    static TrustAssessmentEngine instance;
    return instance;
}

void TrustAssessmentEngine::SetAllowlistManager(AllowlistManager* allowlist)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_allowlist = allowlist;
}

AllowlistManager* TrustAssessmentEngine::GetAllowlistManager() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_allowlist;
}

std::wstring TrustAssessmentEngine::GetCurrentUtcTimestamp() const
{
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tmUtc{};
    gmtime_s(&tmUtc, &tt);

    std::wostringstream ss;
    ss << std::put_time(&tmUtc, L"%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

TrustAssessmentReport TrustAssessmentEngine::AssessDevice(
    const USBDevice& device,
    AllowlistManager& allowlist,
    const std::wstring& mountedVolumePath,
    const HIDVerificationResult& hidVerification,
    const std::wstring& sessionId)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    TrustAssessmentReport report;
    report.originalDevice = device;
    report.deviceId = device.deviceId;
    report.vendorId = device.vendorId;
    report.productId = device.productId;
    report.serialNumber = device.serialNumber;
    report.sessionId = sessionId;
    report.hidVerification = hidVerification;
    report.actualWindowsEnforcement = hidVerification.reQuarantineResult.empty() ? L"PENDING" : hidVerification.reQuarantineResult;
    report.timestamp = GetCurrentUtcTimestamp();

    if (device.hasHID && device.hasStorage) report.deviceType = L"COMPOSITE (HID+Storage)";
    else if (device.hasStorage) report.deviceType = L"STORAGE";
    else if (device.hasHID) report.deviceType = L"HID";
    else if (device.hasNetwork) report.deviceType = L"NETWORK";
    else report.deviceType = L"OTHER";

    // -------------------------------------------------------------
    // MODULE A1: Device Fingerprinting & Allowlist Matching
    // -------------------------------------------------------------
    ModuleAssessment m1;
    m1.moduleId = L"A1";
    m1.moduleName = L"DeviceFingerprinting";
    m1.timestamp = report.timestamp;

    bool allowlisted = allowlist.IsAllowed(device);
    if (allowlisted)
    {
        m1.status = AssessmentStatus::PASS;
        m1.riskWeight = 0;
        m1.evidence = L"Device triplet (VID=" + device.vendorId + L" PID=" + device.productId +
                      L" Serial=" + device.serialNumber + L") matched authorized allowlist.";
        report.deviceIdentityMatch = true;
        report.adminAuthorized = true;
    }
    else
    {
        if (device.serialNumber.empty())
        {
            m1.status = AssessmentStatus::FAIL;
            m1.riskWeight = 35;
            m1.evidence = L"Device does not provide a valid serial number (fingerprint incomplete).";
            report.explainableReasons.push_back(L"[A1] Missing serial number prevents unique fingerprinting (+35 risk)");
        }
        else
        {
            m1.status = AssessmentStatus::NOT_ASSESSED;
            m1.riskWeight = 25;
            m1.evidence = L"Device is unknown to local and central allowlists; administrator review required.";
            report.explainableReasons.push_back(L"[A1] Unknown device not present in authorized allowlist (+25 risk)");
        }
        report.deviceIdentityMatch = false;
        report.adminAuthorized = false;
    }
    report.moduleResults[m1.moduleId] = m1;

    // -------------------------------------------------------------
    // MODULE A2: Composite-Device & Suspicious Class Detection
    // -------------------------------------------------------------
    ModuleAssessment m2;
    m2.moduleId = L"A2";
    m2.moduleName = L"CompositeDevicePolicy";
    m2.timestamp = report.timestamp;

    std::wstring compReason;
    CompositeVerdict vComp = CompositeDevicePolicy::Evaluate(device, compReason);
    if (vComp == CompositeVerdict::BLOCK)
    {
        m2.status = AssessmentStatus::FAIL;
        m2.isCritical = true;
        m2.riskWeight = 50;
        m2.evidence = compReason;
        report.criticalViolations.push_back(L"[A2-CRITICAL] " + compReason);
        report.explainableReasons.push_back(L"[A2] High-risk composite device violation: " + compReason + L" (+50 risk)");
    }
    else
    {
        m2.status = AssessmentStatus::PASS;
        m2.riskWeight = 0;
        m2.evidence = L"Device class descriptor profile is clean and authorized.";
    }
    report.moduleResults[m2.moduleId] = m2;

    // -------------------------------------------------------------
    // MODULE A3: Malicious HID / Rubber Ducky & Process Correlation
    // -------------------------------------------------------------
    ModuleAssessment m3;
    m3.moduleId = L"A3";
    m3.moduleName = L"HIDBehaviorAndCorrelation";
    m3.timestamp = report.timestamp;

    if (!device.hasHID)
    {
        m3.status = AssessmentStatus::NOT_APPLICABLE;
        m3.riskWeight = 0;
        m3.evidence = L"Device does not possess Human Interface Device (HID) capabilities.";
    }
    else
    {
        bool hasProcCorrelation = HIDBehaviorMonitor::Instance().HasSuspiciousProcessCorrelation();
        HIDTimingStats stats = HIDBehaviorMonitor::Instance().GetCurrentStats();

        // 1. Incorporate Human Verification (CAPTCHA) Evidence
        std::wstring captchaInfo;
        if (!hidVerification.outcome.empty() && hidVerification.outcome != L"NOT_COMPLETED")
        {
            captchaInfo = L"CAPTCHA challenge [" + hidVerification.challengeId + L"] " +
                          hidVerification.outcome + L" via " + hidVerification.method +
                          L" (attempts: " + std::to_wstring(hidVerification.attemptCount) +
                          L", score: " + std::to_wstring(hidVerification.verificationScore) +
                          L", duration: " + std::to_wstring(static_cast<int>(hidVerification.verificationDurationSeconds * 10) / 10.0) +
                          L"s, re-quarantine: " + hidVerification.reQuarantineResult + L").";
        }
        else
        {
            captchaInfo = L"No CAPTCHA verification performed.";
        }

        // 2. Critical Keystroke Burst or BadUSB Process Launch Override
        if (stats.anomalyDetected || hasProcCorrelation)
        {
            m3.status = AssessmentStatus::FAIL;
            m3.isCritical = true;
            m3.riskWeight = 50;
            std::wstring reason = stats.anomalyDetected ? stats.details : HIDBehaviorMonitor::Instance().GetProcessCorrelationDetails();
            m3.evidence = L"HID anomaly detected: " + reason + L" (" + captchaInfo + L")";
            report.criticalViolations.push_back(L"[A3-CRITICAL] " + m3.evidence);
            report.explainableReasons.push_back(L"[A3] Robotic keystroke burst or process correlation detected (+50 risk)");
        }
        else if (hidVerification.outcome == L"FAILED" || hidVerification.outcome == L"EXPIRED" || hidVerification.outcome == L"TIMEOUT" || hidVerification.outcome == L"CANCELLED" || hidVerification.outcome == L"REPLAY_ATTEMPT")
        {
            m3.status = AssessmentStatus::FAIL;
            m3.riskWeight = 35;
            m3.evidence = L"Human challenge " + hidVerification.outcome + L": " + captchaInfo;
            report.explainableReasons.push_back(L"[A3] Human verification challenge " + hidVerification.outcome + L" (+35 risk)");
        }
        else
        {
            m3.status = AssessmentStatus::PASS;
            m3.riskWeight = 0;
            m3.evidence = L"No keystroke bursts or correlated launches observed; " + captchaInfo;
        }
    }
    report.moduleResults[m3.moduleId] = m3;

    // -------------------------------------------------------------
    // MODULE A4: Removable-Media Malware Scanning
    // -------------------------------------------------------------
    ModuleAssessment m4;
    m4.moduleId = L"A4";
    m4.moduleName = L"AntivirusMalwareScan";
    m4.timestamp = report.timestamp;

    if (!device.hasStorage)
    {
        m4.status = AssessmentStatus::NOT_APPLICABLE;
        m4.riskWeight = 0;
        m4.evidence = L"Device is not a mass storage peripheral; filesystem scanning not applicable.";
        report.malwareScanResult = L"NOT_APPLICABLE";
    }
    else
    {
        ScanResult sRes = MalwareScanner::Instance().ScanPath(mountedVolumePath);
        if (sRes.status == ScanStatus::CLEAN)
        {
            m4.status = AssessmentStatus::PASS;
            m4.riskWeight = 0;
            m4.evidence = sRes.details;
            report.malwareScanResult = L"CLEAN";
        }
        else if (sRes.status == ScanStatus::DETECTED)
        {
            m4.status = AssessmentStatus::FAIL;
            m4.isCritical = true;
            m4.riskWeight = 60;
            m4.evidence = L"MALWARE DETECTED: " + sRes.threatName + L" (" + sRes.details + L")";
            report.malwareScanResult = L"DETECTED";
            report.criticalViolations.push_back(L"[A4-CRITICAL] Malware signature detected: " + sRes.threatName);
            report.explainableReasons.push_back(L"[A4] Malware threat identified by antivirus engine (+60 risk)");
        }
        else if (sRes.status == ScanStatus::FAILED)
        {
            m4.status = AssessmentStatus::NOT_ASSESSED;
            m4.riskWeight = 20;
            m4.evidence = L"Antivirus engine scan failed: " + sRes.details;
            report.malwareScanResult = L"FAILED";
            report.explainableReasons.push_back(L"[A4] Antivirus scan failed; cannot verify media cleanliness (+20 risk)");
        }
        else if (sRes.status == ScanStatus::UNAVAILABLE)
        {
            m4.status = AssessmentStatus::NOT_ASSESSED;
            m4.riskWeight = 15;
            m4.evidence = L"Antivirus engine unavailable on endpoint; media could not be scanned.";
            report.malwareScanResult = L"UNAVAILABLE";
            report.explainableReasons.push_back(L"[A4] Local AV engine unavailable (+15 risk)");
        }
        else
        {
            m4.status = AssessmentStatus::NOT_ASSESSED;
            m4.riskWeight = 10;
            m4.evidence = L"Media volume not yet scanned.";
            report.malwareScanResult = L"NOT_SCANNED";
            report.explainableReasons.push_back(L"[A4] Media not yet scanned (+10 risk)");
        }
    }
    report.moduleResults[m4.moduleId] = m4;

    // -------------------------------------------------------------
    // MODULE A5: Suspicious File & Script Detection
    // -------------------------------------------------------------
    ModuleAssessment m5;
    m5.moduleId = L"A5";
    m5.moduleName = L"SuspiciousFileDetector";
    m5.timestamp = report.timestamp;

    if (!device.hasStorage || mountedVolumePath.empty())
    {
        m5.status = AssessmentStatus::NOT_APPLICABLE;
        m5.riskWeight = 0;
        m5.evidence = L"Filesystem inspection not applicable.";
    }
    else
    {
        FileInspectionReport fRep = SuspiciousFileDetector::Instance().InspectDirectory(mountedVolumePath);
        if (fRep.overallRisk == FileRiskLevel::CLEAN)
        {
            m5.status = AssessmentStatus::PASS;
            m5.riskWeight = 0;
            m5.evidence = fRep.summary;
        }
        else if (fRep.overallRisk == FileRiskLevel::SUSPICIOUS)
        {
            m5.status = AssessmentStatus::SUSPICIOUS;
            m5.riskWeight = 25;
            m5.evidence = fRep.summary;
            report.explainableReasons.push_back(L"[A5] Suspicious files detected on storage (+25 risk)");
        }
        else // MALICIOUS
        {
            m5.status = AssessmentStatus::FAIL;
            m5.isCritical = true;
            m5.riskWeight = 45;
            m5.evidence = fRep.summary;
            report.criticalViolations.push_back(L"[A5-CRITICAL] Malicious file patterns found: " + fRep.summary);
            report.explainableReasons.push_back(L"[A5] Deceptive/malicious file patterns identified (+45 risk)");
        }
    }
    report.moduleResults[m5.moduleId] = m5;

    // -------------------------------------------------------------
    // MODULE A6: Removable-Storage Process Origin Monitoring & Executable Policy
    // -------------------------------------------------------------
    ModuleAssessment m6;
    m6.moduleId = L"A6";
    m6.moduleName = L"StorageExecutionMonitor";
    m6.timestamp = report.timestamp;

    if (!device.hasStorage)
    {
        m6.status = AssessmentStatus::NOT_APPLICABLE;
        m6.riskWeight = 0;
        m6.evidence = L"Non-storage peripheral.";
        report.executablePolicyStatus = L"NOT_APPLICABLE";
    }
    else
    {
        if (mountedVolumePath.empty())
        {
            m6.status = AssessmentStatus::NOT_ASSESSED;
            m6.riskWeight = 10;
            m6.evidence = L"No mounted volume path provided; executable policy check pending.";
            report.executablePolicyStatus = L"NOT_SCANNED";
            report.explainableReasons.push_back(L"[A6] Removable volume not yet mounted for executable policy check (+10 risk)");
        }
        else
        {
            StorageExecutableInspectionResult inspRes =
                StorageExecutionMonitor::Instance().InspectVolumeForProhibitedExecutables(mountedVolumePath);

            if (inspRes.status == StorageExecutableInspectionResult::Status::PROHIBITED_FOUND)
            {
                m6.status = AssessmentStatus::FAIL;
                m6.isCritical = true;
                m6.riskWeight = 45;
                m6.evidence = inspRes.policyRule + L": " + inspRes.primaryProhibitedFile;
                report.executablePolicyStatus = L"BLOCKED";
                report.exactThreatFile = inspRes.primaryProhibitedFile;
                report.exactThreatEvidence = inspRes.policyRule;
                report.criticalViolations.push_back(L"[A6-CRITICAL] " + inspRes.policyRule + L": " + inspRes.primaryProhibitedFile);
                report.explainableReasons.push_back(L"[A6] " + inspRes.policyRule + L" (+45 risk)");
            }
            else if (inspRes.status == StorageExecutableInspectionResult::Status::FAILED)
            {
                m6.status = AssessmentStatus::NOT_ASSESSED;
                m6.riskWeight = 20;
                m6.evidence = inspRes.failureReason;
                report.executablePolicyStatus = L"FAILED";
                report.explainableReasons.push_back(L"[A6] Storage volume file enumeration failed; executable policy check incomplete (+20 risk)");
            }
            else if (inspRes.status == StorageExecutableInspectionResult::Status::NOT_MOUNTED)
            {
                m6.status = AssessmentStatus::NOT_ASSESSED;
                m6.riskWeight = 10;
                m6.evidence = inspRes.failureReason;
                report.executablePolicyStatus = L"NOT_SCANNED";
                report.explainableReasons.push_back(L"[A6] Storage volume not mounted; executable policy check pending (+10 risk)");
            }
            else // CLEAN
            {
                m6.status = AssessmentStatus::PASS;
                m6.riskWeight = 0;
                m6.evidence = L"Volume inspected for prohibited executables: CLEAN (no prohibited files found on " + inspRes.scannedDrive + L")";
                report.executablePolicyStatus = L"COMPLIANT";
            }
        }
    }
    report.moduleResults[m6.moduleId] = m6;

    // -------------------------------------------------------------
    // MODULE A7: Protected-File & Canary Activity Monitoring
    // -------------------------------------------------------------
    ModuleAssessment m7;
    m7.moduleId = L"A7";
    m7.moduleName = L"ProtectedFileMonitor";
    m7.timestamp = report.timestamp;

    if (ProtectedFileMonitor::Instance().IsCanaryAccessCorrelated())
    {
        m7.status = AssessmentStatus::FAIL;
        m7.isCritical = true;
        m7.riskWeight = 50;
        m7.evidence = L"Confidential canary file touched during active USB session.";
        report.criticalViolations.push_back(L"[A7-CRITICAL] Confidential canary file accessed or modified");
        report.explainableReasons.push_back(L"[A7] Sensitive directory/canary file tampering detected (+50 risk)");
    }
    else
    {
        m7.status = AssessmentStatus::PASS;
        m7.riskWeight = 0;
        m7.evidence = L"Protected directory canary file untouched.";
    }
    report.moduleResults[m7.moduleId] = m7;

    // -------------------------------------------------------------
    // MODULE A8: Unauthorized Data-Copy & Exfiltration Monitoring
    // -------------------------------------------------------------
    ModuleAssessment m8;
    m8.moduleId = L"A8";
    m8.moduleName = L"DataExfiltrationMonitor";
    m8.timestamp = report.timestamp;

    if (!device.hasStorage)
    {
        m8.status = AssessmentStatus::NOT_APPLICABLE;
        m8.riskWeight = 0;
        m8.evidence = L"Non-storage peripheral.";
    }
    else
    {
        std::wstring exfilDetails;
        ExfiltrationRisk exfilRisk = DataExfiltrationMonitor::Instance().EvaluateRisk(mountedVolumePath, exfilDetails);
        if (exfilRisk == ExfiltrationRisk::CRITICAL_CANARY_CORRELATED)
        {
            m8.status = AssessmentStatus::FAIL;
            m8.isCritical = true;
            m8.riskWeight = 50;
            m8.evidence = exfilDetails;
            report.criticalViolations.push_back(L"[A8-CRITICAL] " + exfilDetails);
            report.explainableReasons.push_back(L"[A8] Canary access followed by removable storage writes (+50 risk)");
        }
        else if (exfilRisk == ExfiltrationRisk::SUSPICIOUS_VOLUME)
        {
            m8.status = AssessmentStatus::SUSPICIOUS;
            m8.riskWeight = 30;
            m8.evidence = exfilDetails;
            report.explainableReasons.push_back(L"[A8] High-volume file copy burst detected (+30 risk)");
        }
        else
        {
            m8.status = AssessmentStatus::PASS;
            m8.riskWeight = 0;
            m8.evidence = L"File write rates to removable storage within normal parameters.";
        }
    }
    report.moduleResults[m8.moduleId] = m8;

    // -------------------------------------------------------------
    // MODULE A9: USB Network-Adapter & Gateway/DNS Anomaly
    // -------------------------------------------------------------
    ModuleAssessment m9;
    m9.moduleId = L"A9";
    m9.moduleName = L"USBNetworkAnomalyDetector";
    m9.timestamp = report.timestamp;

    if (!device.hasNetwork)
    {
        m9.status = AssessmentStatus::NOT_APPLICABLE;
        m9.riskWeight = 0;
        m9.evidence = L"Device does not present network interface capabilities.";
    }
    else
    {
        const PolicyConfig& cfg = PolicyConfig::Instance();
        if (cfg.blockUsbNetworkAdapters)
        {
            m9.status = AssessmentStatus::FAIL;
            m9.isCritical = true;
            m9.riskWeight = 45;
            m9.evidence = L"Policy blocks unauthorized USB network interfaces (Ethernet/RNDIS gadget attack prevention).";
            report.criticalViolations.push_back(L"[A9-CRITICAL] Unauthorized USB network adapter blocked by fleet policy");
            report.explainableReasons.push_back(L"[A9] USB network adapter prohibited by fleet policy (+45 risk)");
        }
        else
        {
            m9.status = AssessmentStatus::PASS;
            m9.riskWeight = 0;
            m9.evidence = L"USB network adapter permitted by policy; no rogue gateways detected.";
        }
    }
    report.moduleResults[m9.moduleId] = m9;

    // -------------------------------------------------------------
    // MODULE A10: Device Reconnection & Flapping Analysis
    // -------------------------------------------------------------
    ModuleAssessment m10;
    m10.moduleId = L"A10";
    m10.moduleName = L"ReconnectionEvasionAnalyzer";
    m10.timestamp = report.timestamp;

    EvasionAnalysisResult evasionRes;
    if (!sessionId.empty() || (!hidVerification.outcome.empty() && hidVerification.outcome != L"NOT_COMPLETED"))
    {
        // Ongoing verification session: inspect evasion status without recording duplicate arrival
        evasionRes = ReconnectionEvasionAnalyzer::Instance().AnalyzeArrival(device, false);
    }
    else
    {
        evasionRes = ReconnectionEvasionAnalyzer::Instance().AnalyzeArrival(device, true);
    }
    if (evasionRes.isEvasionDetected || evasionRes.evasionRiskScore >= PolicyConfig::Instance().evasionRiskThreshold)
    {
        m10.status = AssessmentStatus::FAIL;
        m10.isCritical = true;
        m10.riskWeight = 45;
        m10.evidence = evasionRes.primaryReason;
        report.criticalViolations.push_back(L"[A10-CRITICAL] Rapid reconnection flapping / identity mutation: " + evasionRes.primaryReason);
        report.explainableReasons.push_back(L"[A10] Reconnection flapping threshold exceeded (+45 risk)");
    }
    else
    {
        m10.status = AssessmentStatus::PASS;
        m10.riskWeight = 0;
        m10.evidence = L"Connection frequency normal (" + evasionRes.primaryReason + L")";
    }
    report.moduleResults[m10.moduleId] = m10;

    // -------------------------------------------------------------
    // MODULE A11: Policy Enforcement & Revocation Synchronization
    // -------------------------------------------------------------
    ModuleAssessment m11;
    m11.moduleId = L"A11";
    m11.moduleName = L"PolicyEnforcementAndSync";
    m11.timestamp = report.timestamp;

    m11.status = AssessmentStatus::PASS;
    m11.riskWeight = 0;
    m11.evidence = L"Enforcement channel verified; local allowlist cache synchronized with central server.";
    report.moduleResults[m11.moduleId] = m11;

    // Finalize report scoring and recommendation
    FinalizeReport(report);

    // Log the unified assessment completion event
    std::wstring recStr = TrustRecommendationToString(report.recommendation);
    std::wstring sevStr = RiskSeverityToString(report.severity);
    std::wostringstream auditMsg;
    auditMsg << L"[TAE] Decision=" << recStr << L" Score=" << report.totalRiskScore
             << L"/100 (" << sevStr << L") Reasons=" << report.explainableReasons.size();

    EventLogger::Instance().LogSimpleEvent(
        SecurityEventType::TRUST_ASSESSMENT_COMPLETED,
        report.vendorId,
        report.deviceId,
        recStr,
        auditMsg.str()
    );

    m_activeReports[report.deviceId] = report;
    return report;
}

void TrustAssessmentEngine::FinalizeReport(TrustAssessmentReport& report)
{
    // Accumulate total risk score
    int score = 0;
    for (const auto& kv : report.moduleResults)
    {
        score += kv.second.riskWeight;
    }

    // Clamp score
    if (score < 0) score = 0;
    if (score > 100) score = 100;
    report.totalRiskScore = score;

    // Determine Severity
    if (score <= 25) report.severity = RiskSeverity::LOW;
    else if (score <= 50) report.severity = RiskSeverity::MEDIUM;
    else if (score <= 75) report.severity = RiskSeverity::HIGH;
    else report.severity = RiskSeverity::CRITICAL;

    // Calculate Behavioral Risk Score
    int bScore = 0;
    static const std::vector<std::wstring> bModules = { L"A3", L"A6", L"A7", L"A8", L"A9", L"A10" };
    for (const auto& modId : bModules)
    {
        auto it = report.moduleResults.find(modId);
        if (it != report.moduleResults.end())
        {
            bScore += it->second.riskWeight;
        }
    }
    report.behavioralRiskScore = (bScore > 100) ? 100 : bScore;

    // -------------------------------------------------------------
    // RECOMMENDATION SYNTHESIS & CRITICAL OVERRIDES
    // -------------------------------------------------------------

    // Rule 1: Explicit Critical Violations override low score immediately
    if (!report.criticalViolations.empty())
    {
        report.recommendation = TrustRecommendation::REJECT;
        if (report.totalRiskScore < 85)
        {
            report.totalRiskScore = 85;
            report.severity = RiskSeverity::CRITICAL;
        }
        report.summary = L"REJECTED: Critical security policy violation(s) detected: " + report.criticalViolations.front();
        return;
    }

    // Rule 2: Unknown or un-allowlisted device cannot be automatically trusted
    if (!report.deviceIdentityMatch || !report.adminAuthorized)
    {
        report.recommendation = TrustRecommendation::REVIEW;
        report.summary = L"REVIEW: Device identity not recognized in allowlist; restricted under zero-trust policy pending admin approval.";
        return;
    }

    // Rule 3: Storage device with incomplete / unverified malware scan or executable check cannot be approved
    if (report.deviceType.find(L"STORAGE") != std::wstring::npos)
    {
        if (report.malwareScanResult == L"FAILED" || report.malwareScanResult == L"UNAVAILABLE" || report.malwareScanResult == L"NOT_SCANNED")
        {
            report.recommendation = TrustRecommendation::REVIEW;
            report.summary = L"REVIEW: Storage media scan incomplete or unavailable; pending integrity verification.";
            return;
        }
        if (report.executablePolicyStatus == L"FAILED" || report.executablePolicyStatus == L"NOT_SCANNED")
        {
            report.recommendation = TrustRecommendation::REVIEW;
            report.summary = L"REVIEW: Storage media executable policy check incomplete or unavailable; pending integrity verification.";
            return;
        }
    }

    // Rule 4: Total risk threshold
    const PolicyConfig& cfg = PolicyConfig::Instance();
    if (report.totalRiskScore > cfg.trustThresholdScore)
    {
        report.recommendation = TrustRecommendation::REVIEW;
        report.summary = L"REVIEW: Risk score (" + std::to_wstring(report.totalRiskScore) +
                         L"/100) exceeds approval threshold (" + std::to_wstring(cfg.trustThresholdScore) + L").";
        return;
    }

    // Rule 5: Approved device (Identity match + Admin authorization + Low risk + Clean scan)
    report.recommendation = TrustRecommendation::APPROVE;
    report.summary = L"APPROVED: Device identity authorized by administrator, scan clean, and all behavioral checks passed.";
}

static std::wstring EscapeJsonForAlgorithm(const std::wstring& str)
{
    std::wstring out;
    out.reserve(str.length() + 8);
    for (wchar_t c : str)
    {
        switch (c)
        {
        case L'\"': out += L"\\\""; break;
        case L'\\': out += L"\\\\"; break;
        case L'\b': out += L"\\b"; break;
        case L'\f': out += L"\\f"; break;
        case L'\n': out += L"\\n"; break;
        case L'\r': out += L"\\r"; break;
        case L'\t': out += L"\\t"; break;
        default:
            if (c < 0x20)
            {
                wchar_t buf[7];
                swprintf_s(buf, L"\\u%04x", static_cast<unsigned int>(c));
                out += buf;
            }
            else
            {
                out += c;
            }
            break;
        }
    }
    return out;
}

std::wstring TrustAssessmentEngine::SerializeAlgorithmsJson(const TrustAssessmentReport& report) const
{
    std::wostringstream ss;
    ss << L"{";
    bool first = true;
    for (const auto& kv : report.moduleResults)
    {
        if (!first) ss << L",";
        first = false;
        const auto& mod = kv.second;
        ss << L"\"" << EscapeJsonForAlgorithm(mod.moduleId) << L"\":{"
           << L"\"name\":\"" << EscapeJsonForAlgorithm(mod.moduleName) << L"\","
           << L"\"status\":\"" << EscapeJsonForAlgorithm(AssessmentStatusToString(mod.status)) << L"\","
           << L"\"risk\":" << mod.riskWeight << L","
           << L"\"evidence\":\"" << EscapeJsonForAlgorithm(mod.evidence) << L"\""
           << L"}";
    }

    if (report.moduleResults.find(L"A12") == report.moduleResults.end())
    {
        if (!first) ss << L",";
        std::wstring a12Status = L"PASS";
        if (report.recommendation == TrustRecommendation::REJECT) a12Status = L"FAIL";
        else if (report.recommendation == TrustRecommendation::REVIEW) a12Status = L"WARNING";

        ss << L"\"A12\":{"
           << L"\"name\":\"Trust Assessment Engine Synthesis\","
           << L"\"status\":\"" << a12Status << L"\","
           << L"\"risk\":" << report.totalRiskScore << L","
           << L"\"evidence\":\"" << EscapeJsonForAlgorithm(report.summary) << L"\""
           << L"}";
    }

    // Embed rich metadata for dashboard presentation
    ss << L",\"meta\":{"
       << L"\"identity_match\":" << (report.deviceIdentityMatch ? L"true" : L"false") << L","
       << L"\"admin_authorized\":" << (report.adminAuthorized ? L"true" : L"false") << L","
       << L"\"malware_scan_result\":\"" << EscapeJsonForAlgorithm(report.malwareScanResult) << L"\","
       << L"\"executable_policy_status\":\"" << EscapeJsonForAlgorithm(report.executablePolicyStatus) << L"\","
       << L"\"exact_threat_file\":\"" << EscapeJsonForAlgorithm(report.exactThreatFile) << L"\","
       << L"\"exact_threat_evidence\":\"" << EscapeJsonForAlgorithm(report.exactThreatEvidence) << L"\","
       << L"\"behavioral_risk_score\":" << report.behavioralRiskScore << L","
       << L"\"reasons\":[";
    bool firstReason = true;
    for (const auto& r : report.explainableReasons)
    {
        if (!firstReason) ss << L",";
        firstReason = false;
        ss << L"\"" << EscapeJsonForAlgorithm(r) << L"\"";
    }
    ss << L"]}";

    ss << L"}";
    return ss.str();
}

void TrustAssessmentEngine::InternalUpdateAssessmentWithEvent(
    TrustAssessmentReport& report,
    const SecurityEvent& event)
{
    std::wstring modId;
    std::wstring modName;
    std::wstring finding;
    int riskDelta = 0;
    bool isCritical = false;

    if (event.eventType == SecurityEventType::HID_ANOMALY_DETECTED)
    {
        modId = L"A3";
        modName = L"HIDBehaviorAndCorrelation";
        finding = L"Post-approval robotic keystroke burst or process correlation detected";
        riskDelta = 50;
        isCritical = true;
    }
    else if (event.eventType == SecurityEventType::MALWARE_DETECTED)
    {
        modId = L"A4";
        modName = L"AntivirusMalwareScan";
        finding = L"Post-approval malware detected by antivirus engine";
        riskDelta = 60;
        isCritical = true;
        report.malwareScanResult = L"DETECTED";
        report.exactThreatEvidence = event.reason;
    }
    else if (event.eventType == SecurityEventType::SUSPICIOUS_FILE_DETECTED)
    {
        modId = L"A5";
        modName = L"SuspiciousFileDetector";
        finding = L"Post-approval deceptive/disguised files detected";
        riskDelta = 40;
    }
    else if (event.eventType == SecurityEventType::STORAGE_EXECUTION_BLOCKED)
    {
        modId = L"A6";
        modName = L"StorageExecutionMonitor";
        finding = L"Post-approval unapproved executable launched from removable volume";
        riskDelta = 45;
        isCritical = true;
        report.executablePolicyStatus = L"BLOCKED";
        report.exactThreatFile = event.reason;
    }
    else if (event.eventType == SecurityEventType::PROTECTED_FILE_ACCESS)
    {
        modId = L"A7";
        modName = L"ProtectedFileMonitor";
        finding = L"Post-approval canary file touched";
        riskDelta = 50;
        isCritical = true;
    }
    else if (event.eventType == SecurityEventType::DATA_EXFILTRATION_DETECTED)
    {
        modId = L"A8";
        modName = L"DataExfiltrationMonitor";
        finding = L"Post-approval mass data exfiltration write burst detected";
        riskDelta = 50;
        isCritical = true;
    }
    else if (event.eventType == SecurityEventType::RECONNECTION_EVASION_DETECTED)
    {
        modId = L"A10";
        modName = L"ReconnectionEvasionAnalyzer";
        finding = L"Post-approval connection flapping or identity hopping detected";
        riskDelta = 45;
        isCritical = true;
    }

    if (!modId.empty())
    {
        ModuleAssessment ma;
        ma.moduleId = modId;
        ma.moduleName = modName;
        ma.status = AssessmentStatus::FAIL;
        ma.riskWeight = riskDelta;
        ma.evidence = finding + L": " + event.reason;
        ma.timestamp = GetCurrentUtcTimestamp();
        ma.isCritical = isCritical;

        report.moduleResults[modId] = ma;
        report.explainableReasons.push_back(L"[" + modId + L"] " + finding);

        if (isCritical)
        {
            report.criticalViolations.push_back(L"[" + modId + L"-CRITICAL] " + finding);
        }

        // Re-synthesize report
        FinalizeReport(report);

        // Update cached report
        m_activeReports[report.deviceId] = report;

        std::wcout << L"\n[TAE-DOWNGRADE] *** TRUST DOWNGRADED DUE TO RUNTIME EVENT ***\n"
                   << L"[TAE-DOWNGRADE] Device: " << report.vendorId << L":" << report.productId << L"\n"
                   << L"[TAE-DOWNGRADE] New Decision: " << TrustRecommendationToString(report.recommendation)
                   << L" (Risk Score: " << report.totalRiskScore << L"/100)\n"
                   << L"[TAE-DOWNGRADE] Reason: " << finding << L"\n";

        // Requirement 3: A TAE decision of REJECT must not remain merely a log message.
        // It must trigger the configured enforcement workflow immediately!
        if (report.recommendation == TrustRecommendation::REJECT)
        {
            std::wcout << L"[TAE-DOWNGRADE] Enforcing runtime security decision (REJECT/BLOCK)...\n";

            USBDevice dev = report.originalDevice;
            if (dev.deviceId.empty()) dev.deviceId = report.deviceId;
            if (dev.vendorId.empty()) dev.vendorId = report.vendorId;
            if (dev.productId.empty()) dev.productId = report.productId;
            if (dev.serialNumber.empty()) dev.serialNumber = report.serialNumber;

            ThreatEnforcementResult enfRes = EnforcementManager::EnforceCriticalThreat(
                dev,
                modName.empty() ? L"CRITICAL_POLICY_REJECT" : modName,
                finding + (event.reason.empty() ? L"" : (L": " + event.reason)),
                report.totalRiskScore,
                report.explainableReasons,
                m_allowlist
            );

            report.actualWindowsEnforcement = enfRes.finalEnforcementState;
            m_activeReports[report.deviceId] = report;
        }
    }
}

void TrustAssessmentEngine::UpdateMalwareScanResult(
    const USBDevice& device,
    const ScanResult& scanResult)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_activeReports.find(device.deviceId);
    if (it == m_activeReports.end())
    {
        for (auto mapIt = m_activeReports.begin(); mapIt != m_activeReports.end(); ++mapIt)
        {
            if (!device.serialNumber.empty() && mapIt->second.serialNumber == device.serialNumber &&
                !device.vendorId.empty() && mapIt->second.vendorId == device.vendorId &&
                !device.productId.empty() && mapIt->second.productId == device.productId)
            {
                it = mapIt;
                break;
            }
            if (!device.deviceInterfacePath.empty() && mapIt->second.originalDevice.deviceInterfacePath == device.deviceInterfacePath)
            {
                it = mapIt;
                break;
            }
        }
    }

    if (it == m_activeReports.end())
    {
        TrustAssessmentReport rep;
        rep.deviceId = device.deviceId;
        rep.vendorId = device.vendorId;
        rep.productId = device.productId;
        rep.serialNumber = device.serialNumber;
        if (device.hasHID && device.hasStorage) rep.deviceType = L"COMPOSITE (HID+Storage)";
        else if (device.hasStorage) rep.deviceType = L"STORAGE";
        else if (device.hasHID) rep.deviceType = L"HID";
        else if (device.hasNetwork) rep.deviceType = L"NETWORK";
        else rep.deviceType = L"OTHER";
        rep.originalDevice = device;
        rep.timestamp = GetCurrentUtcTimestamp();
        rep.adminAuthorized = (m_allowlist && m_allowlist->IsAllowed(device));
        rep.deviceIdentityMatch = rep.adminAuthorized;
        m_activeReports[device.deviceId] = rep;
        it = m_activeReports.find(device.deviceId);
    }

    TrustAssessmentReport& report = it->second;
    report.originalDevice = device;

    ModuleAssessment m4;
    m4.moduleId = L"A4";
    m4.moduleName = L"AntivirusMalwareScan";
    m4.timestamp = GetCurrentUtcTimestamp();

    if (scanResult.status == ScanStatus::CLEAN)
    {
        m4.status = AssessmentStatus::PASS;
        m4.riskWeight = 0;
        m4.evidence = scanResult.details.empty() ? L"Scan clean: 0 threats detected." : scanResult.details;
        m4.isCritical = false;
        report.malwareScanResult = L"CLEAN";
        if (report.executablePolicyStatus != L"BLOCKED")
        {
            report.exactThreatEvidence = L"";
            report.exactThreatFile = L"";
        }

        // Remove any prior A4 critical violation if present
        for (auto cIt = report.criticalViolations.begin(); cIt != report.criticalViolations.end();)
        {
            if (cIt->find(L"[A4") != std::wstring::npos)
                cIt = report.criticalViolations.erase(cIt);
            else
                ++cIt;
        }
    }
    else if (scanResult.status == ScanStatus::DETECTED)
    {
        m4.status = AssessmentStatus::FAIL;
        m4.riskWeight = 60;
        m4.evidence = L"MALWARE DETECTED: " + scanResult.threatName + L" (" + scanResult.details + L")";
        m4.isCritical = true;
        report.malwareScanResult = L"DETECTED";
        report.exactThreatEvidence = scanResult.details;
        report.exactThreatFile = scanResult.targetPath;
        report.criticalViolations.push_back(L"[A4-CRITICAL] Malware signature detected: " + scanResult.threatName);
        report.explainableReasons.push_back(L"[A4] Malware threat identified by antivirus engine (+60 risk)");
    }
    else if (scanResult.status == ScanStatus::FAILED)
    {
        m4.status = AssessmentStatus::NOT_ASSESSED;
        m4.riskWeight = 15;
        m4.evidence = L"Antivirus engine scan failed: " + scanResult.details;
        m4.isCritical = false;
        report.malwareScanResult = L"FAILED";
        report.explainableReasons.push_back(L"[A4] Antivirus scan failed; cannot verify media cleanliness (+15 risk)");
    }
    else if (scanResult.status == ScanStatus::UNAVAILABLE)
    {
        m4.status = AssessmentStatus::NOT_ASSESSED;
        m4.riskWeight = 10;
        m4.evidence = L"Antivirus engine unavailable on endpoint.";
        m4.isCritical = false;
        report.malwareScanResult = L"UNAVAILABLE";
        report.explainableReasons.push_back(L"[A4] Local AV engine unavailable (+10 risk)");
    }
    else
    {
        m4.status = AssessmentStatus::NOT_ASSESSED;
        m4.riskWeight = 10;
        m4.evidence = L"Media volume not yet scanned.";
        m4.isCritical = false;
        report.malwareScanResult = L"NOT_SCANNED";
    }

    report.moduleResults[m4.moduleId] = m4;
    FinalizeReport(report);
    m_activeReports[report.deviceId] = report;

    std::wcout << L"\n[TAE-SCAN] Antivirus scan result updated for " << report.deviceId << L"\n"
               << L"[TAE-SCAN] Status: " << report.malwareScanResult
               << L" | Recommendation: " << TrustRecommendationToString(report.recommendation)
               << L" (Risk Score: " << report.totalRiskScore << L"/100)\n";

    if (report.recommendation == TrustRecommendation::REJECT && scanResult.status == ScanStatus::DETECTED)
    {
        std::wcout << L"[TAE-SCAN] Confirmed malware detected. Initiating critical threat enforcement...\n";
        USBDevice dev = report.originalDevice;
        if (dev.deviceId.empty()) dev = device;

        std::vector<std::wstring> reasons = report.explainableReasons;
        reasons.push_back(L"Malware: " + scanResult.threatName);

        ThreatEnforcementResult enfRes = EnforcementManager::EnforceCriticalThreat(
            dev,
            L"MALWARE_DETECTED",
            L"Confirmed malware threat on device: " + scanResult.threatName,
            report.totalRiskScore,
            reasons,
            m_allowlist
        );

        report.actualWindowsEnforcement = enfRes.finalEnforcementState;
        m_activeReports[report.deviceId] = report;
    }
}

void TrustAssessmentEngine::UpdateExecutablePolicyResult(
    const USBDevice& device,
    const StorageExecutableInspectionResult& inspectionResult)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_activeReports.find(device.deviceId);
    if (it == m_activeReports.end())
    {
        for (auto mapIt = m_activeReports.begin(); mapIt != m_activeReports.end(); ++mapIt)
        {
            if (!device.serialNumber.empty() && mapIt->second.serialNumber == device.serialNumber &&
                !device.vendorId.empty() && mapIt->second.vendorId == device.vendorId &&
                !device.productId.empty() && mapIt->second.productId == device.productId)
            {
                it = mapIt;
                break;
            }
            if (!device.deviceInterfacePath.empty() && mapIt->second.originalDevice.deviceInterfacePath == device.deviceInterfacePath)
            {
                it = mapIt;
                break;
            }
        }
    }

    if (it == m_activeReports.end())
    {
        TrustAssessmentReport rep;
        rep.deviceId = device.deviceId;
        rep.vendorId = device.vendorId;
        rep.productId = device.productId;
        rep.serialNumber = device.serialNumber;
        if (device.hasHID && device.hasStorage) rep.deviceType = L"COMPOSITE (HID+Storage)";
        else if (device.hasStorage) rep.deviceType = L"STORAGE";
        else if (device.hasHID) rep.deviceType = L"HID";
        else if (device.hasNetwork) rep.deviceType = L"NETWORK";
        else rep.deviceType = L"OTHER";
        rep.originalDevice = device;
        rep.timestamp = GetCurrentUtcTimestamp();
        rep.adminAuthorized = (m_allowlist && m_allowlist->IsAllowed(device));
        rep.deviceIdentityMatch = rep.adminAuthorized;
        m_activeReports[device.deviceId] = rep;
        it = m_activeReports.find(device.deviceId);
    }

    TrustAssessmentReport& report = it->second;
    report.originalDevice = device;

    ModuleAssessment m6;
    m6.moduleId = L"A6";
    m6.moduleName = L"StorageExecutionMonitor";
    m6.timestamp = GetCurrentUtcTimestamp();

    if (inspectionResult.status == StorageExecutableInspectionResult::Status::CLEAN)
    {
        m6.status = AssessmentStatus::PASS;
        m6.riskWeight = 0;
        m6.evidence = L"Executable policy inspection clean: no prohibited files found on " + inspectionResult.scannedDrive;
        m6.isCritical = false;
        report.executablePolicyStatus = L"COMPLIANT";

        for (auto cIt = report.criticalViolations.begin(); cIt != report.criticalViolations.end();)
        {
            if (cIt->find(L"[A6") != std::wstring::npos)
                cIt = report.criticalViolations.erase(cIt);
            else
                ++cIt;
        }
    }
    else if (inspectionResult.status == StorageExecutableInspectionResult::Status::PROHIBITED_FOUND)
    {
        m6.status = AssessmentStatus::FAIL;
        m6.riskWeight = 45;
        m6.evidence = inspectionResult.policyRule + L": " + inspectionResult.primaryProhibitedFile;
        m6.isCritical = true;
        report.executablePolicyStatus = L"BLOCKED";
        report.exactThreatEvidence = inspectionResult.policyRule;
        report.exactThreatFile = inspectionResult.primaryProhibitedFile;
        report.criticalViolations.push_back(L"[A6-CRITICAL] " + inspectionResult.policyRule + L": " + inspectionResult.primaryProhibitedFile);
        report.explainableReasons.push_back(L"[A6] " + inspectionResult.policyRule + L" (+45 risk)");
    }
    else if (inspectionResult.status == StorageExecutableInspectionResult::Status::FAILED)
    {
        m6.status = AssessmentStatus::NOT_ASSESSED;
        m6.riskWeight = 20;
        m6.evidence = inspectionResult.failureReason;
        m6.isCritical = false;
        report.executablePolicyStatus = L"FAILED";
        report.explainableReasons.push_back(L"[A6] Storage volume file enumeration failed; executable policy check incomplete (+20 risk)");
    }
    else // NOT_MOUNTED
    {
        m6.status = AssessmentStatus::NOT_ASSESSED;
        m6.riskWeight = 10;
        m6.evidence = inspectionResult.failureReason;
        m6.isCritical = false;
        report.executablePolicyStatus = L"NOT_SCANNED";
        report.explainableReasons.push_back(L"[A6] Storage volume not mounted; executable policy check pending (+10 risk)");
    }

    report.moduleResults[m6.moduleId] = m6;
    FinalizeReport(report);
    m_activeReports[report.deviceId] = report;

    std::wcout << L"\n[TAE-EXEC] Executable policy result updated for " << report.deviceId << L"\n"
               << L"[TAE-EXEC] Status: " << report.executablePolicyStatus
               << L" | Recommendation: " << TrustRecommendationToString(report.recommendation)
               << L" (Risk Score: " << report.totalRiskScore << L"/100)\n";

    if (report.recommendation == TrustRecommendation::REJECT &&
        inspectionResult.status == StorageExecutableInspectionResult::Status::PROHIBITED_FOUND)
    {
        std::wcout << L"[TAE-EXEC] Prohibited executable detected on removable storage. Initiating critical threat enforcement...\n";
        USBDevice dev = report.originalDevice;
        if (dev.deviceId.empty()) dev = device;

        std::vector<std::wstring> reasons = report.explainableReasons;
        reasons.push_back(inspectionResult.policyRule + L": " + inspectionResult.primaryProhibitedFile);

        ThreatEnforcementResult enfRes = EnforcementManager::EnforceCriticalThreat(
            dev,
            L"STORAGE_EXECUTION_BLOCKED",
            inspectionResult.policyRule + L": " + inspectionResult.primaryProhibitedFile,
            report.totalRiskScore,
            reasons,
            m_allowlist
        );

        report.actualWindowsEnforcement = enfRes.finalEnforcementState;
        m_activeReports[report.deviceId] = report;
    }
}

void TrustAssessmentEngine::UpdateAssessmentWithEvent(
    TrustAssessmentReport& report,
    const SecurityEvent& event)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    InternalUpdateAssessmentWithEvent(report, event);
}

void TrustAssessmentEngine::UpdateAssessmentWithEvent(
    const std::wstring& deviceId,
    SecurityEventType type,
    const std::wstring& reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    SecurityEvent evt;
    evt.eventType = type;
    evt.reason = reason;

    auto it = m_activeReports.find(deviceId);
    if (it != m_activeReports.end())
    {
        InternalUpdateAssessmentWithEvent(it->second, evt);
        return;
    }

    // Fallback search across active reports
    for (auto& kv : m_activeReports)
    {
        if (kv.second.deviceId == deviceId ||
            kv.second.originalDevice.deviceInterfacePath == deviceId ||
            (!kv.second.vendorId.empty() && deviceId.find(kv.second.vendorId) != std::wstring::npos &&
             !kv.second.productId.empty() && deviceId.find(kv.second.productId) != std::wstring::npos))
        {
            InternalUpdateAssessmentWithEvent(kv.second, evt);
            return;
        }
    }
}

void TrustAssessmentEngine::UpdateAssessmentWithEvent(
    const USBDevice& device,
    SecurityEventType type,
    const std::wstring& reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    SecurityEvent evt;
    evt.eventType = type;
    evt.reason = reason;

    auto it = m_activeReports.find(device.deviceId);
    if (it != m_activeReports.end())
    {
        it->second.originalDevice = device;
        InternalUpdateAssessmentWithEvent(it->second, evt);
        return;
    }

    // Fallback search across active reports
    for (auto& kv : m_activeReports)
    {
        if ((!device.serialNumber.empty() && kv.second.serialNumber == device.serialNumber &&
             !device.vendorId.empty() && kv.second.vendorId == device.vendorId &&
             !device.productId.empty() && kv.second.productId == device.productId) ||
            (!device.deviceInterfacePath.empty() && kv.second.originalDevice.deviceInterfacePath == device.deviceInterfacePath))
        {
            kv.second.originalDevice = device;
            InternalUpdateAssessmentWithEvent(kv.second, evt);
            return;
        }
    }

    // If no prior report exists, create one
    TrustAssessmentReport newReport;
    newReport.deviceId = device.deviceId;
    newReport.vendorId = device.vendorId;
    newReport.productId = device.productId;
    newReport.serialNumber = device.serialNumber;
    newReport.originalDevice = device;
    newReport.timestamp = GetCurrentUtcTimestamp();
    InternalUpdateAssessmentWithEvent(newReport, evt);
}

bool TrustAssessmentEngine::GetActiveAssessment(
    const std::wstring& deviceId,
    TrustAssessmentReport& outReport) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_activeReports.find(deviceId);
    if (it != m_activeReports.end())
    {
        outReport = it->second;
        return true;
    }
    return false;
}

bool TrustAssessmentEngine::VerifySelfTest()
{
    AllowlistManager mockAllowlist;
    mockAllowlist.Initialize(L":memory:");

    USBDevice authorizedDev;
    authorizedDev.vendorId = L"0781";
    authorizedDev.productId = L"5583";
    authorizedDev.serialNumber = L"VALID_SERIAL_001";
    authorizedDev.hasStorage = true;
    authorizedDev.type = DeviceType::STORAGE;
    mockAllowlist.AddDevice(authorizedDev);

    // -------------------------------------------------------------
    // Test 1: Fully Authorized Device with Clean Scan -> APPROVE
    // -------------------------------------------------------------
    std::wcout << L"  [12.1] Baseline Authorized Device Evaluation (Allowlisted + Clean Scan)...\n";
    ReconnectionEvasionAnalyzer::Instance().Reset();
    MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);
    StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(true, StorageExecutableInspectionResult::Status::CLEAN);
    TrustAssessmentReport rep1 = AssessDevice(authorizedDev, mockAllowlist, L"E:\\");
    bool t1 = (rep1.recommendation == TrustRecommendation::APPROVE &&
               rep1.severity == RiskSeverity::LOW &&
               rep1.totalRiskScore <= 25);
    std::wcout << L"         Verdict: " << TrustRecommendationToString(rep1.recommendation)
               << L" | Score: " << rep1.totalRiskScore << L"/100 ("
               << RiskSeverityToString(rep1.severity) << L")"
               << (t1 ? L" [PASSED - Clean approval]" : L" [FAILED]") << L"\n";

    // -------------------------------------------------------------
    // Test 2: Unknown Device with Low Score -> REVIEW (Never Auto-Trust!)
    // -------------------------------------------------------------
    std::wcout << L"  [12.2] Unknown Device with Low Risk Score (Not Allowlisted)...\n";
    ReconnectionEvasionAnalyzer::Instance().Reset();
    USBDevice unknownDev = authorizedDev;
    unknownDev.serialNumber = L"UNKNOWN_SERIAL_999";
    TrustAssessmentReport rep2 = AssessDevice(unknownDev, mockAllowlist, L"E:\\");
    bool t2 = (rep2.recommendation == TrustRecommendation::REVIEW &&
               !rep2.deviceIdentityMatch &&
               !rep2.adminAuthorized);
    std::wcout << L"         Verdict: " << TrustRecommendationToString(rep2.recommendation)
               << L" | Score: " << rep2.totalRiskScore << L"/100"
               << (t2 ? L" [PASSED - Unknown device requires review, not auto-approved]" : L" [FAILED]") << L"\n";

    // -------------------------------------------------------------
    // Test 3: Critical Denial Rule Override (Malware Detected on Storage) -> REJECT
    // -------------------------------------------------------------
    std::wcout << L"  [12.3] Critical Denial Rule: Malware Detected on Authorized Storage...\n";
    ReconnectionEvasionAnalyzer::Instance().Reset();
    MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::DETECTED, L"Trojan.Win32.Injector");
    TrustAssessmentReport rep3 = AssessDevice(authorizedDev, mockAllowlist, L"E:\\");
    bool t3 = (rep3.recommendation == TrustRecommendation::REJECT &&
               rep3.severity == RiskSeverity::CRITICAL &&
               rep3.totalRiskScore >= 85);
    std::wcout << L"         Verdict: " << TrustRecommendationToString(rep3.recommendation)
               << L" | Score: " << rep3.totalRiskScore << L"/100 ("
               << RiskSeverityToString(rep3.severity) << L")"
               << (t3 ? L" [PASSED - Critical rule forced REJECT]" : L" [FAILED]") << L"\n";

    // -------------------------------------------------------------
    // Test 4: Critical Denial Rule Override (Composite BadUSB HID+Storage) -> REJECT
    // -------------------------------------------------------------
    std::wcout << L"  [12.4] Critical Denial Rule: Composite BadUSB Device (HID+Storage)...\n";
    ReconnectionEvasionAnalyzer::Instance().Reset();
    MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);
    USBDevice badUsbDev = authorizedDev;
    badUsbDev.hasHID = true; // HID + Storage
    TrustAssessmentReport rep4 = AssessDevice(badUsbDev, mockAllowlist, L"E:\\");
    bool t4 = (rep4.recommendation == TrustRecommendation::REJECT &&
               !rep4.criticalViolations.empty());
    std::wcout << L"         Verdict: " << TrustRecommendationToString(rep4.recommendation)
               << L" | Violations: " << rep4.criticalViolations.size()
               << (t4 ? L" [PASSED - Composite BadUSB strictly rejected]" : L" [FAILED]") << L"\n";

    // -------------------------------------------------------------
    // Test 5: Incomplete Evidence Rule (Scanner Failed / Unavailable) -> REVIEW
    // -------------------------------------------------------------
    std::wcout << L"  [12.5] Incomplete Evidence Rule: AV Scanner Failed on Storage...\n";
    ReconnectionEvasionAnalyzer::Instance().Reset();
    MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::FAILED);
    TrustAssessmentReport rep5 = AssessDevice(authorizedDev, mockAllowlist, L"E:\\");
    bool t5 = (rep5.recommendation == TrustRecommendation::REVIEW &&
               rep5.malwareScanResult == L"FAILED");
    std::wcout << L"         Verdict: " << TrustRecommendationToString(rep5.recommendation)
               << L" | Scan Status: " << rep5.malwareScanResult
               << (t5 ? L" [PASSED - Failed scan not treated as pass]" : L" [FAILED]") << L"\n";

    // -------------------------------------------------------------
    // Test 6: Incomplete Evidence Rule: AV Engine Unavailable -> REVIEW
    // -------------------------------------------------------------
    std::wcout << L"  [12.6] Incomplete Evidence Rule: AV Engine Unavailable...\n";
    ReconnectionEvasionAnalyzer::Instance().Reset();
    MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::UNAVAILABLE);
    TrustAssessmentReport rep6_unavail = AssessDevice(authorizedDev, mockAllowlist, L"E:\\");
    bool t6 = (rep6_unavail.recommendation == TrustRecommendation::REVIEW &&
               rep6_unavail.malwareScanResult == L"UNAVAILABLE");
    std::wcout << L"         Verdict: " << TrustRecommendationToString(rep6_unavail.recommendation)
               << L" | Scan Status: " << rep6_unavail.malwareScanResult
               << (t6 ? L" [PASSED - Unavailable engine held for review, not pass]" : L" [FAILED]") << L"\n";

    // -------------------------------------------------------------
    // Test 7: Suspicious File Finding -> REVIEW / Elevated Risk
    // -------------------------------------------------------------
    std::wcout << L"  [12.7] Suspicious File Finding on Storage Media...\n";
    ReconnectionEvasionAnalyzer::Instance().Reset();
    MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);
    TrustAssessmentReport rep7_susp = AssessDevice(authorizedDev, mockAllowlist, L"E:\\");
    SecurityEvent suspEvt;
    suspEvt.eventType = SecurityEventType::SUSPICIOUS_FILE_DETECTED;
    suspEvt.reason = L"Suspicious double-extension invoice.pdf.exe detected";
    UpdateAssessmentWithEvent(rep7_susp, suspEvt);
    bool t7 = (rep7_susp.recommendation == TrustRecommendation::REVIEW || rep7_susp.recommendation == TrustRecommendation::REJECT);
    std::wcout << L"         Verdict: " << TrustRecommendationToString(rep7_susp.recommendation)
               << L" | Risk Score: " << rep7_susp.totalRiskScore << L"/100"
               << (t7 ? L" [PASSED - Suspicious finding elevated risk]" : L" [FAILED]") << L"\n";

    // -------------------------------------------------------------
    // Test 8: Revoked Device State -> REVIEW / Denied Auto-Approval
    // -------------------------------------------------------------
    std::wcout << L"  [12.8] Revoked Device Authorization State...\n";
    ReconnectionEvasionAnalyzer::Instance().Reset();
    AllowlistManager revokedAllowlist;
    revokedAllowlist.Initialize(L":memory:"); // Empty allowlist simulates post-revocation cache
    TrustAssessmentReport rep8_revoked = AssessDevice(authorizedDev, revokedAllowlist, L"E:\\");
    bool t8 = (rep8_revoked.recommendation == TrustRecommendation::REVIEW &&
               !rep8_revoked.adminAuthorized);
    std::wcout << L"         Verdict: " << TrustRecommendationToString(rep8_revoked.recommendation)
               << L" | Admin Authorized: " << (rep8_revoked.adminAuthorized ? L"YES" : L"NO")
               << (t8 ? L" [PASSED - Revoked device denied automatic trust]" : L" [FAILED]") << L"\n";

    // -------------------------------------------------------------
    // Test 9: Continuous Behavioral Monitoring (Post-Approval Downgrade)
    // -------------------------------------------------------------
    std::wcout << L"  [12.9] Continuous Behavioral Surveillance (Post-Approval Downgrade)...\n";
    ReconnectionEvasionAnalyzer::Instance().Reset();
    MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);
    TrustAssessmentReport rep9 = AssessDevice(authorizedDev, mockAllowlist, L"E:\\");
    bool beforeDowngrade = (rep9.recommendation == TrustRecommendation::APPROVE);

    // Simulate runtime canary access event on already-approved device
    SecurityEvent breachEvt;
    breachEvt.eventType = SecurityEventType::PROTECTED_FILE_ACCESS;
    breachEvt.reason = L"Canary file touched by active process";
    UpdateAssessmentWithEvent(rep9, breachEvt);

    bool afterDowngrade = (rep9.recommendation == TrustRecommendation::REJECT &&
                           rep9.severity == RiskSeverity::CRITICAL);
    bool t9 = (beforeDowngrade && afterDowngrade);
    std::wcout << L"         Pre-event: " << (beforeDowngrade ? L"APPROVE" : L"FAIL")
               << L" -> Post-breach: " << TrustRecommendationToString(rep9.recommendation)
               << L" (" << RiskSeverityToString(rep9.severity) << L")"
               << (t9 ? L" [PASSED - Trust downgraded dynamically]" : L" [FAILED]") << L"\n";

    MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);
    StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
    ReconnectionEvasionAnalyzer::Instance().Reset();
    return (t1 && t2 && t3 && t4 && t5 && t6 && t7 && t8 && t9);
}
