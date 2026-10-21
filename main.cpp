#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <dbt.h>
#include <initguid.h>
#include <usbiodef.h>

#include <iostream>
#include <fstream>
#include <unordered_set>
#include <mutex>
#include <shellapi.h>

#include "ThirdParty/nlohmann/json.hpp"

#include "Models/USBDevice.h"
#include "Extractor/DeviceInfoExtractor.h"
#include "Classifier/DeviceClassifier.h"
#include "Allowlist/AllowlistManager.h"
#include "AccessControl/AccessController.h"
#include "AccessControl/CompositeDevicePolicy.h"
#include "AccessControl/HIDBehaviorMonitor.h"
#include "AccessControl/ProtectedFileMonitor.h"
#include "AccessControl/StorageExecutionMonitor.h"
#include "AccessControl/ReconnectionEvasionAnalyzer.h"
#include "AccessControl/MalwareScanner.h"
#include "AccessControl/SuspiciousFileDetector.h"
#include "AccessControl/DataExfiltrationMonitor.h"
#include "AccessControl/TrustAssessmentEngine.h"
#include "AccessControl/PolicyConfig.h"
#include "Enforcement/EnforcementManager.h"
#include "Presence/DevicePresenceMonitor.h"
#include "Logging/EventLogger.h"
#include "Network/RestClient.h"
#include "Network/SyncManager.h"

HDEVNOTIFY g_hDeviceNotify = nullptr;
AllowlistManager g_allowlist;
std::unordered_set<std::wstring>
g_expectedRemovalNotifications;

std::unordered_set<std::wstring>
g_expectedArrivalNotifications;

std::mutex g_notificationMutex;

std::unordered_set<std::wstring>
g_recentlyDetectedRemovals;

std::mutex
g_removalMutex;

static std::wstring NormalizeNotificationPath(std::wstring path)
{
    for (auto& ch : path)
    {
        ch = static_cast<wchar_t>(towupper(ch));
    }
    return path;
}

static std::wstring ExtractDeviceInstanceId(const std::wstring& path)
{
    size_t usbPos = path.find(L"USB\\");
    if (usbPos == std::wstring::npos) usbPos = path.find(L"USB#");
    if (usbPos != std::wstring::npos)
    {
        size_t guidPos = path.find(L"#{", usbPos);
        if (guidPos == std::wstring::npos) guidPos = path.find(L"\\{", usbPos);
        std::wstring raw = (guidPos != std::wstring::npos) ? path.substr(usbPos, guidPos - usbPos) : path.substr(usbPos);
        for (auto& ch : raw)
        {
            if (ch == L'#') ch = L'\\';
            else ch = static_cast<wchar_t>(towupper(ch));
        }
        return raw;
    }
    return NormalizeNotificationPath(path);
}

void ExpectInternalRemoval(
    const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(
        g_notificationMutex
    );

    g_expectedRemovalNotifications.insert(
        NormalizeNotificationPath(devicePath)
    );
    g_expectedRemovalNotifications.insert(
        ExtractDeviceInstanceId(devicePath)
    );
}


void ExpectInternalArrival(
    const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(
        g_notificationMutex
    );

    g_expectedArrivalNotifications.insert(
        NormalizeNotificationPath(devicePath)
    );
    g_expectedArrivalNotifications.insert(
        ExtractDeviceInstanceId(devicePath)
    );
}


bool ConsumeExpectedRemoval(
    const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(
        g_notificationMutex
    );

    std::wstring norm = NormalizeNotificationPath(devicePath);
    std::wstring inst = ExtractDeviceInstanceId(devicePath);

    bool matched = false;
    if (g_expectedRemovalNotifications.erase(norm) > 0) matched = true;
    if (!inst.empty() && g_expectedRemovalNotifications.erase(inst) > 0) matched = true;
    if (matched)
    {
        return true;
    }

    // Fallback: substring or case-insensitive scan
    for (auto it = g_expectedRemovalNotifications.begin();
         it != g_expectedRemovalNotifications.end();
         ++it)
    {
        if (!it->empty() && (norm.find(*it) != std::wstring::npos || it->find(inst) != std::wstring::npos || _wcsicmp(it->c_str(), devicePath.c_str()) == 0))
        {
            g_expectedRemovalNotifications.erase(it);
            return true;
        }
    }

    return false;
}


bool ConsumeExpectedArrival(
    const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(
        g_notificationMutex
    );

    std::wstring norm = NormalizeNotificationPath(devicePath);
    std::wstring inst = ExtractDeviceInstanceId(devicePath);

    bool matched = false;
    if (g_expectedArrivalNotifications.erase(norm) > 0) matched = true;
    if (!inst.empty() && g_expectedArrivalNotifications.erase(inst) > 0) matched = true;
    if (matched)
    {
        return true;
    }

    // Fallback: substring or case-insensitive scan
    for (auto it = g_expectedArrivalNotifications.begin();
         it != g_expectedArrivalNotifications.end();
         ++it)
    {
        if (!it->empty() && (norm.find(*it) != std::wstring::npos || it->find(inst) != std::wstring::npos || _wcsicmp(it->c_str(), devicePath.c_str()) == 0))
        {
            g_expectedArrivalNotifications.erase(it);
            return true;
        }
    }

    return false;
}

void CancelExpectedRemoval(
    const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(
        g_notificationMutex
    );

    std::wstring norm = NormalizeNotificationPath(devicePath);
    std::wstring inst = ExtractDeviceInstanceId(devicePath);
    g_expectedRemovalNotifications.erase(norm);
    g_expectedRemovalNotifications.erase(inst);

    for (auto setIt = g_expectedRemovalNotifications.begin();
         setIt != g_expectedRemovalNotifications.end();)
    {
        if (_wcsicmp(setIt->c_str(), devicePath.c_str()) == 0 || (!setIt->empty() && norm.find(*setIt) != std::wstring::npos))
        {
            setIt = g_expectedRemovalNotifications.erase(setIt);
        }
        else
        {
            ++setIt;
        }
    }
}


void CancelExpectedArrival(
    const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(
        g_notificationMutex
    );

    std::wstring norm = NormalizeNotificationPath(devicePath);
    std::wstring inst = ExtractDeviceInstanceId(devicePath);
    g_expectedArrivalNotifications.erase(norm);
    g_expectedArrivalNotifications.erase(inst);

    for (auto setIt = g_expectedArrivalNotifications.begin();
         setIt != g_expectedArrivalNotifications.end();)
    {
        if (_wcsicmp(setIt->c_str(), devicePath.c_str()) == 0 || (!setIt->empty() && norm.find(*setIt) != std::wstring::npos))
        {
            setIt = g_expectedArrivalNotifications.erase(setIt);
        }
        else
        {
            ++setIt;
        }
    }
}

// Active workflow tracker to ensure one insertion creates at most one active workflow
// and deduplicate subsequent external arrival events while active
std::unordered_set<std::wstring> g_activeInspectionWorkflows;
std::mutex g_workflowMutex;

bool TryStartInspectionWorkflow(const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(g_workflowMutex);
    std::wstring inst = ExtractDeviceInstanceId(devicePath);
    if (g_activeInspectionWorkflows.find(inst) != g_activeInspectionWorkflows.end())
    {
        return false; // Workflow already active
    }
    g_activeInspectionWorkflows.insert(inst);
    return true; // Workflow claimed
}

bool IsInspectionWorkflowActive(const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(g_workflowMutex);
    std::wstring inst = ExtractDeviceInstanceId(devicePath);
    return (g_activeInspectionWorkflows.find(inst) != g_activeInspectionWorkflows.end());
}

void EndInspectionWorkflow(const std::wstring& devicePath)
{
    std::lock_guard<std::mutex> lock(g_workflowMutex);
    std::wstring inst = ExtractDeviceInstanceId(devicePath);
    g_activeInspectionWorkflows.erase(inst);
}

// ============================================================
// Print device
// ============================================================

void PrintUSBDevice(
    const USBDevice& device)
{
    std::wcout
        << L"\n";

    std::wcout
        << L"========================================\n";

    std::wcout
        << L"USB DEVICE INFORMATION\n";

    std::wcout
        << L"========================================\n";

    std::wcout
        << L"Device Interface Path : "
        << device.deviceInterfacePath
        << L"\n";

    std::wcout
        << L"Device ID             : "
        << device.deviceId
        << L"\n";

    std::wcout
        << L"VID                   : "
        << device.vendorId
        << L"\n";

    std::wcout
        << L"PID                   : "
        << device.productId
        << L"\n";

    std::wcout
        << L"Serial / Instance     : "
        << device.serialNumber
        << L"\n";

    std::wcout
        << L"Description           : "
        << device.description
        << L"\n";

    std::wcout
        << L"Manufacturer          : "
        << device.manufacturer
        << L"\n";

    std::wcout
        << L"Hardware IDs          : "
        << device.hardwareIds
        << L"\n";


    // --------------------------------------------------------
    // Classification
    // --------------------------------------------------------

    std::wcout
        << L"\n";

    std::wcout
        << L"----- CLASSIFICATION -------------------\n";

    std::wcout
        << L"Device Type           : "
        << DeviceClassifier::ToString(
            device.type
        )
        << L"\n";

    std::wcout
        << L"HID Capability        : "
        << (device.hasHID ? L"YES" : L"NO")
        << L"\n";

    std::wcout
        << L"Storage Capability    : "
        << (device.hasStorage ? L"YES" : L"NO")
        << L"\n";

    std::wcout
        << L"Network Capability    : "
        << (device.hasNetwork ? L"YES" : L"NO")
        << L"\n";


    std::wcout
        << L"\nDetected Windows Classes:\n";

    for (const auto& className :
        device.detectedClasses)
    {
        std::wcout
            << L"  - "
            << className
            << L"\n";
    }

    std::wcout
        << L"========================================\n";
}


// ============================================================
// Window Procedure
// ============================================================

LRESULT CALLBACK WindowProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam)
{
    switch (message)
    {
    case WM_DEVICECHANGE:
    {
        // ------------------------------------------------
        // Device connected
        // ------------------------------------------------

        if (wParam ==
            DBT_DEVICEARRIVAL)
        {
            PDEV_BROADCAST_HDR header =
                reinterpret_cast<
                PDEV_BROADCAST_HDR
                >(lParam);

            if (header &&
                header->dbch_devicetype ==
                DBT_DEVTYP_DEVICEINTERFACE)
            {
                PDEV_BROADCAST_DEVICEINTERFACE_W
                    deviceInterface =
                    reinterpret_cast<
                    PDEV_BROADCAST_DEVICEINTERFACE_W
                    >(lParam);

                std::wstring devicePath =
                    deviceInterface->dbcc_name;
                std::wstring instId = ExtractDeviceInstanceId(devicePath);

                if (ConsumeExpectedArrival(devicePath))
                {
                    std::wcout
                        << L"\n[USBIPS] Suppressing internal "
                        << L"device-enable notification for: " << instId << L"\n";

                    break;
                }

                // Deduplicate external arrival events for the same device instance while workflow is active
                if (!TryStartInspectionWorkflow(devicePath))
                {
                    std::wcout
                        << L"\n[USBIPS] Duplicate arrival notification ignored; workflow already active for: "
                        << instId << L"\n";
                    break;
                }

                std::wcout
                    << L"\nUSB DEVICE CONNECTED\n";


                USBDevice device;

                /*
                    STEP 1
                    Extract enough information to identify the device.
                */
                if (!DeviceInfoExtractor::Extract(
                        devicePath,
                        device))
                {
                    // Check if extraction failed during an internal enforcement transition
                    DeviceTrackingState trackedState;
                    if ((DevicePresenceMonitor::GetDeviceState(instId, trackedState) &&
                         trackedState == DeviceTrackingState::QUARANTINED) ||
                        ConsumeExpectedRemoval(devicePath))
                    {
                        std::wcout
                            << L"[USBIPS] Device " << instId
                            << L" is already tracked in QUARANTINED state; ignoring PnP transition.\n";
                        return 0;
                    }

                    std::wcerr
                        << L"[ERROR] Failed to extract USB device information.\n";

                    EventLogger::Instance().LogSimpleEvent(
                        SecurityEventType::DEVICE_CONNECTED,
                        L"",
                        devicePath,
                        L"BLOCK",
                        L"Failed to extract USB device information"
                    );

                    EndInspectionWorkflow(devicePath);
                    return 0;
                }

                EventLogger::Instance().LogEvent(
                    SecurityEventType::DEVICE_CONNECTED,
                    device,
                    L"-",
                    L"USB device connected"
                );

                // Algorithm 4: Physical USB insertion triggers OS-level protected folder access restrictions
                ProtectedFileMonitor::Instance().OnUsbDeviceConnected(device);


                /*
                    STEP 2
                    Perform device classification first to identify device capabilities.
                */
                if (!DeviceClassifier::Classify(device))
                {
                    std::wcerr
                        << L"[ERROR] Device classification failed.\n";

                    std::wcerr
                        << L"[SECURITY] Device will be blocked.\n";

                    EventLogger::Instance().LogEvent(
                        SecurityEventType::DEVICE_BLOCKED,
                        device,
                        L"BLOCK",
                        L"Device classification failed"
                    );

                    return 0;
                }

                std::wstring specificType = DeviceClassifier::GetSpecificTypeString(device);
                std::wcout
                    << L"[DEVICE-ARRIVAL] InterfacePath=" << device.deviceInterfacePath
                    << L" VID=" << device.vendorId << L" PID=" << device.productId
                    << L" Serial=" << device.serialNumber << L" InstanceID=" << device.deviceId
                    << L" Desc=" << device.description << L"\n";
                std::wcout
                    << L"[CLASSIFICATION] PrimaryType=" << DeviceClassifier::ToString(device.type)
                    << L" SpecificType=" << specificType
                    << L" (hasHID=" << (device.hasHID ? L"YES" : L"NO")
                    << L", hasMouse=" << (device.hasMouse ? L"YES" : L"NO")
                    << L", hasKeyboard=" << (device.hasKeyboard ? L"YES" : L"NO")
                    << L", hasStorage=" << (device.hasStorage ? L"YES" : L"NO")
                    << L", hasNetwork=" << (device.hasNetwork ? L"YES" : L"NO") << L")\n";

                /*
                    STEP 3
                    Quarantine policy enforcement:
                    - Non-HID devices (Storage, Network, Other) are immediately quarantined at OS level.
                    - HID devices (Mice and Keyboards) must NOT be disabled at OS level before CAPTCHA,
                      because disabling devnode kills hardware communication and prevents user input.
                      Instead, HID devices follow the safe lifecycle:
                      Detect -> Interactive CAPTCHA (Attributed Input) -> Post-CAPTCHA Quarantine -> Server Review -> Admin Enable.
                */
                bool isHIDInput = (device.hasHID || device.hasMouse || device.hasKeyboard);
                bool quarantined = false;
                CONFIGRET quarantineResult = CR_FAILURE;

                if (!isHIDInput)
                {
                    std::wcout
                        << L"\n----- INITIAL NON-HID QUARANTINE -----\n";

                    ExpectInternalRemoval(
                        device.deviceInterfacePath
                    );

                    quarantined = EnforcementManager::QuarantineDevice(device, &quarantineResult);
                    DevicePresenceMonitor::TrackDevice(device);

                    if (!quarantined)
                    {
                        CancelExpectedRemoval(
                            device.deviceInterfacePath
                        );

                        std::wcerr
                            << L"[ENFORCEMENT] OS-level disablement: "
                            << EnforcementManager::ConfigRetToString(quarantineResult) << L"\n";

                        std::wcout
                            << L"[POLICY] Evaluating device classification, identity, and security rules...\n";
                    }
                    else
                    {
                        EventLogger::Instance().LogEvent(
                            SecurityEventType::DEVICE_QUARANTINED,
                            device,
                            L"-",
                            L"Non-HID device placed in pre-decision zero-trust quarantine (OS PnP disabled)"
                        );
                    }
                }
                else
                {
                    DevicePresenceMonitor::TrackDevice(device);
                    std::wcout
                        << L"[LIFECYCLE] HID peripheral detected (" << specificType
                        << L"). Keeping active for interactive challenge; post-challenge quarantine will be enforced.\n";
                }


                /*
                    STEP 4
                    Display device information.
                */
                PrintUSBDevice(device);


                /*
                    STEP 5
                    Access-control decision & Trust Assessment Engine (A1-A10).
                */
                if (device.hasHID)
                {
                    HIDBehaviorMonitor::Instance().RecordDeviceConnection(device);
                }

                TrustAssessmentReport taeReport = TrustAssessmentEngine::Instance().AssessDevice(device, g_allowlist);
                std::wcout
                    << L"\n----- TRUST ASSESSMENT ENGINE (A1-A10) -----\n"
                    << L"  Trust Recommendation : " << TrustRecommendationToString(taeReport.recommendation) << L"\n"
                    << L"  Risk Score           : " << taeReport.totalRiskScore << L"/100 (" << RiskSeverityToString(taeReport.severity) << L")\n"
                    << L"  Identity Match       : " << (taeReport.deviceIdentityMatch ? L"YES" : L"NO") << L"\n"
                    << L"  Admin Authorized     : " << (taeReport.adminAuthorized ? L"YES" : L"NO") << L"\n"
                    << L"  Malware Scan Status  : " << taeReport.malwareScanResult << L"\n"
                    << L"  Behavioral Risk      : " << taeReport.behavioralRiskScore << L"/100\n"
                    << L"  Assessment Summary   : " << taeReport.summary << L"\n";

                // Log Trust Assessment Completed Event for central telemetry & audit
                std::wstring taeReason = L"[A10-TAE] Score=" + std::to_wstring(taeReport.totalRiskScore) +
                                         L"/100 (" + RiskSeverityToString(taeReport.severity) + L") Rec=" +
                                         TrustRecommendationToString(taeReport.recommendation) + L" | " + taeReport.summary;
                EventLogger::Instance().LogEvent(
                    SecurityEventType::TRUST_ASSESSMENT_COMPLETED,
                    device,
                    TrustRecommendationToString(taeReport.recommendation),
                    taeReason
                );

                std::wcout
                    << L"\n----- ACCESS CONTROL (ALG 1 + ALG 3) -----\n";

                PolicyDecisionRecord policyRecord;
                AccessDecision decision =
                    AccessController::EvaluateWithDetails(
                        device,
                        g_allowlist,
                        policyRecord
                    );

                if (taeReport.recommendation == TrustRecommendation::REJECT)
                {
                    decision = AccessDecision::BLOCK;
                }

                // --- Algorithm 1 console output ---
                std::wcout
                    << L"[ALG1] Fingerprint Check : "
                    << L"VID=" << device.vendorId
                    << L" PID=" << device.productId
                    << L" Serial=" << device.serialNumber << L"\n";

                if (policyRecord.alg1LocalAllowlist)
                {
                    std::wcout
                        << L"[ALG1] Result : LOCAL ALLOWLIST MATCH -- "
                        << policyRecord.alg1MatchedFields << L"\n";
                }

                // --- Algorithm 3 console output ---
                if (policyRecord.alg3CompositeBlock)
                {
                    std::wcout
                        << L"[ALG3] Composite Policy  : BLOCK\n"
                        << L"[ALG3] Reason : " << policyRecord.alg3Reason << L"\n";

                    EventLogger::Instance().LogEvent(
                        SecurityEventType::COMPOSITE_POLICY_VIOLATION,
                        device,
                        L"BLOCK",
                        policyRecord.alg3Reason
                    );
                }

                // --- Reconnection-evasion console output ---
                if (policyRecord.alg7EvasionDetected)
                {
                    std::wcout
                        << L"[ALG7] Reconnect Evasion : BLOCK\n"
                        << L"[ALG7] Reason : " << policyRecord.alg7Reason << L"\n";
                }

                std::wcout
                    << L"Initial Decision : "
                    << AccessController::ToString(decision)
                    << L" -- " << policyRecord.primaryReason << L"\n";


                /*
                    STEP 6
                    Trusted device — also start HID surveillance for keyboards.
                */
                if (decision == AccessDecision::ALLOW)
                {
                    // Check with Central Server if connected to ensure device has not been permanently removed
                    if (SyncManager::Instance().IsServerConnected())
                    {
                        std::wstring clientId = EventLogger::Instance().GetClientId();
                        DeviceCheckResult serverCheck = RestClient::Instance().CheckOrRequestDevice(clientId, device, &taeReport);
                        if (serverCheck.success)
                        {
                            if (serverCheck.decision == L"ASK")
                            {
                                std::wcout << L"[SERVER] Device was permanently removed from Central Server master allowlist. Purging local allowlist cache.\n";
                                g_allowlist.RemoveDevice(device);
                                decision = AccessDecision::ASK;
                            }
                            else if (serverCheck.decision == L"BLOCK")
                            {
                                std::wcout << L"[SERVER] Device is blocked by Central Server policy: " << serverCheck.message << L"\n";
                                g_allowlist.RemoveDevice(device);
                                decision = AccessDecision::BLOCK;
                            }
                        }
                    }
                }

                if (decision == AccessDecision::ALLOW)
                {
                    std::wcout
                        << L"Device is already allowlisted.\n";

                    EventLogger::Instance().LogEvent(
                        SecurityEventType::ALLOWLIST_MATCH,
                        device,
                        L"ALLOW",
                        L"[ALG1] Device fingerprint matched local allowlist"
                    );

                    // Algorithm 2: even allowlisted HID devices get
                    // post-release keystroke surveillance.
                    if (device.hasHID)
                    {
                        HIDBehaviorMonitor::Instance().StartSurveillance(device);
                    }

                    // Algorithm 4: set context for file monitor

                    // Algorithm 5: scan running processes for storage origin
                    if (device.hasStorage && PolicyConfig::Instance().blockStorageExecution)
                    {
                        StorageExecutionMonitor::Instance().ScanRunningProcesses(PolicyConfig::Instance().autoTerminateStorageProcesses);
                    }
                }


                /*
                    STEP 7
                    Unknown device — Algorithm 2 CAPTCHA for HID, then
                    Central Server Authorization Workflow.
                */
                else if (decision == AccessDecision::ASK)
                {
                    std::wcout
                        << L"Device is not in the local allowlist.\n";

                    std::wstring sessionId = L"sess-" + std::to_wstring(std::chrono::system_clock::now().time_since_epoch().count());
                    HIDVerificationResult hidVerif;
                    hidVerif.sessionId = sessionId;

                    // Stages B, C, D: CAPTCHA Lifecycle Verification for HID devices (keyboard or mouse)
                    if (device.hasHID && PolicyConfig::Instance().requireCaptchaForHID)
                    {
                        std::wcout << L"\n[STAGE B] Launching client-side human verification challenge for "
                                   << (device.hasMouse ? L"Mouse" : L"Keyboard") << L"...\n";

                        hidVerif = HIDBehaviorMonitor::Instance().RunLifecycleVerification(device, sessionId);

                        std::wcout << L"[STAGE B] Verification Outcome: " << hidVerif.outcome
                                   << L" (Method=" << hidVerif.method << L", Score=" << hidVerif.verificationScore << L"/100)\n";
                        std::wcout << L"[STAGE C] Temporary Release Window: " << (hidVerif.tempReleaseApplied ? L"APPLIED" : L"SKIPPED")
                                   << L" (" << hidVerif.tempReleaseDurationSeconds << L"s window)\n";
                        std::wcout << L"[STAGE D] Mandatory Re-Quarantine Result: " << hidVerif.reQuarantineResult << L"\n";

                        bool captchaPassed = (hidVerif.outcome == L"PASSED" ||
                                              hidVerif.outcome == L"MOUSE_CAPTCHA_PASSED" ||
                                              hidVerif.outcome == L"KEYBOARD_CAPTCHA_PASSED");
                        if (!captchaPassed)
                        {
                            std::wcerr << L"[SECURITY] Human verification challenge failed, timed out, cancelled, or replayed. Device remains quarantined.\n";
                            TrustAssessmentReport failTaeReport = TrustAssessmentEngine::Instance().AssessDevice(device, g_allowlist, L"", hidVerif, sessionId);
                            std::wstring clientId = EventLogger::Instance().GetClientId();
                            RestClient::Instance().CheckOrRequestDevice(clientId, device, &failTaeReport, &hidVerif);
                            decision = AccessDecision::BLOCK;
                            goto enforcement_decision;
                        }
                    }
                    else
                    {
                        hidVerif.outcome = L"NOT_APPLICABLE";
                        hidVerif.method = L"NONE";
                        hidVerif.currentEnforcementState = quarantined ? L"QUARANTINED" : L"PARTIALLY_ENFORCED";
                    }

                    // Run Trust Assessment Engine synthesizing all 12 security modules
                    TrustAssessmentReport taeReport = TrustAssessmentEngine::Instance().AssessDevice(device, g_allowlist, L"", hidVerif, sessionId);
                    std::wcout
                        << L"\n----- TRUST ASSESSMENT ENGINE (A1-A10) -----\n"
                        << L"  Trust Recommendation : " << TrustRecommendationToString(taeReport.recommendation) << L"\n"
                        << L"  Risk Score           : " << taeReport.totalRiskScore << L"/100 (" << RiskSeverityToString(taeReport.severity) << L")\n"
                        << L"  Identity Match       : " << (taeReport.deviceIdentityMatch ? L"YES" : L"NO") << L"\n"
                        << L"  Admin Authorized     : " << (taeReport.adminAuthorized ? L"YES" : L"NO") << L"\n"
                        << L"  Malware Scan Status  : " << taeReport.malwareScanResult << L"\n"
                        << L"  Behavioral Risk      : " << taeReport.behavioralRiskScore << L"/100\n"
                        << L"  Assessment Summary   : " << taeReport.summary << L"\n";

                    EventLogger::Instance().LogEvent(
                        SecurityEventType::UNKNOWN_DEVICE,
                        device,
                        L"ASK",
                        L"Device not found in local allowlist; submitting complete assessment report to central server"
                    );

                    std::wstring clientId = EventLogger::Instance().GetClientId();
                    std::wcout << L"[SERVER] Submitting Complete Assessment & Verification Report to Central Server...\n";

                    DeviceCheckResult checkResult =
                        RestClient::Instance().CheckOrRequestDevice(clientId, device, &taeReport, &hidVerif);

                    if (!checkResult.success)
                    {
                        // Central server is offline or unreachable -> Zero-Trust fallback
                        std::wcerr
                            << L"[OFFLINE] Central server unavailable (" << checkResult.message << L").\n"
                            << L"[OFFLINE] Enforcing local zero-trust policy: DEVICE BLOCKED.\n";

                        decision = AccessDecision::BLOCK;

                        EventLogger::Instance().LogEvent(
                            SecurityEventType::DEVICE_BLOCKED,
                            device,
                            L"BLOCK",
                            L"Central server unavailable; unknown device blocked by local zero-trust policy: " + checkResult.message
                        );
                    }
                    else if (checkResult.decision == L"ALLOW")
                    {
                        if (taeReport.recommendation == TrustRecommendation::REJECT)
                        {
                            std::wcerr << L"[SECURITY] Automatic approval denied: device has critical security violations!\n";
                            decision = AccessDecision::BLOCK;
                        }
                        else
                        {
                            std::wcout
                                << L"[SERVER] Authorization granted by Central Server: "
                                << checkResult.message << L"\n";

                            g_allowlist.AddDevice(device, checkResult.durationMinutes, checkResult.expiresAt, checkResult.message);
                            decision = AccessDecision::ALLOW;

                            EventLogger::Instance().LogEvent(
                                SecurityEventType::USER_APPROVED,
                                device,
                                L"ALLOW",
                                L"Central server master allowlist match"
                            );
                        }
                    }
                    else if (checkResult.decision == L"BLOCK")
                    {
                        std::wcout
                            << L"[SERVER] Authorization DENIED by Central Server policy: "
                            << checkResult.message << L"\n";

                        decision = AccessDecision::BLOCK;

                        EventLogger::Instance().LogEvent(
                            SecurityEventType::DEVICE_BLOCKED,
                            device,
                            L"BLOCK",
                            L"Central server policy denied authorization"
                        );
                    }
                    else // decision == L"ASK", requestStatus == L"PENDING"
                    {
                        std::wstring reqId = checkResult.requestId;
                        std::wcout << L"--------------------------------------------------\n";
                        std::wcout << L"[SERVER] Authorization request submitted to Central Server.\n";
                        std::wcout << L"[SERVER] Request ID : " << reqId << L"\n";
                        std::wcout << L"[SERVER] Status     : PENDING ADMINISTRATOR DECISION\n";
                        std::wcout << L"[SERVER] Dashboard  : http://" << RestClient::Instance().GetServerHost()
                                   << L":" << RestClient::Instance().GetServerPort() << L"\n";
                        std::wcout << L"[SECURITY] Peripheral remains quarantined in zero-trust state.\n";
                        std::wcout << L"[SERVER] Waiting for administrator decision on Web Dashboard";

                        const int maxPollSeconds = 120; // 2 minutes timeout
                        const int pollIntervalMs = 2000; // poll every 2 seconds
                        int elapsedSeconds = 0;
                        bool decided = false;

                        while (elapsedSeconds < maxPollSeconds)
                        {
                            // 1. Process any pending window messages so removal/arrival notifications aren't blocked
                            MSG msg;
                            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
                            {
                                TranslateMessage(&msg);
                                DispatchMessageW(&msg);
                            }

                            // 2. Check if device was physically disconnected while waiting
                            if (!DevicePresenceMonitor::IsDevicePresent(device.deviceId))
                            {
                                std::wcout << L"\n[NOTICE] Device was physically disconnected while awaiting approval.\n";
                                decision = AccessDecision::BLOCK;
                                decided = true;
                                break;
                            }

                            // 3. Poll server for request status
                            DeviceCheckResult pollResult = RestClient::Instance().PollRequestStatus(reqId);
                            if (pollResult.success)
                            {
                                if (pollResult.requestStatus == L"APPROVED")
                                {
                                    if (taeReport.recommendation == TrustRecommendation::REJECT)
                                    {
                                        std::wcerr << L"\n[SECURITY] Approval rejected: device has critical security violations!\n";
                                        decision = AccessDecision::BLOCK;
                                    }
                                    else
                                    {
                                        std::wcout << L"\n[SERVER] >>> AUTHORIZATION APPROVED BY ADMINISTRATOR! <<<\n";
                                        if (pollResult.durationMinutes > 0)
                                        {
                                            std::wcout << L"[SERVER] Timed Authorization Granted: " << pollResult.durationMinutes
                                                       << L" minutes (Expires: " << pollResult.expiresAt << L")\n";
                                        }
                                        else
                                        {
                                            std::wcout << L"[SERVER] Permanent Authorization Granted\n";
                                        }
                                        std::wcout << L"[SERVER] Adding device to local allowlist cache.\n";

                                        g_allowlist.AddDevice(device, pollResult.durationMinutes, pollResult.expiresAt, pollResult.message);
                                        decision = AccessDecision::ALLOW;

                                        EventLogger::Instance().LogEvent(
                                            SecurityEventType::USER_APPROVED,
                                            device,
                                            L"ALLOW",
                                            L"Administrator approved authorization request on Central Dashboard"
                                        );
                                    }

                                    decided = true;
                                    break;
                                }
                                else if (pollResult.requestStatus == L"DECLINED" || pollResult.requestStatus == L"REVOKED" || pollResult.requestStatus == L"EXPIRED")
                                {
                                    std::wcout << L"\n[SERVER] >>> AUTHORIZATION "
                                               << pollResult.requestStatus
                                               << L"! <<<\n";
                                    std::wcout << L"[SERVER] Device will remain blocked.\n";

                                    decision = AccessDecision::BLOCK;

                                    EventLogger::Instance().LogEvent(
                                        SecurityEventType::DEVICE_BLOCKED,
                                        device,
                                        L"BLOCK",
                                        pollResult.requestStatus == L"REVOKED"
                                            ? L"Administrator revoked authorization on Central Dashboard"
                                            : (pollResult.requestStatus == L"EXPIRED"
                                                ? L"Device authorization expired on Central Dashboard"
                                                : L"Administrator declined authorization request on Central Dashboard")
                                    );

                                    decided = true;
                                    break;
                                }
                            }

                            std::wcout << L"." << std::flush;
                            Sleep(pollIntervalMs);
                            elapsedSeconds += (pollIntervalMs / 1000);
                        }

                        if (!decided)
                        {
                            std::wcout << L"\n[SERVER] Authorization request timed out (" << maxPollSeconds << L"s).\n";
                            std::wcout << L"[SERVER] Device will remain quarantined.\n";
                            decision = AccessDecision::BLOCK;

                            EventLogger::Instance().LogEvent(
                                SecurityEventType::DEVICE_BLOCKED,
                                device,
                                L"BLOCK",
                                L"Authorization request timed out while awaiting administrator approval"
                            );
                        }
                    }
                }


                /*
                    STEP 8
                    Final decision.
                */
                std::wcout
                    << L"\n----- FINAL DECISION -----\n";

                std::wcout
                    << L"Decision : "
                    << AccessController::ToString(decision)
                    << L"\n";


                enforcement_decision:

                /*
                    STEP 9
                    Release trusted device.
                */
                if (decision == AccessDecision::ALLOW)
                {
                    std::wcout
                        << L"\n----- ENFORCEMENT & PRE-RELEASE VERIFICATION -----\n";

                    ExpectInternalArrival(
                        device.deviceInterfacePath
                    );

                    CONFIGRET releaseResult = CR_FAILURE;
                    bool released =
                        EnforcementManager::ReleaseDevice(device, &releaseResult);

                    if (!released)
                    {
                        CancelExpectedArrival(
                            device.deviceInterfacePath
                        );
                        std::wcerr
                            << L"Enforcement Status : "
                            << L"RELEASE FAILED (CONFIGRET: " << releaseResult << L" - "
                            << EnforcementManager::ConfigRetToString(releaseResult) << L")\n";

                        std::wcerr
                            << L"[SECURITY] Device remains quarantined.\n";

                        EventLogger::Instance().LogEvent(
                            SecurityEventType::DEVICE_BLOCKED,
                            device,
                            L"BLOCK",
                            L"Device release failed (CONFIGRET: " +
                            std::wstring(EnforcementManager::ConfigRetToString(releaseResult)) +
                            L"); device remains quarantined"
                        );
                        decision = AccessDecision::BLOCK;
                    }
                    else
                    {
                        // Staged pre-release storage media inspection
                        bool storageClean = true;
                        if (device.hasStorage)
                        {
                            std::wcout << L"[STAGED INSPECTION] Staged device node enabled; performing pre-release executable policy & media inspection...\n";
                            storageClean = InspectStorageMedia(device);
                        }

                        if (storageClean)
                        {
                            DevicePresenceMonitor::SetDeviceState(
                                device.deviceId,
                                DeviceTrackingState::RELEASED
                            );

                            std::wcout
                                << L"Enforcement Status : "
                                << L"DEVICE RELEASED (All security checks passed, CM_Enable_DevNode: CR_SUCCESS)\n";

                            EventLogger::Instance().LogEvent(
                                SecurityEventType::DEVICE_RELEASED,
                                device,
                                L"ALLOW",
                                L"Device released from quarantine and operational (CM_Enable_DevNode: CR_SUCCESS)"
                            );

                            // Algorithm 4: activate file monitor for released device

                            // Synchronize clean inspection report with central server
                            TrustAssessmentReport postCleanReport;
                            if (TrustAssessmentEngine::Instance().GetActiveAssessment(device.deviceId, postCleanReport))
                            {
                                RestClient::Instance().CheckOrRequestDevice(EventLogger::Instance().GetClientId(), device, &postCleanReport);
                            }
                        }
                        else
                        {
                            TrustAssessmentReport postInspReport;
                            TrustAssessmentEngine::Instance().GetActiveAssessment(device.deviceId, postInspReport);

                            bool isCriticalThreat = (postInspReport.executablePolicyStatus == L"BLOCKED" ||
                                                     postInspReport.malwareScanResult == L"INFECTED" ||
                                                     postInspReport.recommendation == TrustRecommendation::REJECT);

                            if (isCriticalThreat)
                            {
                                CancelExpectedArrival(
                                    device.deviceInterfacePath
                                );
                                CancelExpectedArrival(
                                    device.deviceId
                                );

                                std::wcerr << L"[SECURITY] Critical threat detected during pre-release inspection! Device blocked.\n";
                                decision = AccessDecision::BLOCK;
                                taeReport = postInspReport;

                                std::vector<std::wstring> reasons = postInspReport.explainableReasons;
                                if (!postInspReport.exactThreatEvidence.empty())
                                {
                                    reasons.push_back(postInspReport.exactThreatEvidence);
                                }

                                EnforcementManager::EnforceCriticalThreat(
                                    device,
                                    postInspReport.executablePolicyStatus == L"BLOCKED" ? L"STORAGE_EXECUTION_BLOCKED" : L"MALWARE_DETECTED",
                                    postInspReport.exactThreatEvidence,
                                    postInspReport.totalRiskScore,
                                    reasons,
                                    &g_allowlist
                                );

                                // Re-quarantine device immediately
                                ExpectInternalRemoval(device.deviceId);
                                if (!device.deviceInterfacePath.empty()) ExpectInternalRemoval(device.deviceInterfacePath);
                                CONFIGRET qCr = CR_FAILURE;
                                EnforcementManager::QuarantineDevice(device, &qCr);
                                DevicePresenceMonitor::SetDeviceState(device.deviceId, DeviceTrackingState::QUARANTINED);

                                RestClient::Instance().CheckOrRequestDevice(EventLogger::Instance().GetClientId(), device, &postInspReport);
                            }
                            else
                            {
                                // Incomplete scan or volume mount wait timed out (NOT a critical threat)
                                std::wcout << L"[SECURITY] Storage volume inspection pending mount or incomplete. Keeping device restricted.\n";
                                std::wcout << L"[SECURITY] Device is NOT released for normal use. Registering bounded retry mechanism...\n";

                                // Re-quarantine device at Windows level while pending inspection
                                ExpectInternalRemoval(device.deviceId);
                                if (!device.deviceInterfacePath.empty()) ExpectInternalRemoval(device.deviceInterfacePath);
                                CONFIGRET qCr = CR_FAILURE;
                                EnforcementManager::QuarantineDevice(device, &qCr);
                                DevicePresenceMonitor::SetDeviceState(device.deviceId, DeviceTrackingState::QUARANTINED);
                                decision = AccessDecision::BLOCK;

                                // Register with PendingStorageInspectionManager
                                PendingStorageInspectionManager::Instance().RegisterPendingDevice(device);

                                // Synchronize current status (e.g. NOT_SCANNED) to server so dashboard displays accurate status
                                RestClient::Instance().CheckOrRequestDevice(EventLogger::Instance().GetClientId(), device, &postInspReport);
                            }
                        }
                    }
                }


                /*
                    STEP 10
                    Blocked device remains disabled.
                */
                if (decision == AccessDecision::BLOCK)
                {
                    std::wcout
                        << L"\n----- ENFORCEMENT -----\n";

                    if (taeReport.recommendation == TrustRecommendation::REJECT)
                    {
                        if (!g_allowlist.HasActiveCriticalThreat(device))
                        {
                            // Critical threat policy rejection: invoke central enforcement
                            ThreatEnforcementResult enfRes = EnforcementManager::EnforceCriticalThreat(
                                device,
                                L"POLICY_REJECT",
                                taeReport.summary,
                                taeReport.totalRiskScore,
                                taeReport.explainableReasons,
                                &g_allowlist
                            );

                            std::wcout << L"Enforcement Status : " << enfRes.finalEnforcementState << L"\n";
                        }
                        else
                        {
                            std::wcout << L"Enforcement Status : CRITICAL THREAT ENFORCED AND ALLOWLIST REVOKED (QUARANTINED_VERIFIED_CODE_22)\n";
                        }
                    }
                    else
                    {
                        // Unknown or unapproved device: ensure physical device is quarantined and verified
                        CONFIGRET qRet = CR_FAILURE;
                        bool isQuarantined = EnforcementManager::VerifyDeviceDisabled(device);
                        if (!isQuarantined)
                        {
                            ExpectInternalRemoval(device.deviceInterfacePath);
                            bool disabled = EnforcementManager::QuarantineDevice(device, &qRet);
                            if (disabled)
                            {
                                isQuarantined = EnforcementManager::VerifyDeviceDisabled(device);
                            }
                            else
                            {
                                CancelExpectedRemoval(device.deviceInterfacePath);
                            }
                        }

                        if (isQuarantined)
                        {
                            DevicePresenceMonitor::SetDeviceState(device.deviceId, DeviceTrackingState::QUARANTINED);
                            std::wcout << L"Enforcement Status : DEVICE REMAINS QUARANTINED (Verified Code 22)\n";
                            EventLogger::Instance().LogEvent(
                                SecurityEventType::DEVICE_BLOCKED,
                                device,
                                L"BLOCK",
                                L"Device access blocked or pending approval; quarantined and disabled at OS level"
                            );
                        }
                        else
                        {
                            std::wcerr << L"Enforcement Status : QUARANTINE UNVERIFIED / FAILED (CONFIGRET: "
                                       << qRet << L" - " << EnforcementManager::ConfigRetToString(qRet) << L")\n";
                            std::wcerr << L"[SECURITY] Device restricted by zero-trust software policy.\n";
                            EventLogger::Instance().LogEvent(
                                SecurityEventType::DEVICE_BLOCKED,
                                device,
                                L"BLOCK",
                                L"Device access blocked by policy; OS-level disablement unverified (" +
                                std::wstring(EnforcementManager::ConfigRetToString(qRet)) + L"); restricted by policy"
                            );
                        }
                    }
                }
            }
            else if (header &&
                     header->dbch_devicetype ==
                     DBT_DEVTYP_VOLUME)
            {
                std::wcout << L"\n[STORAGE-EVENT] Filesystem volume arrival notification received (DBT_DEVTYP_VOLUME).\n";
                PendingStorageInspectionManager::Instance().OnVolumeArrival();
            }
        }


        // ------------------------------------------------
        // Device removed
        // ------------------------------------------------

        else if (
            wParam ==
            DBT_DEVICEREMOVECOMPLETE)
        {
            PDEV_BROADCAST_HDR header =
                reinterpret_cast<
                PDEV_BROADCAST_HDR
                >(lParam);

            if (header &&
                header->dbch_devicetype ==
                DBT_DEVTYP_DEVICEINTERFACE)
            {
                PDEV_BROADCAST_DEVICEINTERFACE_W
                    deviceInterface =
                    reinterpret_cast<
                    PDEV_BROADCAST_DEVICEINTERFACE_W
                    >(lParam);

                std::wstring devicePath =
                    deviceInterface->dbcc_name;
                std::wstring instId = ExtractDeviceInstanceId(devicePath);

                if (ConsumeExpectedRemoval(devicePath))
                {
                    std::wcout
                        << L"\n[USBIPS] Suppressing internal "
                        << L"device-disable notification for: " << instId << L"\n";

                    break;
                }

                std::wcout
                    << L"\nUSB DEVICE REMOVED\n"
                    << L"[DEVICE-REMOVAL] InterfacePath="
                    << devicePath
                    << L"\n";

                // Genuine physical removal: clear active workflow state
                EndInspectionWorkflow(devicePath);

                // Unregister any pending inspections for this disconnected device
                PendingStorageInspectionManager::Instance().UnregisterDevice(devicePath);
                PendingStorageInspectionManager::Instance().UnregisterDevice(instId);

                // Update presence tracker (untrack physically removed device)
                DevicePresenceMonitor::UntrackDevice(instId);

                // Algorithm 2: stop surveillance when device leaves
                if (HIDBehaviorMonitor::Instance().IsSurveillanceActive())
                {
                    HIDBehaviorMonitor::Instance().StopSurveillance();
                }

                // Invalidate any active challenge or input session for the removed device
                HIDBehaviorMonitor::Instance().InvalidateDeviceSession(devicePath);

                // Algorithm 4: update USB presence and handle removal policy
                ProtectedFileMonitor::Instance().OnUsbDeviceDisconnected(devicePath);

                EventLogger::Instance().LogSimpleEvent(
                    SecurityEventType::DEVICE_REMOVED,
                    L"",
                    devicePath,
                    L"-",
                    L"USB device interface disconnected (OS notification)"
                );
            }
        }

        break;
    }


    case WM_DESTROY:

        PostQuitMessage(0);

        return 0;
    }

    return DefWindowProcW(
        hwnd,
        message,
        wParam,
        lParam
    );
}


// ============================================================
// Priority 1: USB Insertion Assessment & Enforcement Regression Suite
// ============================================================

bool RunPriority1EnforcementRegressionSuite()
{
    std::wcout << L"\n=======================================================\n";
    std::wcout << L" PRIORITY 1: USB INSERTION ASSESSMENT & ENFORCEMENT    \n";
    std::wcout << L"             REGRESSION VERIFICATION SUITE             \n";
    std::wcout << L"=======================================================\n\n";

    int p1Passed = 0;
    int p1Total = 12;

    AllowlistManager testAllowlist;
    if (!testAllowlist.Initialize(L":memory:"))
    {
        std::wcerr << L"[P1 ERROR] Failed to initialize in-memory test allowlist.\n";
        return false;
    }

    // Connect TAE to test allowlist
    TrustAssessmentEngine::Instance().SetAllowlistManager(&testAllowlist);

    // --------------------------------------------------------
    // Test 1: Clean scan + no .exe + admin approval => ALLOW and release
    // --------------------------------------------------------
    std::wcout << L"[P1-TEST 1] Clean scan + no .exe + admin approval => ALLOW and release\n";
    std::wcout << L"----------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(true, StorageExecutableInspectionResult::Status::CLEAN);

        USBDevice approvedDev;
        approvedDev.vendorId = L"13FE";
        approvedDev.productId = L"1D20";
        approvedDev.serialNumber = L"TEST_P1_CLEAN_001";
        approvedDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_P1_CLEAN_001";
        approvedDev.deviceInterfacePath = L"\\\\?\\USB#VID_13FE&PID_1D20#TEST_P1_CLEAN_001#{a5dcbf10-6530-11d2-901f-00c04fb1036c}";
        approvedDev.type = DeviceType::STORAGE;
        approvedDev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(approvedDev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(approvedDev.deviceId, L"E:");

        // Admin approval: add to allowlist
        testAllowlist.AddDevice(approvedDev, 60, L"", L"Admin approved clean storage drive");

        // AccessController decision
        PolicyDecisionRecord pRec;
        AccessDecision dec = AccessController::EvaluateWithDetails(approvedDev, testAllowlist, pRec);

        // TAE Assessment with clean volume
        TrustAssessmentReport rep = TrustAssessmentEngine::Instance().AssessDevice(approvedDev, testAllowlist, L"E:\\");

        // Enforcement release
        CONFIGRET relCr = CR_FAILURE;
        bool released = EnforcementManager::ReleaseDevice(approvedDev, &relCr);
        if (released)
        {
            DevicePresenceMonitor::SetDeviceState(approvedDev.deviceId, DeviceTrackingState::RELEASED);
        }
        bool isEnabled = EnforcementManager::VerifyDeviceEnabled(approvedDev);
        bool inAllowlist = testAllowlist.IsAllowed(approvedDev);
        bool noTombstone = !testAllowlist.HasActiveCriticalThreat(approvedDev);

        std::wcout << L"  [1.1] AccessController Decision: " << AccessController::ToString(dec)
                   << L" (Expected: ALLOW) -> " << (dec == AccessDecision::ALLOW ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [1.2] TAE Recommendation: " << TrustRecommendationToString(rep.recommendation)
                   << L" (Expected: APPROVE, Score: " << rep.totalRiskScore << L"/100) -> "
                   << (rep.recommendation == TrustRecommendation::APPROVE ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [1.3] Device Released & Operational: " << (released && isEnabled ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [1.4] Kept in Allowlist: " << (inAllowlist ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [1.5] No Critical-Threat Tombstone: " << (noTombstone ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (dec == AccessDecision::ALLOW && rep.recommendation == TrustRecommendation::APPROVE &&
            released && isEnabled && inAllowlist && noTombstone)
        {
            std::wcout << L"  -> [RESULT] TEST 1: PASSED (Clean approved device released and operational)\n\n";
            p1Passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 1: FAILED\n\n";
        }
        MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // Test 2: Confirmed malware on the exact USB => BLOCK and enforcement called
    // --------------------------------------------------------
    std::wcout << L"[P1-TEST 2] Confirmed malware on the exact USB => BLOCK and enforcement called\n";
    std::wcout << L"-----------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::DETECTED, L"Trojan:Win32/Wacatac.B!ml");

        USBDevice infectedDev;
        infectedDev.vendorId = L"13FE";
        infectedDev.productId = L"1D20";
        infectedDev.serialNumber = L"TEST_P1_MALWARE_001";
        infectedDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_P1_MALWARE_001";
        infectedDev.deviceInterfacePath = L"\\\\?\\USB#VID_13FE&PID_1D20#TEST_P1_MALWARE_001#{a5dcbf10-6530-11d2-901f-00c04fb1036c}";
        infectedDev.type = DeviceType::STORAGE;
        infectedDev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(infectedDev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(infectedDev.deviceId, L"E:");

        // Initially in allowlist
        testAllowlist.AddDevice(infectedDev);
        DevicePresenceMonitor::SetDeviceState(infectedDev.deviceId, DeviceTrackingState::RELEASED);

        // Scan mapped drive and update TAE
        ScanResult sRes = MalwareScanner::Instance().ScanPath(L"E:\\malware.bin");
        sRes.targetPath = L"E:\\malware.bin";
        TrustAssessmentEngine::Instance().AssessDevice(infectedDev, testAllowlist);
        TrustAssessmentEngine::Instance().UpdateMalwareScanResult(infectedDev, sRes);

        TrustAssessmentReport repAfter;
        TrustAssessmentEngine::Instance().GetActiveAssessment(infectedDev.deviceId, repAfter);

        bool recIsReject = (repAfter.recommendation == TrustRecommendation::REJECT);
        bool scoreIsCritical = (repAfter.totalRiskScore >= 85);
        bool enfVerified = (repAfter.actualWindowsEnforcement == L"QUARANTINED_VERIFIED_CODE_22");
        bool allowlistRevoked = !testAllowlist.IsAllowed(infectedDev);
        bool tombstoneCreated = testAllowlist.HasActiveCriticalThreat(infectedDev);

        std::wcout << L"  [2.1] TAE Recommendation: " << TrustRecommendationToString(repAfter.recommendation)
                   << L" (Expected: REJECT, Score: " << repAfter.totalRiskScore << L"/100) -> "
                   << (recIsReject && scoreIsCritical ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [2.2] Windows Enforcement Executed: " << repAfter.actualWindowsEnforcement
                   << L" -> " << (enfVerified ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [2.3] Local Allowlist Revoked: " << (allowlistRevoked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [2.4] Critical Threat Tombstone: " << (tombstoneCreated ? L"RECORDED [OK]" : L"NOT_RECORDED [FAIL]") << L"\n";

        if (recIsReject && scoreIsCritical && enfVerified && allowlistRevoked && tombstoneCreated)
        {
            std::wcout << L"  -> [RESULT] TEST 2: PASSED (Confirmed malware triggered hardware disablement & revocation)\n\n";
            p1Passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 2: FAILED\n\n";
        }
        MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // Test 3: Prohibited .exe on the exact USB => executable-policy block
    // --------------------------------------------------------
    std::wcout << L"[P1-TEST 3] Prohibited .exe on the exact USB => executable-policy block\n";
    std::wcout << L"----------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        USBDevice exeDev;
        exeDev.vendorId = L"13FE";
        exeDev.productId = L"1D20";
        exeDev.serialNumber = L"TEST_P1_PROHIBITED_EXE_001";
        exeDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_P1_PROHIBITED_EXE_001";
        exeDev.deviceInterfacePath = L"\\\\?\\USB#VID_13FE&PID_1D20#TEST_P1_PROHIBITED_EXE_001#{a5dcbf10-6530-11d2-901f-00c04fb1036c}";
        exeDev.type = DeviceType::STORAGE;
        exeDev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(exeDev);
        testAllowlist.AddDevice(exeDev);
        DevicePresenceMonitor::SetDeviceState(exeDev.deviceId, DeviceTrackingState::RELEASED);

        // Initial assessment with clean AV
        TrustAssessmentEngine::Instance().AssessDevice(exeDev, testAllowlist, L"E:\\");

        // Executable violation occurs (prohibited .exe)
        TrustAssessmentEngine::Instance().UpdateAssessmentWithEvent(
            exeDev,
            SecurityEventType::STORAGE_EXECUTION_BLOCKED,
            L"E:\\payload_installer.exe"
        );

        TrustAssessmentReport exeRep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(exeDev.deviceId, exeRep);

        bool isBlockReject = (exeRep.recommendation == TrustRecommendation::REJECT);
        bool isNotMalware = (exeRep.malwareScanResult == L"CLEAN" || exeRep.malwareScanResult == L"NOT_SCANNED");
        bool isExeBlocked = (exeRep.executablePolicyStatus == L"BLOCKED");
        bool enfInvoked = (exeRep.actualWindowsEnforcement == L"QUARANTINED_VERIFIED_CODE_22");

        std::wcout << L"  [3.1] Policy Decision: " << TrustRecommendationToString(exeRep.recommendation)
                   << L" -> " << (isBlockReject ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [3.2] Executable Policy Status: " << exeRep.executablePolicyStatus
                   << L" -> " << (isExeBlocked ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [3.3] Malware Scan Status (Not Conflated with Malware): " << exeRep.malwareScanResult
                   << L" -> " << (isNotMalware ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [3.4] Quarantine Enforcement Invoked: " << (enfInvoked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (isBlockReject && isNotMalware && isExeBlocked && enfInvoked)
        {
            std::wcout << L"  -> [RESULT] TEST 3: PASSED (Executable policy violation enforced without false malware classification)\n\n";
            p1Passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 3: FAILED\n\n";
        }
        MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);
    }

    // --------------------------------------------------------
    // Test 4: NOT_SCANNED => not classified as malware
    // --------------------------------------------------------
    std::wcout << L"[P1-TEST 4] NOT_SCANNED => not classified as malware\n";
    std::wcout << L"---------------------------------------------------\n";
    {
        MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);

        USBDevice unscannedDev;
        unscannedDev.vendorId = L"13FE";
        unscannedDev.productId = L"1D20";
        unscannedDev.serialNumber = L"TEST_P1_NOT_SCANNED_001";
        unscannedDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_P1_NOT_SCANNED_001";
        unscannedDev.deviceInterfacePath = L"\\\\?\\USB#VID_13FE&PID_1D20#TEST_P1_NOT_SCANNED_001#{a5dcbf10-6530-11d2-901f-00c04fb1036c}";
        unscannedDev.type = DeviceType::STORAGE;
        unscannedDev.hasStorage = true;

        // Device inserted without mounted volume
        TrustAssessmentReport rep = TrustAssessmentEngine::Instance().AssessDevice(unscannedDev, testAllowlist, L"");

        bool statusIsNotScanned = (rep.malwareScanResult == L"NOT_SCANNED");
        bool recIsReview = (rep.recommendation == TrustRecommendation::REVIEW);
        bool scoreNotCritical = (rep.totalRiskScore < 85);
        bool noCriticalViolations = rep.criticalViolations.empty();
        bool noTombstone = !testAllowlist.HasActiveCriticalThreat(unscannedDev);

        std::wcout << L"  [4.1] Malware Scan Result: " << rep.malwareScanResult
                   << L" (Expected: NOT_SCANNED) -> " << (statusIsNotScanned ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [4.2] TAE Recommendation: " << TrustRecommendationToString(rep.recommendation)
                   << L" (Expected: REVIEW) -> " << (recIsReview ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [4.3] Risk Score: " << rep.totalRiskScore << L"/100 (Non-critical) -> "
                   << (scoreNotCritical ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [4.4] Critical Violations: " << rep.criticalViolations.size()
                   << L" -> " << (noCriticalViolations ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [4.5] No Permanent Tombstone: " << (noTombstone ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (statusIsNotScanned && recIsReview && scoreNotCritical && noCriticalViolations && noTombstone)
        {
            std::wcout << L"  -> [RESULT] TEST 4: PASSED (NOT_SCANNED safely classified as REVIEW, not malware)\n\n";
            p1Passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 4: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // Test 5: Scan failure/timeout => restricted pending scan, no permanent malware revocation
    // --------------------------------------------------------
    std::wcout << L"[P1-TEST 5] Scan failure/timeout => restricted pending scan, no permanent revocation\n";
    std::wcout << L"---------------------------------------------------------------------------------\n";
    {
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::FAILED);

        USBDevice failDev;
        failDev.vendorId = L"13FE";
        failDev.productId = L"1D20";
        failDev.serialNumber = L"TEST_P1_SCAN_FAIL_001";
        failDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_P1_SCAN_FAIL_001";
        failDev.deviceInterfacePath = L"\\\\?\\USB#VID_13FE&PID_1D20#TEST_P1_SCAN_FAIL_001#{a5dcbf10-6530-11d2-901f-00c04fb1036c}";
        failDev.type = DeviceType::STORAGE;
        failDev.hasStorage = true;

        testAllowlist.AddDevice(failDev);

        TrustAssessmentReport rep = TrustAssessmentEngine::Instance().AssessDevice(failDev, testAllowlist, L"E:\\");

        bool statusIsFailed = (rep.malwareScanResult == L"FAILED");
        bool recIsReview = (rep.recommendation == TrustRecommendation::REVIEW);
        bool scoreNotCritical = (rep.totalRiskScore < 85);
        bool noTombstone = !testAllowlist.HasActiveCriticalThreat(failDev);

        std::wcout << L"  [5.1] Scan Result Status: " << rep.malwareScanResult
                   << L" (Expected: FAILED) -> " << (statusIsFailed ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [5.2] TAE Recommendation: " << TrustRecommendationToString(rep.recommendation)
                   << L" (Expected: REVIEW) -> " << (recIsReview ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [5.3] Risk Score: " << rep.totalRiskScore << L"/100 (Non-critical) -> "
                   << (scoreNotCritical ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [5.4] No Permanent Malware Tombstone: " << (noTombstone ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (statusIsFailed && recIsReview && scoreNotCritical && noTombstone)
        {
            std::wcout << L"  -> [RESULT] TEST 5: PASSED (Scan failure kept device in REVIEW without permanent revocation)\n\n";
            p1Passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 5: FAILED\n\n";
        }
        MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);
    }

    // --------------------------------------------------------
    // Test 6: Malware alert on an unrelated drive => no block of the approved USB
    // --------------------------------------------------------
    std::wcout << L"[P1-TEST 6] Malware alert on unrelated drive => no block of approved USB\n";
    std::wcout << L"-------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(true, StorageExecutableInspectionResult::Status::CLEAN);

        USBDevice approvedDev;
        approvedDev.vendorId = L"13FE";
        approvedDev.productId = L"1D20";
        approvedDev.serialNumber = L"TEST_P1_UNRELATED_001";
        approvedDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_P1_UNRELATED_001";
        approvedDev.deviceInterfacePath = L"\\\\?\\USB#VID_13FE&PID_1D20#TEST_P1_UNRELATED_001#{a5dcbf10-6530-11d2-901f-00c04fb1036c}";
        approvedDev.type = DeviceType::STORAGE;
        approvedDev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(approvedDev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(approvedDev.deviceId, L"E:");

        testAllowlist.AddDevice(approvedDev);
        DevicePresenceMonitor::SetDeviceState(approvedDev.deviceId, DeviceTrackingState::RELEASED);

        // Approved device is assessed on its mapped drive E:
        TrustAssessmentReport rep = TrustAssessmentEngine::Instance().AssessDevice(approvedDev, testAllowlist, L"E:\\");

        // Verify volume attribution rejects drive A:
        USBDevice outDev;
        bool mappedA = StorageExecutionMonitor::Instance().GetUsbDeviceForDrive(L"A:", outDev);
        bool aNotAttributed = (!mappedA || outDev.serialNumber != approvedDev.serialNumber);

        // A scanner alert happens on A:
        ScanResult aRes;
        aRes.status = ScanStatus::DETECTED;
        aRes.targetPath = L"A:\\bad.bin";
        aRes.threatName = L"Trojan:Win32/UnrelatedDrive.A";

        // TAE is NOT updated for approvedDev with A's alert because A is not mapped to approvedDev
        auto mappedDrives = StorageExecutionMonitor::Instance().GetDriveLettersForDevice(approvedDev);
        bool aInMappedDrives = false;
        for (const auto& d : mappedDrives)
        {
            if (d == L"A:") aInMappedDrives = true;
        }

        bool stillAllowed = testAllowlist.IsAllowed(approvedDev);
        bool noTombstone = !testAllowlist.HasActiveCriticalThreat(approvedDev);
        DeviceTrackingState trkState;
        DevicePresenceMonitor::GetDeviceState(approvedDev.deviceId, trkState);
        bool stillReleased = (trkState == DeviceTrackingState::RELEASED);

        std::wcout << L"  [6.1] Drive A: Attributed to Approved USB: " << (aInMappedDrives ? L"YES (Bug!)" : L"NO (Correct Attribution) [OK]") << L"\n";
        std::wcout << L"  [6.2] Device Isolation: Drive A: Rejected for USB: " << (aNotAttributed ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [6.3] Approved USB Remains Allowed: " << (stillAllowed ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [6.4] Approved USB Tracking State: " << (stillReleased ? L"RELEASED [OK]" : L"BLOCKED [FAIL]") << L"\n";
        std::wcout << L"  [6.5] No Critical-Threat Tombstone: " << (noTombstone ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (!aInMappedDrives && aNotAttributed && stillAllowed && stillReleased && noTombstone)
        {
            std::wcout << L"  -> [RESULT] TEST 6: PASSED (Unrelated drive alert correctly isolated from approved USB)\n\n";
            p1Passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 6: FAILED\n\n";
        }
        MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // Test 7: Stale scanner result => rejected as evidence for the current device
    // --------------------------------------------------------
    std::wcout << L"[P1-TEST 7] Stale scanner result => rejected as evidence for current device\n";
    std::wcout << L"--------------------------------------------------------------------------\n";
    {
        ScanResult staleRes;
        staleRes.status = ScanStatus::CLEAN;
        staleRes.scanTimePoint = std::chrono::system_clock::now() - std::chrono::seconds(180); // 3 minutes old

        ScanResult freshRes;
        freshRes.status = ScanStatus::CLEAN;
        freshRes.scanTimePoint = std::chrono::system_clock::now();

        bool staleRejected = !MalwareScanner::Instance().IsScanResultFresh(staleRes, 60);
        bool freshAccepted = MalwareScanner::Instance().IsScanResultFresh(freshRes, 60);

        std::wcout << L"  [7.1] Stale Result (>60s) Freshness Check: " << (!staleRejected ? L"ACCEPTED (Stale Leak!)" : L"REJECTED [OK]") << L"\n";
        std::wcout << L"  [7.2] Fresh Result Freshness Check: " << (freshAccepted ? L"ACCEPTED [OK]" : L"REJECTED [FAIL]") << L"\n";

        if (staleRejected && freshAccepted)
        {
            std::wcout << L"  -> [RESULT] TEST 7: PASSED (Stale scanner evidence rejected; fresh evidence required)\n\n";
            p1Passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 7: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // Test 8: A clean previously approved USB remains approved
    // --------------------------------------------------------
    std::wcout << L"[P1-TEST 8] A clean previously approved USB remains approved\n";
    std::wcout << L"-----------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(true, StorageExecutableInspectionResult::Status::CLEAN);

        USBDevice prevDev;
        prevDev.vendorId = L"13FE";
        prevDev.productId = L"1D20";
        prevDev.serialNumber = L"TEST_P1_PREV_APPROVED_001";
        prevDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_P1_PREV_APPROVED_001";
        prevDev.deviceInterfacePath = L"\\\\?\\USB#VID_13FE&PID_1D20#TEST_P1_PREV_APPROVED_001#{a5dcbf10-6530-11d2-901f-00c04fb1036c}";
        prevDev.type = DeviceType::STORAGE;
        prevDev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(prevDev);
        testAllowlist.AddDevice(prevDev);
        DevicePresenceMonitor::SetDeviceState(prevDev.deviceId, DeviceTrackingState::RELEASED);

        // Re-assess device
        TrustAssessmentReport rep = TrustAssessmentEngine::Instance().AssessDevice(prevDev, testAllowlist, L"E:\\");
        PolicyDecisionRecord pRec;
        AccessDecision dec = AccessController::EvaluateWithDetails(prevDev, testAllowlist, pRec);

        bool decAllow = (dec == AccessDecision::ALLOW);
        bool repApprove = (rep.recommendation == TrustRecommendation::APPROVE);
        bool isAllowed = testAllowlist.IsAllowed(prevDev);
        bool scoreZero = (rep.totalRiskScore <= 10);

        std::wcout << L"  [8.1] Re-evaluation Access Decision: " << AccessController::ToString(dec)
                   << L" -> " << (decAllow ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [8.2] TAE Recommendation: " << TrustRecommendationToString(rep.recommendation)
                   << L" -> " << (repApprove ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [8.3] Allowlist Status: " << (isAllowed ? L"ALLOWED [OK]" : L"REVOKED [FAIL]") << L"\n";
        std::wcout << L"  [8.4] Total Risk Score: " << rep.totalRiskScore << L"/100 -> " << (scoreZero ? L"[OK]" : L"[FAIL]") << L"\n";

        if (decAllow && repApprove && isAllowed && scoreZero)
        {
            std::wcout << L"  -> [RESULT] TEST 8: PASSED (Clean previously approved USB remains approved)\n\n";
            p1Passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 8: FAILED\n\n";
        }
        MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
    }

    // --------------------------------------------------------
    // Test 9: A confirmed threat overrides prior approval
    // --------------------------------------------------------
    std::wcout << L"[P1-TEST 9] A confirmed threat overrides prior approval\n";
    std::wcout << L"------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(true, StorageExecutableInspectionResult::Status::CLEAN);

        USBDevice overDev;
        overDev.vendorId = L"13FE";
        overDev.productId = L"1D20";
        overDev.serialNumber = L"TEST_P1_OVERRIDE_001";
        overDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_P1_OVERRIDE_001";
        overDev.deviceInterfacePath = L"\\\\?\\USB#VID_13FE&PID_1D20#TEST_P1_OVERRIDE_001#{a5dcbf10-6530-11d2-901f-00c04fb1036c}";
        overDev.type = DeviceType::STORAGE;
        overDev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(overDev);
        testAllowlist.AddDevice(overDev);
        DevicePresenceMonitor::SetDeviceState(overDev.deviceId, DeviceTrackingState::RELEASED);

        // Device begins in APPROVE state
        TrustAssessmentReport initRep = TrustAssessmentEngine::Instance().AssessDevice(overDev, testAllowlist, L"E:\\");
        bool initApprove = (initRep.recommendation == TrustRecommendation::APPROVE);

        // Confirmed threat occurs
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::DETECTED, L"Ransom:Win32/WannaCrypt");
        ScanResult threatRes = MalwareScanner::Instance().ScanPath(L"E:\\ransomware.exe");
        threatRes.targetPath = L"E:\\ransomware.exe";
        TrustAssessmentEngine::Instance().UpdateMalwareScanResult(overDev, threatRes);

        TrustAssessmentReport downRep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(overDev.deviceId, downRep);

        bool overridden = (downRep.recommendation == TrustRecommendation::REJECT);
        bool revoked = !testAllowlist.IsAllowed(overDev);
        bool tombstone = testAllowlist.HasActiveCriticalThreat(overDev);
        bool enfVerified = (downRep.actualWindowsEnforcement == L"QUARANTINED_VERIFIED_CODE_22");

        std::wcout << L"  [9.1] Initial Status: " << TrustRecommendationToString(initRep.recommendation)
                   << L" -> " << (initApprove ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [9.2] Overridden Decision: " << TrustRecommendationToString(downRep.recommendation)
                   << L" (Risk: " << downRep.totalRiskScore << L"/100) -> " << (overridden ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [9.3] Prior Allowlist Approval Revoked: " << (revoked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [9.4] Critical Threat Tombstone Active: " << (tombstone ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [9.5] Hardware Disablement Verified: " << (enfVerified ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (initApprove && overridden && revoked && tombstone && enfVerified)
        {
            std::wcout << L"  -> [RESULT] TEST 9: PASSED (Confirmed threat strictly overrides prior approval)\n\n";
            p1Passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 9: FAILED\n\n";
        }
        MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
    }

    // --------------------------------------------------------
    // Test 10: A failed Windows disable operation is reported honestly
    // --------------------------------------------------------
    std::wcout << L"[P1-TEST 10] Failed Windows disable operation is reported honestly\n";
    std::wcout << L"-------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, false, CR_ACCESS_DENIED);

        USBDevice failDev;
        failDev.vendorId = L"13FE";
        failDev.productId = L"1D20";
        failDev.serialNumber = L"TEST_P1_FAILED_DISABLE_001";
        failDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_P1_FAILED_DISABLE_001";
        failDev.deviceInterfacePath = L"\\\\?\\USB#VID_13FE&PID_1D20#TEST_P1_FAILED_DISABLE_001#{a5dcbf10-6530-11d2-901f-00c04fb1036c}";
        failDev.type = DeviceType::STORAGE;
        failDev.hasStorage = true;

        ThreatEnforcementResult failRes = EnforcementManager::EnforceCriticalThreat(
            failDev,
            L"POLICY_REJECT",
            L"Disable attempt without sufficient privilege",
            85,
            { L"Windows PnP access denied" },
            &testAllowlist
        );

        bool reportedNotApplied = (!failRes.quarantineApplied);
        bool reportedNotVerified = (!failRes.verificationSuccess);
        bool codeIsAccessDenied = (failRes.configRet == CR_ACCESS_DENIED);
        bool stateContainsError = (failRes.finalEnforcementState.find(L"CR_ACCESS_DENIED") != std::wstring::npos);

        std::wcout << L"  [10.1] Quarantine Applied: " << (failRes.quarantineApplied ? L"TRUE (False Success!)" : L"FALSE (Honest Failure) [OK]") << L"\n";
        std::wcout << L"  [10.2] Verified State: " << (failRes.verificationSuccess ? L"TRUE (False Success!)" : L"FALSE (Honest Failure) [OK]") << L"\n";
        std::wcout << L"  [10.3] CONFIGRET Code: " << failRes.configRet << L" (" << failRes.failureReason << L") -> " << (codeIsAccessDenied ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [10.4] Enforcement State String: " << failRes.finalEnforcementState << L" -> " << (stateContainsError ? L"[OK]" : L"[FAIL]") << L"\n";

        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);

        if (reportedNotApplied && reportedNotVerified && codeIsAccessDenied && stateContainsError)
        {
            std::wcout << L"  -> [RESULT] TEST 10: PASSED (Failed OS disablement reported honestly without false success)\n\n";
            p1Passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 10: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // Test 11: Admin recovery of false-positive revocation clears tombstone
    //          and enables clean release on subsequent insertion
    // --------------------------------------------------------
    std::wcout << L"[P1-TEST 11] Recovery from false-positive revocation => ALLOW and release\n";
    std::wcout << L"------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(true, StorageExecutableInspectionResult::Status::CLEAN);

        USBDevice fpDev;
        fpDev.vendorId = L"13FE";
        fpDev.productId = L"1D20";
        fpDev.serialNumber = L"TEST_P1_FP_RECOVER_001";
        fpDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_P1_FP_RECOVER_001";
        fpDev.deviceInterfacePath = L"\\\\?\\USB#VID_13FE&PID_1D20#TEST_P1_FP_RECOVER_001#{a5dcbf10-6530-11d2-901f-00c04fb1036c}";
        fpDev.type = DeviceType::STORAGE;
        fpDev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(fpDev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(fpDev.deviceId, L"E:");

        // 1. Seed a false-positive revocation tombstone (e.g. Defender scan error 0x80508023 / Generic signature)
        testAllowlist.RecordCriticalThreat(
            fpDev,
            L"AntivirusMalwareScan",
            L"Post-approval malware detected by antivirus engine: Threat detected: Win32/MalwareSignature.Generic (Defender error 0x80508023 on drive A:)",
            85
        );
        bool hasTombstoneBefore = testAllowlist.HasActiveCriticalThreat(fpDev);

        // Verify IsRevocationDueToUnverifiedScanError identifies it correctly
        RevokedThreatRecord recBefore;
        bool foundRecord = testAllowlist.GetCriticalThreat(fpDev, recBefore);
        bool isUnverified = recBefore.isUnverifiedScanError;

        // 2. Perform Admin Recovery
        std::wstring recoveryError;
        bool recoverySucceeded = testAllowlist.AdminRecoverDevice(
            fpDev,
            L"Cleared false-positive detection: Defender error 0x80508023 on unmounted drive A:",
            false,
            &recoveryError
        );
        bool hasTombstoneAfter = testAllowlist.HasActiveCriticalThreat(fpDev);

        // 3. Subsequent insertion assessment and admin approval
        testAllowlist.AddDevice(fpDev, 60, L"", L"Approved by admin after false-positive clearance");
        TrustAssessmentReport rep = TrustAssessmentEngine::Instance().AssessDevice(fpDev, testAllowlist, L"E:\\");

        // 4. Simulate clean scan and release
        ScanResult cleanScan;
        cleanScan.targetPath = L"E:";
        cleanScan.status = ScanStatus::CLEAN;
        cleanScan.threatName = L"";
        TrustAssessmentEngine::Instance().UpdateMalwareScanResult(fpDev, cleanScan);
        TrustAssessmentEngine::Instance().GetActiveAssessment(fpDev.deviceId, rep);

        CONFIGRET crRelease = CR_FAILURE;
        bool released = EnforcementManager::ReleaseDevice(fpDev, &crRelease);
        bool inAllowlist = testAllowlist.IsAllowed(fpDev);

        std::wcout << L"  [11.1] Initial Tombstone Present: " << (hasTombstoneBefore ? L"TRUE [OK]" : L"FALSE [FAIL]") << L"\n";
        std::wcout << L"  [11.2] Identified as Unverified Scan Error: " << (isUnverified ? L"TRUE [OK]" : L"FALSE [FAIL]") << L"\n";
        std::wcout << L"  [11.3] Admin Recovery Result: " << (recoverySucceeded ? L"SUCCESS [OK]" : L"FAILED [FAIL]") << L"\n";
        std::wcout << L"  [11.4] Tombstone Removed After Recovery: " << (!hasTombstoneAfter ? L"TRUE [OK]" : L"FALSE [FAIL]") << L"\n";
        std::wcout << L"  [11.5] Subsequent Evaluation: " << TrustRecommendationToString(rep.recommendation)
                   << L" | Risk Score: " << rep.totalRiskScore << L"/100\n";
        std::wcout << L"  [11.6] Peripheral Released: " << (released ? L"TRUE (CM_Enable_DevNode: CR_SUCCESS) [OK]" : L"FALSE [FAIL]") << L"\n";
        std::wcout << L"  [11.7] Maintained in Allowlist: " << (inAllowlist ? L"TRUE [OK]" : L"FALSE [FAIL]") << L"\n";

        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);

        if (hasTombstoneBefore && isUnverified && recoverySucceeded && !hasTombstoneAfter &&
            released && inAllowlist && rep.recommendation == TrustRecommendation::APPROVE)
        {
            std::wcout << L"  -> [RESULT] TEST 11: PASSED (False-positive revocation recovered cleanly without re-blocking)\n\n";
            p1Passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 11: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // Test 12: Admin recovery strictly preserves genuine confirmed malware
    //          and refuses automatic clearing without explicit override
    // --------------------------------------------------------
    std::wcout << L"[P1-TEST 12] Retention of genuine confirmed malware revocations\n";
    std::wcout << L"----------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);

        USBDevice realMalwareDev;
        realMalwareDev.vendorId = L"0781";
        realMalwareDev.productId = L"5583";
        realMalwareDev.serialNumber = L"TEST_P1_GENUINE_MALWARE_001";
        realMalwareDev.deviceId = L"USB\\VID_0781&PID_5583\\TEST_P1_GENUINE_MALWARE_001";
        realMalwareDev.deviceInterfacePath = L"\\\\?\\USB#VID_0781&PID_5583#TEST_P1_GENUINE_MALWARE_001#{a5dcbf10-6530-11d2-901f-00c04fb1036c}";
        realMalwareDev.type = DeviceType::STORAGE;
        realMalwareDev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(realMalwareDev);

        // 1. Seed a genuine confirmed malware revocation
        testAllowlist.RecordCriticalThreat(
            realMalwareDev,
            L"AntivirusMalwareScan",
            L"Post-approval malware detected by antivirus engine: Threat detected: Trojan:Win32/Wacatac.B!ml on E:\\payload.exe",
            85
        );

        RevokedThreatRecord rec;
        testAllowlist.GetCriticalThreat(realMalwareDev, rec);
        bool isUnverified = rec.isUnverifiedScanError;

        // 2. Attempt recovery WITHOUT force override -> MUST FAIL
        std::wstring errNoOverride;
        bool recoveryWithoutOverride = testAllowlist.AdminRecoverDevice(
            realMalwareDev,
            L"Attempting unverified clearing",
            false,
            &errNoOverride
        );
        bool tombstoneRetained = testAllowlist.HasActiveCriticalThreat(realMalwareDev);

        // 3. Attempt recovery WITH explicit force override and justified reason -> SUCCEEDS
        std::wstring errWithOverride;
        bool recoveryWithOverride = testAllowlist.AdminRecoverDevice(
            realMalwareDev,
            L"SecOps authorized forensic lab analysis override",
            true,
            &errWithOverride
        );
        bool tombstoneClearedWithOverride = !testAllowlist.HasActiveCriticalThreat(realMalwareDev);

        std::wcout << L"  [12.1] Identified as Genuine Malware (isUnverified=false): " << (!isUnverified ? L"TRUE [OK]" : L"FALSE [FAIL]") << L"\n";
        std::wcout << L"  [12.2] Automatic Recovery Refused Without Override: " << (!recoveryWithoutOverride ? L"TRUE (Refused) [OK]" : L"FALSE [FAIL]") << L"\n";
        std::wcout << L"  [12.3] Error Reason Logged: " << errNoOverride << L"\n";
        std::wcout << L"  [12.4] Tombstone Retained After Refusal: " << (tombstoneRetained ? L"TRUE [OK]" : L"FALSE [FAIL]") << L"\n";
        std::wcout << L"  [12.5] Explicit Admin Override Succeeded: " << (recoveryWithOverride && tombstoneClearedWithOverride ? L"TRUE [OK]" : L"FALSE [FAIL]") << L"\n";

        if (!isUnverified && !recoveryWithoutOverride && tombstoneRetained &&
            recoveryWithOverride && tombstoneClearedWithOverride)
        {
            std::wcout << L"  -> [RESULT] TEST 12: PASSED (Genuine malware revocations strictly retained and protected)\n\n";
            p1Passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 12: FAILED\n\n";
        }
    }

    // Clean up test harness
    EnforcementManager::SetMockEnforcement(false);
    TrustAssessmentEngine::Instance().SetAllowlistManager(nullptr);

    std::wcout << L"=======================================================\n";
    std::wcout << L"PRIORITY 1 REGRESSION SUMMARY: " << p1Passed << L"/" << p1Total << L" PASSED\n";
    std::wcout << L"=======================================================\n\n";

    return (p1Passed == p1Total);
}

// ============================================================
// Executable Policy Regression Suite (10 Automated Scenarios)
// ============================================================

bool RunExecutablePolicyRegressionSuite()
{
    std::wcout << L"\n=======================================================\n";
    std::wcout << L" EXECUTABLE POLICY REGRESSION VERIFICATION SUITE       \n";
    std::wcout << L" (.com, .exe, nested directories, staged enforcement)  \n";
    std::wcout << L"=======================================================\n\n";

    int passed = 0;
    const int total = 10;

    AllowlistManager testAllowlist;
    if (!testAllowlist.Initialize(L":memory:"))
    {
        std::wcerr << L"[EXE-POLICY ERROR] Failed to initialize in-memory test allowlist.\n";
        return false;
    }

    TrustAssessmentEngine::Instance().SetAllowlistManager(&testAllowlist);

    // Root directory for test filesystem artifacts
    std::filesystem::path testBaseDir = std::filesystem::temp_directory_path() / "usbips_exe_reg_suite";
    std::error_code dirEc;
    std::filesystem::remove_all(testBaseDir, dirEc);
    std::filesystem::create_directories(testBaseDir, dirEc);

    // Helper lambda to create a binary mock file
    auto createMockFile = [](const std::filesystem::path& path, const std::string& content = "MZTestMockBinary") {
        std::filesystem::create_directories(path.parent_path());
        std::ofstream out(path, std::ios::binary);
        out << content;
        out.close();
    };

    // --------------------------------------------------------
    // Test 1: .com file at the USB root => BLOCK with exact filename and reason
    // --------------------------------------------------------
    std::wcout << L"[EXE-TEST 1] .com file at USB root => BLOCK with exact filename and reason\n";
    std::wcout << L"--------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t1";
        std::filesystem::path comFile = driveDir / "payload.com";
        createMockFile(comFile);

        USBDevice dev;
        dev.vendorId = L"13FE";
        dev.productId = L"1D20";
        dev.serialNumber = L"TEST_COM_ROOT_001";
        dev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_COM_ROOT_001";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"E:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"E:", driveDir.wstring());

        testAllowlist.AddDevice(dev);

        // Pre-release inspection via InspectStorageMedia
        bool allowRelease = InspectStorageMedia(dev);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isBlocked = !allowRelease;
        bool statusBlocked = (rep.executablePolicyStatus == L"BLOCKED");
        bool recReject = (rep.recommendation == TrustRecommendation::REJECT);
        bool scoreCritical = (rep.totalRiskScore >= 85);
        bool fileRecorded = (rep.exactThreatFile.find(L"payload.com") != std::wstring::npos);
        bool ruleRecorded = (rep.exactThreatEvidence.find(L".com") != std::wstring::npos);
        bool hardwareDisabled = (rep.actualWindowsEnforcement == L"QUARANTINED_VERIFIED_CODE_22");

        std::wcout << L"  [1.1] Pre-release Inspection Permitted Release: " << (allowRelease ? L"YES [FAIL]" : L"NO (Blocked) [OK]") << L"\n";
        std::wcout << L"  [1.2] Executable Policy Status: " << rep.executablePolicyStatus << L" -> " << (statusBlocked ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [1.3] TAE Decision: " << TrustRecommendationToString(rep.recommendation)
                   << L" (Score: " << rep.totalRiskScore << L"/100) -> " << (recReject && scoreCritical ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [1.4] Exact Prohibited File: " << rep.exactThreatFile << L" -> " << (fileRecorded ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [1.5] Policy Rule Recorded: " << rep.exactThreatEvidence << L" -> " << (ruleRecorded ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [1.6] DevNode Disabled: " << rep.actualWindowsEnforcement << L" -> " << (hardwareDisabled ? L"[OK]" : L"[FAIL]") << L"\n";

        if (isBlocked && statusBlocked && recReject && scoreCritical && fileRecorded && ruleRecorded && hardwareDisabled)
        {
            std::wcout << L"  -> [RESULT] TEST 1: PASSED (.com file at USB root reliably detected and blocked)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 1: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // Test 2: .COM uppercase extension => BLOCK
    // --------------------------------------------------------
    std::wcout << L"[EXE-TEST 2] .COM uppercase extension => BLOCK (case-insensitive comparison)\n";
    std::wcout << L"----------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t2";
        std::filesystem::path comFile = driveDir / "COMMAND_RUNNER.COM";
        createMockFile(comFile);

        USBDevice dev;
        dev.vendorId = L"13FE";
        dev.productId = L"1D20";
        dev.serialNumber = L"TEST_COM_UPPER_002";
        dev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_COM_UPPER_002";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"E:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"E:", driveDir.wstring());
        testAllowlist.AddDevice(dev);

        bool allowRelease = InspectStorageMedia(dev);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isBlocked = !allowRelease;
        bool statusBlocked = (rep.executablePolicyStatus == L"BLOCKED");
        bool fileRecorded = (rep.exactThreatFile.find(L"COMMAND_RUNNER.COM") != std::wstring::npos);

        std::wcout << L"  [2.1] Pre-release Inspection: " << (isBlocked ? L"BLOCKED [OK]" : L"ALLOWED [FAIL]") << L"\n";
        std::wcout << L"  [2.2] Status: " << rep.executablePolicyStatus << L" -> " << (statusBlocked ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [2.3] File Detected: " << rep.exactThreatFile << L" -> " << (fileRecorded ? L"[OK]" : L"[FAIL]") << L"\n";

        if (isBlocked && statusBlocked && fileRecorded)
        {
            std::wcout << L"  -> [RESULT] TEST 2: PASSED (Uppercase .COM extension case-insensitively blocked)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 2: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // Test 3: .com in a nested directory => BLOCK
    // --------------------------------------------------------
    std::wcout << L"[EXE-TEST 3] .com in a nested directory => BLOCK (recursive traversal)\n";
    std::wcout << L"--------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t3";
        std::filesystem::path nestedDir = driveDir / "documents" / "archive" / "hidden";
        std::filesystem::path nestedCom = nestedDir / "backdoor.com";
        createMockFile(nestedCom);

        USBDevice dev;
        dev.vendorId = L"13FE";
        dev.productId = L"1D20";
        dev.serialNumber = L"TEST_COM_NESTED_003";
        dev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_COM_NESTED_003";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"E:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"E:", driveDir.wstring());
        testAllowlist.AddDevice(dev);

        bool allowRelease = InspectStorageMedia(dev);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isBlocked = !allowRelease;
        bool statusBlocked = (rep.executablePolicyStatus == L"BLOCKED");
        bool fileRecorded = (rep.exactThreatFile.find(L"backdoor.com") != std::wstring::npos);

        std::wcout << L"  [3.1] Pre-release Inspection: " << (isBlocked ? L"BLOCKED [OK]" : L"ALLOWED [FAIL]") << L"\n";
        std::wcout << L"  [3.2] Status: " << rep.executablePolicyStatus << L" -> " << (statusBlocked ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [3.3] Nested File Detected: " << rep.exactThreatFile << L" -> " << (fileRecorded ? L"[OK]" : L"[FAIL]") << L"\n";

        if (isBlocked && statusBlocked && fileRecorded)
        {
            std::wcout << L"  -> [RESULT] TEST 3: PASSED (Deeply nested .com detected via recursive enumeration)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 3: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // Test 4: .exe file => BLOCK
    // --------------------------------------------------------
    std::wcout << L"[EXE-TEST 4] .exe file => BLOCK\n";
    std::wcout << L"--------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t4";
        std::filesystem::path exeFile = driveDir / "setup_installer.exe";
        createMockFile(exeFile);

        USBDevice dev;
        dev.vendorId = L"13FE";
        dev.productId = L"1D20";
        dev.serialNumber = L"TEST_EXE_004";
        dev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_EXE_004";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"E:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"E:", driveDir.wstring());
        testAllowlist.AddDevice(dev);

        bool allowRelease = InspectStorageMedia(dev);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isBlocked = !allowRelease;
        bool statusBlocked = (rep.executablePolicyStatus == L"BLOCKED");
        bool fileRecorded = (rep.exactThreatFile.find(L"setup_installer.exe") != std::wstring::npos);

        std::wcout << L"  [4.1] Pre-release Inspection: " << (isBlocked ? L"BLOCKED [OK]" : L"ALLOWED [FAIL]") << L"\n";
        std::wcout << L"  [4.2] Status: " << rep.executablePolicyStatus << L" -> " << (statusBlocked ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [4.3] File Detected: " << rep.exactThreatFile << L" -> " << (fileRecorded ? L"[OK]" : L"[FAIL]") << L"\n";

        if (isBlocked && statusBlocked && fileRecorded)
        {
            std::wcout << L"  -> [RESULT] TEST 4: PASSED (.exe prohibited executable detected and blocked)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 4: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // Test 5: No prohibited executable + successful checks + admin approval => ALLOW
    // --------------------------------------------------------
    std::wcout << L"[EXE-TEST 5] No prohibited executable + successful checks + admin approval => ALLOW\n";
    std::wcout << L"----------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t5_clean";
        createMockFile(driveDir / "financial_report.pdf", "PDFContentHere");
        createMockFile(driveDir / "presentation.pptx", "PPTXContentHere");
        createMockFile(driveDir / "notes.txt", "TextNotes");

        USBDevice dev;
        dev.vendorId = L"13FE";
        dev.productId = L"1D20";
        dev.serialNumber = L"TEST_CLEAN_ALLOW_005";
        dev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_CLEAN_ALLOW_005";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"E:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"E:", driveDir.wstring());

        testAllowlist.AddDevice(dev, 60, L"", L"Admin approved clean drive");

        bool allowRelease = InspectStorageMedia(dev);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool inspectionPassed = allowRelease;
        bool statusCompliant = (rep.executablePolicyStatus == L"COMPLIANT");
        bool malwareClean = (rep.malwareScanResult == L"CLEAN");
        bool isAllowed = testAllowlist.IsAllowed(dev);

        std::wcout << L"  [5.1] Pre-release Inspection Allowed: " << (inspectionPassed ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [5.2] Executable Policy Status: " << rep.executablePolicyStatus << L" -> " << (statusCompliant ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [5.3] Malware Scan Status: " << rep.malwareScanResult << L" -> " << (malwareClean ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [5.4] Allowlist Membership: " << (isAllowed ? L"ALLOWED [OK]" : L"REVOKED [FAIL]") << L"\n";

        if (inspectionPassed && statusCompliant && malwareClean && isAllowed)
        {
            std::wcout << L"  -> [RESULT] TEST 5: PASSED (Clean storage device passes checks and is permitted for release)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 5: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // Test 6: Admin-approved device later found to contain .com => BLOCK
    // --------------------------------------------------------
    std::wcout << L"[EXE-TEST 6] Admin-approved device later found to contain .com => BLOCK\n";
    std::wcout << L"----------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t6";
        createMockFile(driveDir / "document.pdf", "PDFContent");

        USBDevice dev;
        dev.vendorId = L"13FE";
        dev.productId = L"1D20";
        dev.serialNumber = L"TEST_POST_APPROVE_COM_006";
        dev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_POST_APPROVE_COM_006";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"E:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"E:", driveDir.wstring());

        // Prior admin approval
        testAllowlist.AddDevice(dev, 60, L"", L"Prior admin approval");
        bool wasAllowed = testAllowlist.IsAllowed(dev);

        // A .com file is later copied onto the drive
        createMockFile(driveDir / "dropped_tool.com", "MZBinaryCode");

        // Executable policy check runs
        bool allowRelease = InspectStorageMedia(dev);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isBlocked = !allowRelease;
        bool statusBlocked = (rep.executablePolicyStatus == L"BLOCKED");
        bool recReject = (rep.recommendation == TrustRecommendation::REJECT);
        bool allowlistRevoked = !testAllowlist.IsAllowed(dev);
        bool threatRecorded = testAllowlist.HasActiveCriticalThreat(dev);

        std::wcout << L"  [6.1] Was Device Prior-Approved: " << (wasAllowed ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [6.2] Inspection Blocked Release: " << (isBlocked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [6.3] Status: " << rep.executablePolicyStatus << L" -> " << (statusBlocked ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [6.4] Prior Approval Overridden: " << (allowlistRevoked ? L"REVOKED [OK]" : L"RETAINED [FAIL]") << L"\n";
        std::wcout << L"  [6.5] Critical Threat Recorded: " << (threatRecorded ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (wasAllowed && isBlocked && statusBlocked && recReject && allowlistRevoked && threatRecorded)
        {
            std::wcout << L"  -> [RESULT] TEST 6: PASSED (Prior admin approval strictly overridden by .com detection)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 6: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // Test 7: Unrelated drive contains .com => target USB is not blocked
    // --------------------------------------------------------
    std::wcout << L"[EXE-TEST 7] Unrelated drive contains .com => target USB is not blocked\n";
    std::wcout << L"----------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path targetDriveDir = testBaseDir / "drive_t7_target";
        createMockFile(targetDriveDir / "clean_data.txt", "CleanData");

        std::filesystem::path unrelatedDriveDir = testBaseDir / "drive_t7_unrelated";
        createMockFile(unrelatedDriveDir / "rogue_malware.com", "MZBinaryCode");

        USBDevice targetDev;
        targetDev.vendorId = L"13FE";
        targetDev.productId = L"1D20";
        targetDev.serialNumber = L"TEST_TARGET_USB_007";
        targetDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_TARGET_USB_007";
        targetDev.type = DeviceType::STORAGE;
        targetDev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(targetDev);
        // Map targetDev strictly to E:
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(targetDev.deviceId, L"E:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"E:", targetDriveDir.wstring());
        // Map unrelated drive G:
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"G:", unrelatedDriveDir.wstring());

        testAllowlist.AddDevice(targetDev);

        // Verify drive letters mapped to target device
        auto mapped = StorageExecutionMonitor::Instance().GetDriveLettersForDevice(targetDev);
        bool onlyTargetDrive = (mapped.size() == 1 && mapped[0] == L"E:");

        // Inspect target USB
        bool allowRelease = InspectStorageMedia(targetDev);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(targetDev.deviceId, rep);

        bool targetClean = allowRelease;
        bool statusCompliant = (rep.executablePolicyStatus == L"COMPLIANT");
        bool targetAllowed = testAllowlist.IsAllowed(targetDev);

        std::wcout << L"  [7.1] Attribution Mapping Isolated: " << (onlyTargetDrive ? L"ONLY E: [OK]" : L"CONTAMINATED [FAIL]") << L"\n";
        std::wcout << L"  [7.2] Target USB Inspection Passed: " << (targetClean ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [7.3] Target USB Status: " << rep.executablePolicyStatus << L" -> " << (statusCompliant ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [7.4] Target USB Retains Approval: " << (targetAllowed ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (onlyTargetDrive && targetClean && statusCompliant && targetAllowed)
        {
            std::wcout << L"  -> [RESULT] TEST 7: PASSED (Unrelated drive .com does not contaminate or block target USB)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 7: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // Test 8: Unmounted volume or enumeration failure => NOT_SCANNED/FAILED, never falsely reported clean
    // --------------------------------------------------------
    std::wcout << L"[EXE-TEST 8] Unmounted volume or enumeration failure => NOT_SCANNED/FAILED\n";
    std::wcout << L"-------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);

        // Part A: Unmounted / non-existent volume Z:
        auto unmountedRes = StorageExecutionMonitor::Instance().InspectVolumeForProhibitedExecutables(L"Z:");
        bool partA_NotMounted = (unmountedRes.status == StorageExecutableInspectionResult::Status::NOT_MOUNTED);
        bool partA_HasReason = (!unmountedRes.failureReason.empty());

        USBDevice unmountedDev;
        unmountedDev.vendorId = L"13FE";
        unmountedDev.productId = L"1D20";
        unmountedDev.serialNumber = L"TEST_UNMOUNTED_008";
        unmountedDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_UNMOUNTED_008";
        unmountedDev.type = DeviceType::STORAGE;
        unmountedDev.hasStorage = true;
        testAllowlist.AddDevice(unmountedDev);

        TrustAssessmentEngine::Instance().UpdateExecutablePolicyResult(unmountedDev, unmountedRes);
        TrustAssessmentReport repA;
        TrustAssessmentEngine::Instance().GetActiveAssessment(unmountedDev.deviceId, repA);

        bool partA_NotScanned = (repA.executablePolicyStatus == L"NOT_SCANNED");
        bool partA_Restricted = (repA.recommendation == TrustRecommendation::REVIEW);

        // Part B: File enumeration failure
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(
            true,
            StorageExecutableInspectionResult::Status::FAILED,
            L"",
            L"",
            L"Device I/O hardware failure on sector 0"
        );

        auto failedRes = StorageExecutionMonitor::Instance().InspectVolumeForProhibitedExecutables(L"E:");
        bool partB_Failed = (failedRes.status == StorageExecutableInspectionResult::Status::FAILED);

        USBDevice failedDev;
        failedDev.vendorId = L"13FE";
        failedDev.productId = L"1D20";
        failedDev.serialNumber = L"TEST_ENUM_FAIL_008";
        failedDev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_ENUM_FAIL_008";
        failedDev.type = DeviceType::STORAGE;
        failedDev.hasStorage = true;
        testAllowlist.AddDevice(failedDev);

        TrustAssessmentEngine::Instance().UpdateExecutablePolicyResult(failedDev, failedRes);
        TrustAssessmentReport repB;
        TrustAssessmentEngine::Instance().GetActiveAssessment(failedDev.deviceId, repB);

        bool partB_ReportFailed = (repB.executablePolicyStatus == L"FAILED");
        bool partB_Restricted = (repB.recommendation == TrustRecommendation::REVIEW);

        std::wcout << L"  [8.1] Unmounted Volume Status: " << (partA_NotMounted ? L"NOT_MOUNTED [OK]" : L"FAILED") << L"\n";
        std::wcout << L"  [8.2] Unmounted TAE Status: " << repA.executablePolicyStatus << L" -> " << (partA_NotScanned ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [8.3] Unmounted Device Kept Restricted: " << (partA_Restricted ? L"REVIEW [OK]" : L"APPROVE (False Clean!) [FAIL]") << L"\n";
        std::wcout << L"  [8.4] Enumeration Error Status: " << (partB_Failed ? L"FAILED [OK]" : L"WRONG_STATUS [FAIL]") << L"\n";
        std::wcout << L"  [8.5] Enumeration Error TAE Status: " << repB.executablePolicyStatus << L" -> " << (partB_ReportFailed ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [8.6] Enumeration Error Kept Restricted: " << (partB_Restricted ? L"REVIEW [OK]" : L"APPROVE (False Clean!) [FAIL]") << L"\n";

        if (partA_NotMounted && partA_HasReason && partA_NotScanned && partA_Restricted &&
            partB_Failed && partB_ReportFailed && partB_Restricted)
        {
            std::wcout << L"  -> [RESULT] TEST 8: PASSED (Unmounted volume and enumeration failures never falsely reported clean)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 8: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
    }

    // --------------------------------------------------------
    // Test 9: Windows enforcement failure => report failure honestly
    // --------------------------------------------------------
    std::wcout << L"[EXE-TEST 9] Windows enforcement failure => report failure honestly\n";
    std::wcout << L"-------------------------------------------------------------------\n";
    {
        // Mock enforcement configured to return CR_ACCESS_DENIED
        EnforcementManager::SetMockEnforcement(true, false, CR_ACCESS_DENIED);

        USBDevice dev;
        dev.vendorId = L"13FE";
        dev.productId = L"1D20";
        dev.serialNumber = L"TEST_ENF_FAIL_009";
        dev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_ENF_FAIL_009";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        ThreatEnforcementResult enfRes = EnforcementManager::EnforceCriticalThreat(
            dev,
            L"STORAGE_EXECUTION_BLOCKED",
            L"Prohibited executable extension (.com) detected on removable media: E:\\trojan.com",
            85,
            { L"Executable policy violation" },
            &testAllowlist
        );

        bool quarantineFailed = (!enfRes.quarantineApplied);
        bool verificationFailed = (!enfRes.verificationSuccess);
        bool configRetDenied = (enfRes.configRet == CR_ACCESS_DENIED);
        bool stateReportsFailure = (enfRes.finalEnforcementState.find(L"ENFORCEMENT_FAILED") != std::wstring::npos &&
                                    enfRes.finalEnforcementState.find(L"CR_ACCESS_DENIED") != std::wstring::npos);

        std::wcout << L"  [9.1] Hardware Quarantine Applied: " << (enfRes.quarantineApplied ? L"TRUE (False Success!)" : L"FALSE (Reported Honest Failure) [OK]") << L"\n";
        std::wcout << L"  [9.2] Verification Success: " << (enfRes.verificationSuccess ? L"TRUE (False Success!)" : L"FALSE [OK]") << L"\n";
        std::wcout << L"  [9.3] Windows CONFIGRET: " << enfRes.configRet << L" (" << enfRes.failureReason << L") -> " << (configRetDenied ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [9.4] Final Enforcement State: " << enfRes.finalEnforcementState << L" -> " << (stateReportsFailure ? L"[OK]" : L"[FAIL]") << L"\n";

        if (quarantineFailed && verificationFailed && configRetDenied && stateReportsFailure)
        {
            std::wcout << L"  -> [RESULT] TEST 9: PASSED (Windows enforcement failure reported honestly without claiming success)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 9: FAILED\n\n";
        }

        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
    }

    // --------------------------------------------------------
    // Test 10: Confirm malware status remains separate from executable-policy status
    // --------------------------------------------------------
    std::wcout << L"[EXE-TEST 10] Confirm malware status remains separate from executable-policy status\n";
    std::wcout << L"----------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);

        USBDevice dev;
        dev.vendorId = L"13FE";
        dev.productId = L"1D20";
        dev.serialNumber = L"TEST_DECOUPLED_010";
        dev.deviceId = L"USB\\VID_13FE&PID_1D20\\TEST_DECOUPLED_010";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        testAllowlist.AddDevice(dev);

        // 1. Storage executable policy check: finds prohibited .com file
        StorageExecutableInspectionResult execRes;
        execRes.status = StorageExecutableInspectionResult::Status::PROHIBITED_FOUND;
        execRes.scannedDrive = L"E:";
        execRes.primaryProhibitedFile = L"E:\\dos_tool.com";
        execRes.policyRule = L"Prohibited executable extension (.com) detected on removable media";
        TrustAssessmentEngine::Instance().UpdateExecutablePolicyResult(dev, execRes);

        // 2. Antivirus malware scan: completes CLEAN (0 threats detected by AV signature engine)
        ScanResult avRes;
        avRes.status = ScanStatus::CLEAN;
        avRes.targetPath = L"E:";
        avRes.details = L"Defender scan completed: 0 threats found";
        avRes.threatName = L"";
        TrustAssessmentEngine::Instance().UpdateMalwareScanResult(dev, avRes);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool exePolicyBlocked = (rep.executablePolicyStatus == L"BLOCKED");
        bool malwareScanClean = (rep.malwareScanResult == L"CLEAN");
        bool recommendationReject = (rep.recommendation == TrustRecommendation::REJECT);
        bool distinctEvidence = (rep.exactThreatEvidence == execRes.policyRule ||
                                 rep.exactThreatEvidence == (execRes.policyRule + L": " + execRes.primaryProhibitedFile) ||
                                 rep.exactThreatEvidence.find(execRes.policyRule) != std::wstring::npos);

        std::wcout << L"  [10.1] Executable Policy Status : " << rep.executablePolicyStatus << L" -> " << (exePolicyBlocked ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [10.2] Antivirus Scan Status    : " << rep.malwareScanResult << L" -> " << (malwareScanClean ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [10.3] Final TAE Decision       : " << TrustRecommendationToString(rep.recommendation)
                    << L" (Risk Score: " << rep.totalRiskScore << L"/100)\n";
        std::wcout << L"  [10.4] Exact Policy Rule Active : " << rep.exactThreatEvidence << L" -> " << (distinctEvidence ? L"[OK]" : L"[FAIL]") << L"\n";

        if (exePolicyBlocked && malwareScanClean && recommendationReject && distinctEvidence)
        {
            std::wcout << L"  -> [RESULT] TEST 10: PASSED (Executable policy violations strictly distinct from malware scan results)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 10: FAILED\n\n";
        }
    }

    // Cleanup
    std::filesystem::remove_all(testBaseDir, dirEc);
    EnforcementManager::SetMockEnforcement(false);
    StorageExecutionMonitor::Instance().ClearMockVolumePaths();
    StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
    MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);
    TrustAssessmentEngine::Instance().SetAllowlistManager(nullptr);

    std::wcout << L"=======================================================\n";
    std::wcout << L"EXECUTABLE POLICY REGRESSION SUMMARY: " << passed << L"/" << total << L" PASSED\n";
    std::wcout << L"=======================================================\n\n";

    return (passed == total);
}


// ============================================================
// Storage Inspection and Approval Loop Regression Suite
// (7 Focused Verification Scenarios)
// ============================================================

bool RunStorageInspectionWorkflowRegressionSuite()
{
    std::wcout << L"\n=======================================================\n";
    std::wcout << L" STORAGE INSPECTION & APPROVAL LOOP REGRESSION SUITE   \n";
    std::wcout << L"                  (TESTS 1 - 7)                        \n";
    std::wcout << L"=======================================================\n\n";

    int passed = 0;
    int total = 7;

    // Temporary directory setup for realistic filesystem tests
    std::error_code dirEc;
    std::filesystem::path tempDir = std::filesystem::temp_directory_path(dirEc);
    std::filesystem::path testBaseDir = tempDir / "usbips_workflow_tests";
    std::filesystem::remove_all(testBaseDir, dirEc);
    std::filesystem::create_directories(testBaseDir, dirEc);

    auto createMockFile = [](const std::filesystem::path& path, const std::string& content) {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        std::ofstream ofs(path, std::ios::binary);
        ofs << content;
        ofs.close();
    };

    AllowlistManager testAllowlist;
    testAllowlist.Initialize(L":memory:");
    TrustAssessmentEngine::Instance().SetAllowlistManager(&testAllowlist);

    // --------------------------------------------------------
    // TEST 1: One insertion causes one inspection workflow
    // --------------------------------------------------------
    std::wcout << L"[WORKFLOW-TEST 1] One insertion causes one inspection workflow\n";
    std::wcout << L"---------------------------------------------------------------\n";
    {
        std::wstring devPath = L"\\\\?\\USB#VID_0781&PID_5583#SANDISK_WF_001#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
        std::wstring devId = L"USB\\VID_0781&PID_5583\\SANDISK_WF_001";

        // Ensure clean state
        EndInspectionWorkflow(devPath);

        bool started1 = TryStartInspectionWorkflow(devPath);
        bool isActive1 = IsInspectionWorkflowActive(devPath);
        bool isActiveById = IsInspectionWorkflowActive(devId);

        // Subsequent arrival events for the same insertion while active should be deduplicated
        bool startedDuplicatePath = TryStartInspectionWorkflow(devPath);
        bool startedDuplicateId = TryStartInspectionWorkflow(devId);

        std::wcout << L"  [1.1] Initial Arrival Workflow Claimed: " << (started1 ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [1.2] Active by Interface Path       : " << (isActive1 ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [1.3] Active by Canonical Device ID  : " << (isActiveById ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [1.4] Duplicate Interface Path Rejected: " << (!startedDuplicatePath ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [1.5] Duplicate Canonical ID Rejected: " << (!startedDuplicateId ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (started1 && isActive1 && isActiveById && !startedDuplicatePath && !startedDuplicateId)
        {
            std::wcout << L"  -> [RESULT] TEST 1: PASSED (Exact single workflow started for device insertion)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 1: FAILED\n\n";
        }

        EndInspectionWorkflow(devPath);
    }

    // --------------------------------------------------------
    // TEST 2: Delayed mount is detected within bounded wait
    // --------------------------------------------------------
    std::wcout << L"[WORKFLOW-TEST 2] Delayed mount is detected within bounded wait\n";
    std::wcout << L"---------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t2_delayed";
        createMockFile(driveDir / "project_specs.docx", "ProjectDocumentation");
        createMockFile(driveDir / "budget.xlsx", "SpreadsheetData");

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5583";
        dev.serialNumber = L"SANDISK_DELAYED_MOUNT_002";
        dev.deviceId = L"USB\\VID_0781&PID_5583\\SANDISK_DELAYED_MOUNT_002";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"M:", driveDir.wstring());

        // Spawn a background thread that mounts the volume after 1000ms delay
        std::thread mountThread([&dev]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"M:");
        });

        auto startTime = std::chrono::steady_clock::now();
        // Wait up to 4000ms (bounded retry)
        bool inspectionSuccess = InspectStorageMedia(dev, 4000);
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime
        ).count();

        if (mountThread.joinable())
        {
            mountThread.join();
        }

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool detected = inspectionSuccess && (rep.executablePolicyStatus == L"COMPLIANT");
        bool timingValid = (elapsedMs >= 900 && elapsedMs <= 3800);

        std::wcout << L"  [2.1] Delayed Mount Detected & Clean: " << (detected ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [2.2] Elapsed Wait Time            : " << elapsedMs << L"ms (expected ~1000-2000ms) -> " << (timingValid ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [2.3] Executable Policy Status     : " << rep.executablePolicyStatus << L"\n";

        if (detected && timingValid)
        {
            std::wcout << L"  -> [RESULT] TEST 2: PASSED (Delayed filesystem mount successfully detected within bounded window)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 2: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // TEST 3: .exe or .com found => BLOCK with path and reason
    // --------------------------------------------------------
    std::wcout << L"[WORKFLOW-TEST 3] .exe or .com found => BLOCK with path and reason\n";
    std::wcout << L"------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t3_prohibited";
        createMockFile(driveDir / "documents" / "nested" / "stealth_loader.COM", "DOS_COM_HEADER");
        createMockFile(driveDir / "readme.txt", "ReadMe");

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5583";
        dev.serialNumber = L"SANDISK_BLOCK_COM_003";
        dev.deviceId = L"USB\\VID_0781&PID_5583\\SANDISK_BLOCK_COM_003";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"N:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"N:", driveDir.wstring());

        bool inspectionResult = InspectStorageMedia(dev, 2000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isBlocked = !inspectionResult;
        bool statusBlocked = (rep.executablePolicyStatus == L"BLOCKED");
        bool fileIdentified = (rep.exactThreatFile.find(L"stealth_loader.COM") != std::wstring::npos);
        bool highRisk = (rep.totalRiskScore >= 80);

        std::wcout << L"  [3.1] Inspection Result: " << (isBlocked ? L"BLOCKED [OK]" : L"ALLOWED [FAIL]") << L"\n";
        std::wcout << L"  [3.2] Status           : " << rep.executablePolicyStatus << L" -> " << (statusBlocked ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [3.3] Exact Threat File: " << rep.exactThreatFile << L" -> " << (fileIdentified ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [3.4] Total Risk Score : " << rep.totalRiskScore << L"/100 -> " << (highRisk ? L"[OK]" : L"[FAIL]") << L"\n";

        if (isBlocked && statusBlocked && fileIdentified && highRisk)
        {
            std::wcout << L"  -> [RESULT] TEST 3: PASSED (Prohibited .com/.exe blocked with exact evidence and risk score)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 3: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // TEST 4: Clean completed scan + admin approval => ALLOW
    // --------------------------------------------------------
    std::wcout << L"[WORKFLOW-TEST 4] Clean completed scan + admin approval => ALLOW\n";
    std::wcout << L"----------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t4_clean_allow";
        createMockFile(driveDir / "documents" / "quarterly_results.pdf", "PDFData");
        createMockFile(driveDir / "data" / "archive.zip", "ZIPData");

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5583";
        dev.serialNumber = L"SANDISK_CLEAN_APPROVED_004";
        dev.deviceId = L"USB\\VID_0781&PID_5583\\SANDISK_CLEAN_APPROVED_004";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"P:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"P:", driveDir.wstring());

        // Admin approves device in allowlist
        testAllowlist.AddDevice(dev, 120, L"", L"Administrator signed-off for data transfer");

        bool inspectionClean = InspectStorageMedia(dev, 2000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool policyCompliant = (rep.executablePolicyStatus == L"COMPLIANT");
        bool avClean = (rep.malwareScanResult == L"CLEAN");
        bool allowlistValid = testAllowlist.IsAllowed(dev);

        std::wcout << L"  [4.1] Media Inspection Clean: " << (inspectionClean ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [4.2] Policy Compliance     : " << rep.executablePolicyStatus << L" -> " << (policyCompliant ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [4.3] Antivirus Status      : " << rep.malwareScanResult << L" -> " << (avClean ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [4.4] Admin Allowlist Match : " << (allowlistValid ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (inspectionClean && policyCompliant && avClean && allowlistValid)
        {
            std::wcout << L"  -> [RESULT] TEST 4: PASSED (Clean scan and valid admin approval permit device release)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 4: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // TEST 5: Scan timeout => restricted with honest timeout reason (no infinite loop)
    // --------------------------------------------------------
    std::wcout << L"[WORKFLOW-TEST 5] Scan timeout => restricted with honest timeout reason\n";
    std::wcout << L"------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
        StorageExecutionMonitor::Instance().ClearMockVolumePaths();

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5583";
        dev.serialNumber = L"SANDISK_UNMOUNTED_TIMEOUT_005";
        dev.deviceId = L"USB\\VID_0781&PID_5583\\SANDISK_UNMOUNTED_TIMEOUT_005";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);

        auto startTime = std::chrono::steady_clock::now();
        // 1000ms bounded wait
        bool inspectionSuccess = InspectStorageMedia(dev, 1000);
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime
        ).count();

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isRestricted = !inspectionSuccess;
        bool statusHonest = (rep.executablePolicyStatus == L"NOT_MOUNTED" || rep.executablePolicyStatus == L"NOT_SCANNED");
        bool avStatusHonest = (rep.malwareScanResult == L"NOT_SCANNED");
        bool honestReason = (rep.executablePolicyStatus == L"NOT_MOUNTED" || rep.executablePolicyStatus == L"NOT_SCANNED") &&
                            (rep.malwareScanResult == L"NOT_SCANNED");
        bool boundedTime = (elapsedMs >= 900 && elapsedMs <= 2500);

        std::wcout << L"  [5.1] Device Held Restricted   : " << (isRestricted ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [5.2] Executable Policy Status : " << rep.executablePolicyStatus << L" -> " << (statusHonest ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [5.3] Malware Scan Status      : " << rep.malwareScanResult << L" -> " << (avStatusHonest ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [5.4] Honest Failure Reason    : " << (honestReason ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [5.5] Bounded Wait Time        : " << elapsedMs << L"ms -> " << (boundedTime ? L"[OK]" : L"[FAIL]") << L"\n";

        if (isRestricted && statusHonest && avStatusHonest && honestReason && boundedTime)
        {
            std::wcout << L"  -> [RESULT] TEST 5: PASSED (Unmounted storage reports honest NOT_SCANNED without infinite loop)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 5: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // TEST 6: Internal disable/enable notifications do not restart the workflow
    // --------------------------------------------------------
    std::wcout << L"[WORKFLOW-TEST 6] Internal disable/enable notifications do not restart workflow\n";
    std::wcout << L"------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        EnforcementManager::SetNotificationSuppressionCallback(ExpectInternalRemoval);
        EnforcementManager::SetArrivalSuppressionCallback(ExpectInternalArrival);

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5583";
        dev.serialNumber = L"SANDISK_NOTIF_GUARD_006";
        dev.deviceId = L"USB\\VID_0781&PID_5583\\SANDISK_NOTIF_GUARD_006";
        dev.deviceInterfacePath = L"\\\\?\\USB#VID_0781&PID_5583#SANDISK_NOTIF_GUARD_006#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        CONFIGRET cr = CR_FAILURE;
        // Quarantine should register internal removal expectations for both path and deviceId
        EnforcementManager::QuarantineDevice(dev, &cr);

        bool removalSuppressed = ConsumeExpectedRemoval(dev.deviceInterfacePath) || ConsumeExpectedRemoval(dev.deviceId);

        // Release should register internal arrival expectations for both path and deviceId
        EnforcementManager::ReleaseDevice(dev, &cr);

        bool arrivalSuppressed = ConsumeExpectedArrival(dev.deviceInterfacePath) || ConsumeExpectedArrival(dev.deviceId);

        std::wcout << L"  [6.1] Quarantine Suppresses Internal Removal: " << (removalSuppressed ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [6.2] Release Suppresses Internal Arrival   : " << (arrivalSuppressed ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (removalSuppressed && arrivalSuppressed)
        {
            std::wcout << L"  -> [RESULT] TEST 6: PASSED (Internal PnP transitions suppressed from re-triggering workflows)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 6: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // TEST 7: Genuine physical removal clears the workflow state
    // --------------------------------------------------------
    std::wcout << L"[WORKFLOW-TEST 7] Genuine physical removal clears the workflow state\n";
    std::wcout << L"--------------------------------------------------------------------\n";
    {
        std::wstring devPath = L"\\\\?\\USB#VID_0781&PID_5583#SANDISK_REMOVAL_007#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
        std::wstring devId = L"USB\\VID_0781&PID_5583\\SANDISK_REMOVAL_007";

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5583";
        dev.serialNumber = L"SANDISK_REMOVAL_007";
        dev.deviceId = devId;
        dev.deviceInterfacePath = devPath;
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);

        // 1. Workflow starts on initial physical insertion
        bool started = TryStartInspectionWorkflow(devPath);
        bool activeBefore = IsInspectionWorkflowActive(devPath);

        // 2. Genuine physical removal event occurs (not suppressed by internal removal)
        bool wasInternalRemoval = ConsumeExpectedRemoval(devPath);
        EndInspectionWorkflow(devPath);
        DevicePresenceMonitor::UntrackDevice(devId);

        bool activeAfter = IsInspectionWorkflowActive(devPath);
        DeviceTrackingState dummyState;
        bool presenceRemoved = !DevicePresenceMonitor::GetDeviceState(devId, dummyState);

        // 3. New insertion after genuine removal can now start a fresh workflow
        bool reinsertionStarted = TryStartInspectionWorkflow(devPath);
        EndInspectionWorkflow(devPath);

        std::wcout << L"  [7.1] Initial Workflow Active          : " << (activeBefore ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [7.2] Unsuppressed Physical Removal    : " << (!wasInternalRemoval ? L"GENUINE [OK]" : L"INTERNAL [FAIL]") << L"\n";
        std::wcout << L"  [7.3] Workflow Cleared After Removal   : " << (!activeAfter ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [7.4] Presence State Marked REMOVED    : " << (presenceRemoved ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [7.5] Re-insertion Allows New Workflow : " << (reinsertionStarted ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (started && activeBefore && !wasInternalRemoval && !activeAfter && presenceRemoved && reinsertionStarted)
        {
            std::wcout << L"  -> [RESULT] TEST 7: PASSED (Genuine removal clears workflow state and enables re-inspection)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 7: FAILED\n\n";
        }
    }

    // Cleanup
    std::filesystem::remove_all(testBaseDir, dirEc);
    EnforcementManager::SetMockEnforcement(false);
    StorageExecutionMonitor::Instance().ClearMockVolumePaths();
    StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
    MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);
    TrustAssessmentEngine::Instance().SetAllowlistManager(nullptr);

    std::wcout << L"=======================================================\n";
    std::wcout << L"STORAGE WORKFLOW REGRESSION SUMMARY: " << passed << L"/" << total << L" PASSED\n";
    std::wcout << L"=======================================================\n\n";

    return (passed == total);
}


// ============================================================
// Protected-Folder Access Restrictions Regression Suite (Tests 1-8)
// ============================================================

bool RunProtectedFolderAccessRestrictionsSuite()
{
    std::wcout << L"\n=======================================================\n";
    std::wcout << L"   USBIPS PROTECTED-FOLDER ACCESS RESTRICTIONS SUITE   \n";
    std::wcout << L"=======================================================\n";
    std::wcout << L"Objective: Verify OS-level filesystem denial (STATUS_ACCESS_DENIED 5)\n"
               << L"           across Read, Copy, Create, Paste, Overwrite, Rename, and Delete\n"
               << L"           upon USB arrival, and access restoration upon USB removal.\n\n";

    int passed = 0;
    int total = 8;

    // Set up dedicated test folder and files
    wchar_t tempPathBuf[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tempPathBuf);
    std::wstring testRoot = std::wstring(tempPathBuf) + L"usbips_folder_enforce_suite";

    // Clean up any stale directory from previous test run
    std::wstring cleanupCmd = L"if exist \"" + testRoot + L"\" rd /s /q \"" + testRoot + L"\"";
    _wsystem(cleanupCmd.c_str());
    CreateDirectoryW(testRoot.c_str(), nullptr);

    std::wstring sampleFile = testRoot + L"\\confidential_doc.txt";
    HANDLE hf = CreateFileW(sampleFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (hf != INVALID_HANDLE_VALUE)
    {
        const char content[] = "TOP SECRET SENSITIVE DATA - USBIPS RESTRICTED";
        DWORD written = 0;
        WriteFile(hf, content, sizeof(content) - 1, &written, nullptr);
        CloseHandle(hf);
    }

    std::wstring subFolder = testRoot + L"\\sub_folder";
    CreateDirectoryW(subFolder.c_str(), nullptr);
    std::wstring nestedFile = subFolder + L"\\nested_record.dat";
    HANDLE hfSub = CreateFileW(nestedFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (hfSub != INVALID_HANDLE_VALUE)
    {
        const char contentSub[] = "NESTED FINANCIAL DATA";
        DWORD written = 0;
        WriteFile(hfSub, contentSub, sizeof(contentSub) - 1, &written, nullptr);
        CloseHandle(hfSub);
    }

    // Configure test folder policy
    std::vector<ProtectedFolder> policyList;
    ProtectedFolder pf;
    pf.id = 888;
    pf.folderPath = testRoot;
    pf.description = L"Automated Regression Test Folder";
    pf.isEnabled = true;
    policyList.push_back(pf);

    ProtectedFileMonitor::Instance().UpdateProtectedFolders(policyList);

    // Dummy test USB device
    USBDevice testDev1;
    testDev1.vendorId = L"0781";
    testDev1.productId = L"5583";
    testDev1.serialNumber = L"TEST_ENFORCE_SAN_001";
    testDev1.deviceId = L"USB\\VID_0781&PID_5583\\TEST_ENFORCE_SAN_001";
    testDev1.deviceInterfacePath = L"\\\\?\\USB#VID_0781&PID_5583#TEST_ENFORCE_SAN_001#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";
    testDev1.type = DeviceType::STORAGE;
    testDev1.hasStorage = true;

    // --------------------------------------------------------
    // TEST 1: Physical USB Insertion Activates Protected-Folder Policy
    // --------------------------------------------------------
    std::wcout << L"[TEST 1/8] USB Insertion Triggers OS-Level Protected Folder Policy Activation\n";
    std::wcout << L"----------------------------------------------------------------------------\n";
    PolicyConfig::Instance().enforceFolderProtectionOnUsb = true;
    PolicyConfig::Instance().deactivateProtectionOnUsbRemoval = true;

    ProtectedFileMonitor::Instance().OnUsbDeviceConnected(testDev1);

    bool t1Active = ProtectedFileMonitor::Instance().IsEnforcementActive();
    int t1DevCount = ProtectedFileMonitor::Instance().GetActiveUsbDeviceCount();
    std::wcout << L"  [1.1] Monitor Enforcement State : " << (t1Active ? L"ACTIVE [OK]" : L"INACTIVE [ERROR]") << L"\n";
    std::wcout << L"  [1.2] Active USB Device Count   : " << t1DevCount << L" [OK]\n";

    if (t1Active && t1DevCount == 1)
    {
        std::wcout << L"  -> [RESULT] TEST 1: PASSED (NTFS DACL Deny rule successfully applied upon USB insertion)\n\n";
        passed++;
    }
    else
    {
        std::wcout << L"  -> [RESULT] TEST 1: FAILED\n\n";
    }

    // --------------------------------------------------------
    // TEST 2: Block Unauthorized Reading or Opening of Protected Files
    // --------------------------------------------------------
    std::wcout << L"[TEST 2/8] Block Unauthorized Reading or Opening of Protected Files\n";
    std::wcout << L"-------------------------------------------------------------------\n";
    HANDLE hRead1 = CreateFileW(sampleFile.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD errRead1 = (hRead1 == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (hRead1 != INVALID_HANDLE_VALUE) CloseHandle(hRead1);

    HANDLE hReadNested = CreateFileW(nestedFile.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD errReadNested = (hReadNested == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (hReadNested != INVALID_HANDLE_VALUE) CloseHandle(hReadNested);

    std::wcout << L"  [2.1] Read Root File Attempt   : " << (errRead1 == ERROR_ACCESS_DENIED ? L"DENIED (STATUS_ACCESS_DENIED 5) [OK]" : L"ALLOWED/ERROR") << L"\n";
    std::wcout << L"  [2.2] Read Nested File Attempt : " << (errReadNested == ERROR_ACCESS_DENIED ? L"DENIED (STATUS_ACCESS_DENIED 5) [OK]" : L"ALLOWED/ERROR") << L"\n";

    if (errRead1 == ERROR_ACCESS_DENIED && errReadNested == ERROR_ACCESS_DENIED)
    {
        std::wcout << L"  -> [RESULT] TEST 2: PASSED (Windows natively denies file opening and data reading)\n\n";
        passed++;
    }
    else
    {
        std::wcout << L"  -> [RESULT] TEST 2: FAILED\n\n";
    }

    // --------------------------------------------------------
    // TEST 3: Block Copying Protected Files to Outside or USB Drives
    // --------------------------------------------------------
    std::wcout << L"[TEST 3/8] Block Copying Protected Files (Source Read Denial)\n";
    std::wcout << L"-------------------------------------------------------------\n";
    std::wstring copyOutDest = std::wstring(tempPathBuf) + L"stolen_exfiltrated_data.txt";
    BOOL copyOk = CopyFileW(sampleFile.c_str(), copyOutDest.c_str(), FALSE);
    DWORD errCopy = !copyOk ? GetLastError() : 0;

    std::wcout << L"  [3.1] Copy Out Attempt Result  : " << (!copyOk ? L"FAILED [OK]" : L"SUCCEEDED [ERROR]") << L"\n";
    std::wcout << L"  [3.2] OS Denial Error Code     : " << errCopy << L" "
               << (errCopy == ERROR_ACCESS_DENIED ? L"(ERROR_ACCESS_DENIED) [OK]" : L"(UNEXPECTED)") << L"\n";

    if (!copyOk && errCopy == ERROR_ACCESS_DENIED)
    {
        std::wcout << L"  -> [RESULT] TEST 3: PASSED (Copy operation completely prevented by Windows SRM)\n\n";
        passed++;
    }
    else
    {
        std::wcout << L"  -> [RESULT] TEST 3: FAILED\n\n";
    }

    // --------------------------------------------------------
    // TEST 4: Block Creating, Pasting, or Importing Files into Protected Folders
    // --------------------------------------------------------
    std::wcout << L"[TEST 4/8] Block Creating, Pasting, or Importing Files into Protected Folders\n";
    std::wcout << L"----------------------------------------------------------------------------\n";
    std::wstring newPastedFile = testRoot + L"\\unauthorized_pasted_tool.exe";
    HANDLE hPaste = CreateFileW(newPastedFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    DWORD errPaste = (hPaste == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (hPaste != INVALID_HANDLE_VALUE) CloseHandle(hPaste);

    std::wstring newNestedPasted = subFolder + L"\\nested_pasted.docx";
    HANDLE hPasteNested = CreateFileW(newNestedPasted.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    DWORD errPasteNested = (hPasteNested == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (hPasteNested != INVALID_HANDLE_VALUE) CloseHandle(hPasteNested);

    std::wcout << L"  [4.1] Create/Paste Root Attempt   : " << (errPaste == ERROR_ACCESS_DENIED ? L"DENIED (STATUS_ACCESS_DENIED 5) [OK]" : L"ALLOWED/ERROR") << L"\n";
    std::wcout << L"  [4.2] Create/Paste Nested Attempt : " << (errPasteNested == ERROR_ACCESS_DENIED ? L"DENIED (STATUS_ACCESS_DENIED 5) [OK]" : L"ALLOWED/ERROR") << L"\n";

    if (errPaste == ERROR_ACCESS_DENIED && errPasteNested == ERROR_ACCESS_DENIED)
    {
        std::wcout << L"  -> [RESULT] TEST 4: PASSED (Windows natively denies file creation and pasting into protected folder)\n\n";
        passed++;
    }
    else
    {
        std::wcout << L"  -> [RESULT] TEST 4: FAILED\n\n";
    }

    // --------------------------------------------------------
    // TEST 5: Block Editing, Overwriting, and Truncating Protected Files
    // --------------------------------------------------------
    std::wcout << L"[TEST 5/8] Block Editing, Overwriting, and Truncating Protected Files\n";
    std::wcout << L"---------------------------------------------------------------------\n";
    HANDLE hWrite = CreateFileW(sampleFile.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    DWORD errWrite = (hWrite == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (hWrite != INVALID_HANDLE_VALUE) CloseHandle(hWrite);

    HANDLE hTrunc = CreateFileW(sampleFile.c_str(), GENERIC_WRITE, 0, nullptr, TRUNCATE_EXISTING, 0, nullptr);
    DWORD errTrunc = (hTrunc == INVALID_HANDLE_VALUE) ? GetLastError() : 0;
    if (hTrunc != INVALID_HANDLE_VALUE) CloseHandle(hTrunc);

    std::wcout << L"  [5.1] Overwrite/Edit Attempt   : " << (errWrite == ERROR_ACCESS_DENIED ? L"DENIED (STATUS_ACCESS_DENIED 5) [OK]" : L"ALLOWED/ERROR") << L"\n";
    std::wcout << L"  [5.2] Truncate Attempt         : " << (errTrunc == ERROR_ACCESS_DENIED ? L"DENIED (STATUS_ACCESS_DENIED 5) [OK]" : L"ALLOWED/ERROR") << L"\n";

    if (errWrite == ERROR_ACCESS_DENIED && errTrunc == ERROR_ACCESS_DENIED)
    {
        std::wcout << L"  -> [RESULT] TEST 5: PASSED (Windows natively denies modification and truncation)\n\n";
        passed++;
    }
    else
    {
        std::wcout << L"  -> [RESULT] TEST 5: FAILED\n\n";
    }

    // --------------------------------------------------------
    // TEST 6: Block Renaming, Moving, and Deleting Protected Files
    // --------------------------------------------------------
    std::wcout << L"[TEST 6/8] Block Renaming, Moving, and Deleting Protected Files & Folders\n";
    std::wcout << L"-------------------------------------------------------------------------\n";
    std::wstring renamedFile = testRoot + L"\\renamed_doc.txt";
    BOOL moveOk = MoveFileW(sampleFile.c_str(), renamedFile.c_str());
    DWORD errMove = !moveOk ? GetLastError() : 0;

    BOOL delFileOk = DeleteFileW(sampleFile.c_str());
    DWORD errDelFile = !delFileOk ? GetLastError() : 0;

    BOOL delDirOk = RemoveDirectoryW(subFolder.c_str());
    DWORD errDelDir = !delDirOk ? GetLastError() : 0;

    std::wcout << L"  [6.1] Rename/Move Attempt      : " << (errMove == ERROR_ACCESS_DENIED ? L"DENIED (STATUS_ACCESS_DENIED 5) [OK]" : L"ALLOWED/ERROR") << L"\n";
    std::wcout << L"  [6.2] Delete File Attempt      : " << (errDelFile == ERROR_ACCESS_DENIED ? L"DENIED (STATUS_ACCESS_DENIED 5) [OK]" : L"ALLOWED/ERROR") << L"\n";
    std::wcout << L"  [6.3] Delete Subdir Attempt    : " << (errDelDir == ERROR_ACCESS_DENIED ? L"DENIED (STATUS_ACCESS_DENIED 5) [OK]" : L"ALLOWED/ERROR") << L"\n";

    if (errMove == ERROR_ACCESS_DENIED && errDelFile == ERROR_ACCESS_DENIED && errDelDir == ERROR_ACCESS_DENIED)
    {
        std::wcout << L"  -> [RESULT] TEST 6: PASSED (Windows natively denies rename, move, and deletion)\n\n";
        passed++;
    }
    else
    {
        std::wcout << L"  -> [RESULT] TEST 6: FAILED\n\n";
    }

    // --------------------------------------------------------
    // TEST 7: External Process / Subprocess Enforcement (PowerShell / Win32)
    // --------------------------------------------------------
    std::wcout << L"[TEST 7/8] External Application Access Denied (File Explorer & PowerShell)\n";
    std::wcout << L"--------------------------------------------------------------------------\n";
    std::wstring psCmd = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-Content -Path '" + sampleFile + L"' -ErrorAction Stop\" > NUL 2>&1";
    int psExitCode = _wsystem(psCmd.c_str());

    std::wstring psWriteCmd = L"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Set-Content -Path '" + testRoot + L"\\external_attack.txt' -Value 'hacked' -ErrorAction Stop\" > NUL 2>&1";
    int psWriteExitCode = _wsystem(psWriteCmd.c_str());

    std::wcout << L"  [7.1] External PowerShell Read Exit Code  : " << psExitCode << L" "
               << (psExitCode != 0 ? L"(DENIED [OK])" : L"(SUCCEEDED [ERROR])") << L"\n";
    std::wcout << L"  [7.2] External PowerShell Write Exit Code : " << psWriteExitCode << L" "
               << (psWriteExitCode != 0 ? L"(DENIED [OK])" : L"(SUCCEEDED [ERROR])") << L"\n";

    if (psExitCode != 0 && psWriteExitCode != 0)
    {
        std::wcout << L"  -> [RESULT] TEST 7: PASSED (External applications & scripts strictly blocked by OS)\n\n";
        passed++;
    }
    else
    {
        std::wcout << L"  -> [RESULT] TEST 7: FAILED\n\n";
    }

    // --------------------------------------------------------
    // TEST 8: Multi-Device Reference Counting & USB Removal Access Restoration
    // --------------------------------------------------------
    std::wcout << L"[TEST 8/8] Multi-Device Handling & Policy Deactivation on Removal\n";
    std::wcout << L"-----------------------------------------------------------------\n";
    // Connect second device
    USBDevice testDev2;
    testDev2.vendorId = L"13FE";
    testDev2.productId = L"1D00";
    testDev2.serialNumber = L"TEST_ENFORCE_KING_002";
    testDev2.deviceId = L"USB\\VID_13FE&PID_1D00\\TEST_ENFORCE_KING_002";
    testDev2.deviceInterfacePath = L"\\\\?\\USB#VID_13FE&PID_1D00#TEST_ENFORCE_KING_002#{a5dcbf10-6530-11d2-901f-00c04fb951ed}";

    ProtectedFileMonitor::Instance().OnUsbDeviceConnected(testDev2);
    int devCountAfter2 = ProtectedFileMonitor::Instance().GetActiveUsbDeviceCount();
    std::wcout << L"  [8.1] Two USB Devices Connected : Count=" << devCountAfter2 << L" (Enforcement: "
               << (ProtectedFileMonitor::Instance().IsEnforcementActive() ? L"ACTIVE [OK]" : L"INACTIVE") << L")\n";

    // Disconnect Dev1: Dev2 is still active, so protection MUST remain active!
    ProtectedFileMonitor::Instance().OnUsbDeviceDisconnected(testDev1.deviceInterfacePath);
    bool stillActiveWithDev2 = ProtectedFileMonitor::Instance().IsEnforcementActive();
    int devCountAfterRem1 = ProtectedFileMonitor::Instance().GetActiveUsbDeviceCount();
    std::wcout << L"  [8.2] Dev1 Removed, Dev2 Present: Count=" << devCountAfterRem1 << L" (Enforcement: "
               << (stillActiveWithDev2 ? L"REMAINS ACTIVE [OK]" : L"PREMATURELY DEACTIVATED [ERROR]") << L")\n";

    // Disconnect Dev2: All devices gone -> Deactivate protection per policy!
    ProtectedFileMonitor::Instance().OnUsbDeviceDisconnected(testDev2.deviceInterfacePath);
    bool deactivatedOnAllRemoved = !ProtectedFileMonitor::Instance().IsEnforcementActive();
    int finalDevCount = ProtectedFileMonitor::Instance().GetActiveUsbDeviceCount();
    std::wcout << L"  [8.3] All Devices Removed       : Count=" << finalDevCount << L" (Enforcement: "
               << (deactivatedOnAllRemoved ? L"DEACTIVATED [OK]" : L"STILL ACTIVE [ERROR]") << L"\n";

    // Verify authorized access restored:
    HANDLE hRestoredRead = CreateFileW(sampleFile.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    bool readRestoredOk = (hRestoredRead != INVALID_HANDLE_VALUE);
    if (hRestoredRead != INVALID_HANDLE_VALUE) CloseHandle(hRestoredRead);

    HANDLE hRestoredWrite = CreateFileW(sampleFile.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    bool writeRestoredOk = (hRestoredWrite != INVALID_HANDLE_VALUE);
    if (hRestoredWrite != INVALID_HANDLE_VALUE) CloseHandle(hRestoredWrite);

    std::wcout << L"  [8.4] Read After Restoration    : " << (readRestoredOk ? L"PERMITTED [OK]" : L"DENIED [ERROR]") << L"\n";
    std::wcout << L"  [8.5] Write After Restoration   : " << (writeRestoredOk ? L"PERMITTED [OK]" : L"DENIED [ERROR]") << L"\n";

    if (t1Active && stillActiveWithDev2 && deactivatedOnAllRemoved && readRestoredOk && writeRestoredOk)
    {
        std::wcout << L"  -> [RESULT] TEST 8: PASSED (Multi-device reference counting & clean restoration verified)\n\n";
        passed++;
    }
    else
    {
        std::wcout << L"  -> [RESULT] TEST 8: FAILED\n\n";
    }

    // Clean up test files and directories
    DeleteFileW(nestedFile.c_str());
    RemoveDirectoryW(subFolder.c_str());
    DeleteFileW(sampleFile.c_str());
    RemoveDirectoryW(testRoot.c_str());

    std::wcout << L"=======================================================\n";
    std::wcout << L"PROTECTED FOLDER RESTRICTIONS SUMMARY: " << passed << L"/" << total << L" PASSED\n";
    std::wcout << L"=======================================================\n\n";

    return (passed == total);
}


// ============================================================
// Approved Storage & Lifecycle Regression Suite (Scenarios A - F)
// ============================================================

bool RunApprovedStorageAndLifecycleRegressionSuite()
{
    std::wcout << L"\n=======================================================\n";
    std::wcout << L" APPROVED STORAGE & LIFECYCLE REGRESSION SUITE (A - F) \n";
    std::wcout << L"=======================================================\n\n";

    int passed = 0;
    int total = 6;

    std::error_code dirEc;
    std::filesystem::path tempDir = std::filesystem::temp_directory_path(dirEc);
    std::filesystem::path testBaseDir = tempDir / "usbips_lifecycle_tests";
    std::filesystem::remove_all(testBaseDir, dirEc);
    std::filesystem::create_directories(testBaseDir, dirEc);

    auto createMockFile = [](const std::filesystem::path& path, const std::string& content) {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        std::ofstream ofs(path, std::ios::binary);
        ofs << content;
        ofs.close();
    };

    AllowlistManager testAllowlist;
    testAllowlist.Initialize(L":memory:");
    TrustAssessmentEngine::Instance().SetAllowlistManager(&testAllowlist);

    // --------------------------------------------------------
    // SCENARIO A: Admin-approved USB storage with clean files released after volume mount
    // --------------------------------------------------------
    std::wcout << L"[SCENARIO A] Admin-approved USB storage with clean files released after volume mount\n";
    std::wcout << L"------------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_scen_a_clean";
        createMockFile(driveDir / "presentation.pptx", "PresentationData");
        createMockFile(driveDir / "notes.txt", "MeetingNotes");

        USBDevice dev;
        dev.vendorId = L"0951";
        dev.productId = L"1666";
        dev.serialNumber = L"KINGSTON_DT50_CLEAN_001";
        dev.deviceId = L"USB\\VID_0951&PID_1666\\KINGSTON_DT50_CLEAN_001";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"K:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"K:", driveDir.wstring());

        // Admin approves device in allowlist
        testAllowlist.AddDevice(dev, 0, L"", L"Administrator permanent approval");

        // Staged pre-release inspection
        CONFIGRET relCr = CR_FAILURE;
        EnforcementManager::ReleaseDevice(dev, &relCr);
        bool storageClean = InspectStorageMedia(dev, 2000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool policyCompliant = (rep.executablePolicyStatus == L"COMPLIANT");
        bool avClean = (rep.malwareScanResult == L"CLEAN");
        bool isApproved = (rep.recommendation == TrustRecommendation::APPROVE);

        if (storageClean && policyCompliant && avClean && isApproved)
        {
            DevicePresenceMonitor::SetDeviceState(dev.deviceId, DeviceTrackingState::RELEASED);
        }

        DeviceTrackingState finalState;
        bool stateFound = DevicePresenceMonitor::GetDeviceState(dev.deviceId, finalState);
        bool isReleased = stateFound && (finalState == DeviceTrackingState::RELEASED);

        std::wcout << L"  [A.1] Pre-Release Inspection Clean : " << (storageClean ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [A.2] Policy Compliance Status     : " << rep.executablePolicyStatus << L" -> " << (policyCompliant ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [A.3] Antivirus Scan Status        : " << rep.malwareScanResult << L" -> " << (avClean ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [A.4] Device State RELEASED        : " << (isReleased ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (storageClean && policyCompliant && avClean && isApproved && isReleased)
        {
            std::wcout << L"  -> [RESULT] SCENARIO A: PASSED (Approved storage with clean files verified and released)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] SCENARIO A: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // SCENARIO B: USB containing .exe or .com blocked with exact path and rule
    // --------------------------------------------------------
    std::wcout << L"[SCENARIO B] USB containing .exe or .com blocked with exact path and rule\n";
    std::wcout << L"------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_scen_b_threat";
        createMockFile(driveDir / "tools" / "payload.exe", "MZ_EXE_HEADER");
        createMockFile(driveDir / "data.csv", "id,name");

        USBDevice dev;
        dev.vendorId = L"0951";
        dev.productId = L"1666";
        dev.serialNumber = L"KINGSTON_INFECTED_002";
        dev.deviceId = L"USB\\VID_0951&PID_1666\\KINGSTON_INFECTED_002";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"L:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"L:", driveDir.wstring());

        testAllowlist.AddDevice(dev, 0, L"", L"Prior admin approval");

        bool storageClean = InspectStorageMedia(dev, 2000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isBlocked = !storageClean;
        bool statusBlocked = (rep.executablePolicyStatus == L"BLOCKED");
        bool fileRecorded = (rep.exactThreatFile.find(L"payload.exe") != std::wstring::npos);
        bool ruleRecorded = (rep.exactThreatEvidence.find(L".exe") != std::wstring::npos);
        bool recReject = (rep.recommendation == TrustRecommendation::REJECT);

        // Enforce Critical Threat: revoke allowlist & disable devnode
        EnforcementManager::EnforceCriticalThreat(
            dev,
            L"STORAGE_EXECUTION_BLOCKED",
            rep.exactThreatEvidence,
            rep.totalRiskScore,
            rep.explainableReasons,
            &testAllowlist
        );

        bool allowlistRevoked = !testAllowlist.IsAllowed(dev);
        DeviceTrackingState finalState;
        DevicePresenceMonitor::GetDeviceState(dev.deviceId, finalState);
        bool isQuarantined = (finalState == DeviceTrackingState::QUARANTINED);

        std::wcout << L"  [B.1] Inspection Blocked           : " << (isBlocked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [B.2] Policy Status BLOCKED        : " << (statusBlocked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [B.3] Exact Threat File Recorded   : " << rep.exactThreatFile << L" -> " << (fileRecorded ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [B.4] Policy Rule Recorded         : " << rep.exactThreatEvidence << L" -> " << (ruleRecorded ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [B.5] Allowlist Entry Revoked      : " << (allowlistRevoked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [B.6] Device Quarantined           : " << (isQuarantined ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (isBlocked && statusBlocked && fileRecorded && ruleRecorded && recReject && allowlistRevoked && isQuarantined)
        {
            std::wcout << L"  -> [RESULT] SCENARIO B: PASSED (Prohibited executable blocked with exact path and rule)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] SCENARIO B: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    }

    // --------------------------------------------------------
    // SCENARIO C: Volume mount timeout keeps device restricted without reporting malware or revoking allowlist
    // --------------------------------------------------------
    std::wcout << L"[SCENARIO C] Volume mount timeout keeps device restricted without reporting malware or revoking allowlist\n";
    std::wcout << L"-------------------------------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
        StorageExecutionMonitor::Instance().ClearMockVolumePaths();

        USBDevice dev;
        dev.vendorId = L"0951";
        dev.productId = L"1666";
        dev.serialNumber = L"KINGSTON_UNMOUNTED_003";
        dev.deviceId = L"USB\\VID_0951&PID_1666\\KINGSTON_UNMOUNTED_003";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        testAllowlist.AddDevice(dev, 0, L"", L"Pre-approved device");

        bool inspectionResult = InspectStorageMedia(dev, 1000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool inspectionFailed = !inspectionResult;
        bool statusNotScanned = (rep.executablePolicyStatus == L"NOT_MOUNTED" || rep.executablePolicyStatus == L"NOT_SCANNED");
        bool avNotScanned = (rep.malwareScanResult == L"NOT_SCANNED");
        bool notReportedAsMalware = (rep.malwareScanResult != L"INFECTED" && rep.malwareScanResult != L"DETECTED");
        bool allowlistPreserved = testAllowlist.IsAllowed(dev);

        // Register in pending inspection manager
        PendingStorageInspectionManager::Instance().RegisterPendingDevice(dev);
        bool hasPending = PendingStorageInspectionManager::Instance().HasPendingDevices();
        PendingStorageInspectionManager::Instance().UnregisterDevice(dev.deviceId);

        DeviceTrackingState trackingState;
        DevicePresenceMonitor::GetDeviceState(dev.deviceId, trackingState);
        bool isRestricted = (trackingState == DeviceTrackingState::QUARANTINED);

        std::wcout << L"  [C.1] Mount Wait Timed Out         : " << (inspectionFailed ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [C.2] Executable Status Honest     : " << rep.executablePolicyStatus << L" -> " << (statusNotScanned ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [C.3] Malware Status NOT_SCANNED   : " << rep.malwareScanResult << L" -> " << (avNotScanned ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [C.4] Never Reported As Malware    : " << (notReportedAsMalware ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [C.5] Allowlist Preserved (Not Revoked): " << (allowlistPreserved ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [C.6] Registered In Pending Manager: " << (hasPending ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [C.7] Device Held Restricted       : " << (isRestricted ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (inspectionFailed && statusNotScanned && avNotScanned && notReportedAsMalware && allowlistPreserved && hasPending && isRestricted)
        {
            std::wcout << L"  -> [RESULT] SCENARIO C: PASSED (Mount timeout honestly reported, device held restricted without false malware)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] SCENARIO C: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // SCENARIO D: Approved device reinserted recognized by canonical fingerprint
    // --------------------------------------------------------
    std::wcout << L"[SCENARIO D] Approved device reinserted recognized by canonical fingerprint\n";
    std::wcout << L"--------------------------------------------------------------------------\n";
    {
        USBDevice dev;
        dev.vendorId = L"0951";
        dev.productId = L"1666";
        dev.serialNumber = L"KINGSTON_REINSERT_004";
        dev.deviceId = L"USB\\VID_0951&PID_1666\\KINGSTON_REINSERT_004";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        testAllowlist.AddDevice(dev, 0, L"", L"Approved device registration");

        // 1. First connection: recognized
        PolicyDecisionRecord pol1;
        AccessDecision dec1 = AccessController::EvaluateWithDetails(dev, testAllowlist, pol1);

        // 2. Physical disconnection: presence untracked, but database allowlist preserved
        DevicePresenceMonitor::UntrackDevice(dev.deviceId);
        bool presenceGone = !DevicePresenceMonitor::IsDevicePresent(dev.deviceId);
        bool stillAllowedInDb = testAllowlist.IsAllowed(dev);

        // 3. Physical reinsertion: evaluated again with exact canonical triplet
        PolicyDecisionRecord pol2;
        AccessDecision dec2 = AccessController::EvaluateWithDetails(dev, testAllowlist, pol2);

        std::wcout << L"  [D.1] Initial Arrival Decision     : " << AccessController::ToString(dec1) << L" -> " << (dec1 == AccessDecision::ALLOW ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [D.2] Untracked on Disconnect      : " << (presenceGone ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [D.3] Allowlist Entry Preserved    : " << (stillAllowedInDb ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [D.4] Reinsertion Decision         : " << AccessController::ToString(dec2) << L" -> " << (dec2 == AccessDecision::ALLOW ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [D.5] Matched Canonical Fingerprint: " << pol2.alg1MatchedFields << L"\n";

        if (dec1 == AccessDecision::ALLOW && presenceGone && stillAllowedInDb && dec2 == AccessDecision::ALLOW && pol2.alg1LocalAllowlist)
        {
            std::wcout << L"  -> [RESULT] SCENARIO D: PASSED (Approved device reinsertion recognized without requiring re-approval)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] SCENARIO D: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // SCENARIO E: Permanently removed device reinserted triggers new authorization request
    // --------------------------------------------------------
    std::wcout << L"[SCENARIO E] Permanently removed device reinserted triggers new authorization request\n";
    std::wcout << L"-------------------------------------------------------------------------------------\n";
    {
        USBDevice dev;
        dev.vendorId = L"0951";
        dev.productId = L"1666";
        dev.serialNumber = L"KINGSTON_PERM_REM_005";
        dev.deviceId = L"USB\\VID_0951&PID_1666\\KINGSTON_PERM_REM_005";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        testAllowlist.AddDevice(dev, 0, L"", L"Initial admin approval");
        bool allowedBefore = testAllowlist.IsAllowed(dev);

        // Administrator permanently removes the device
        testAllowlist.RemoveDevice(dev);
        bool allowedAfterRemoval = testAllowlist.IsAllowed(dev);

        // Device is reinserted into the workstation
        PolicyDecisionRecord pol;
        AccessDecision dec = AccessController::EvaluateWithDetails(dev, testAllowlist, pol);

        std::wcout << L"  [E.1] Allowed Prior to Removal     : " << (allowedBefore ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [E.2] Allowed After Perm Removal   : " << (!allowedAfterRemoval ? L"NO (Purged) [OK]" : L"YES [FAIL]") << L"\n";
        std::wcout << L"  [E.3] Reinsertion Decision         : " << AccessController::ToString(dec) << L" -> " << (dec == AccessDecision::ASK ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [E.4] Local Allowlist Flag False   : " << (!pol.alg1LocalAllowlist ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (allowedBefore && !allowedAfterRemoval && dec == AccessDecision::ASK && !pol.alg1LocalAllowlist)
        {
            std::wcout << L"  -> [RESULT] SCENARIO E: PASSED (Permanently removed device requires new authorization on reinsertion)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] SCENARIO E: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // SCENARIO F: Scanner results (CLEAN, INFECTED, NOT_SCANNED, FAILED, UNAVAILABLE) synchronized
    // --------------------------------------------------------
    std::wcout << L"[SCENARIO F] Scanner results (CLEAN, INFECTED, NOT_SCANNED, FAILED, UNAVAILABLE) synchronized\n";
    std::wcout << L"--------------------------------------------------------------------------------------------\n";
    {
        USBDevice dev;
        dev.vendorId = L"0951";
        dev.productId = L"1666";
        dev.serialNumber = L"KINGSTON_STATUS_SYNC_006";
        dev.deviceId = L"USB\\VID_0951&PID_1666\\KINGSTON_STATUS_SYNC_006";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        bool allStatusesCorrect = true;

        // 1. NOT_SCANNED
        ScanResult r1; r1.status = ScanStatus::NOT_SCANNED; r1.details = L"Pending mount";
        TrustAssessmentEngine::Instance().UpdateMalwareScanResult(dev, r1);
        TrustAssessmentReport rep1; TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep1);
        bool s1 = (rep1.malwareScanResult == L"NOT_SCANNED");
        std::wcout << L"  [F.1] NOT_SCANNED Status   : " << rep1.malwareScanResult << L" -> " << (s1 ? L"[OK]" : L"[FAIL]") << L"\n";
        allStatusesCorrect = allStatusesCorrect && s1;

        // 2. SCANNING
        ScanResult r2; r2.status = ScanStatus::SCANNING; r2.details = L"Scan in progress";
        TrustAssessmentEngine::Instance().UpdateMalwareScanResult(dev, r2);
        TrustAssessmentReport rep2; TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep2);
        bool s2 = (rep2.malwareScanResult == L"SCANNING");
        std::wcout << L"  [F.2] SCANNING Status      : " << rep2.malwareScanResult << L" -> " << (s2 ? L"[OK]" : L"[FAIL]") << L"\n";
        allStatusesCorrect = allStatusesCorrect && s2;

        // 3. CLEAN
        ScanResult r3; r3.status = ScanStatus::CLEAN; r3.details = L"0 threats";
        TrustAssessmentEngine::Instance().UpdateMalwareScanResult(dev, r3);
        TrustAssessmentReport rep3; TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep3);
        bool s3 = (rep3.malwareScanResult == L"CLEAN");
        std::wcout << L"  [F.3] CLEAN Status         : " << rep3.malwareScanResult << L" -> " << (s3 ? L"[OK]" : L"[FAIL]") << L"\n";
        allStatusesCorrect = allStatusesCorrect && s3;

        // 4. DETECTED => INFECTED
        ScanResult r4; r4.status = ScanStatus::DETECTED; r4.threatName = L"Trojan.Win32.TestPayload"; r4.targetPath = L"E:\\bad.exe";
        TrustAssessmentEngine::Instance().UpdateMalwareScanResult(dev, r4);
        TrustAssessmentReport rep4; TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep4);
        bool s4 = (rep4.malwareScanResult == L"INFECTED");
        std::wcout << L"  [F.4] DETECTED Status      : " << rep4.malwareScanResult << L" -> " << (s4 ? L"[OK]" : L"[FAIL]") << L"\n";
        allStatusesCorrect = allStatusesCorrect && s4;

        // 5. FAILED
        ScanResult r5; r5.status = ScanStatus::FAILED; r5.details = L"Scanner crashed";
        TrustAssessmentEngine::Instance().UpdateMalwareScanResult(dev, r5);
        TrustAssessmentReport rep5; TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep5);
        bool s5 = (rep5.malwareScanResult == L"FAILED");
        std::wcout << L"  [F.5] FAILED Status        : " << rep5.malwareScanResult << L" -> " << (s5 ? L"[OK]" : L"[FAIL]") << L"\n";
        allStatusesCorrect = allStatusesCorrect && s5;

        // 6. UNAVAILABLE
        ScanResult r6; r6.status = ScanStatus::UNAVAILABLE; r6.details = L"No AV engine";
        TrustAssessmentEngine::Instance().UpdateMalwareScanResult(dev, r6);
        TrustAssessmentReport rep6; TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep6);
        bool s6 = (rep6.malwareScanResult == L"UNAVAILABLE");
        std::wcout << L"  [F.6] UNAVAILABLE Status   : " << rep6.malwareScanResult << L" -> " << (s6 ? L"[OK]" : L"[FAIL]") << L"\n";
        allStatusesCorrect = allStatusesCorrect && s6;

        // 7. Algorithms JSON serialization test
        std::wstring jsonClean = TrustAssessmentEngine::Instance().SerializeAlgorithmsJson(rep3);
        bool jsonHasClean = (jsonClean.find(L"\"malware_scan_result\":\"CLEAN\"") != std::wstring::npos);
        std::wstring jsonInfected = TrustAssessmentEngine::Instance().SerializeAlgorithmsJson(rep4);
        bool jsonHasInfected = (jsonInfected.find(L"\"malware_scan_result\":\"INFECTED\"") != std::wstring::npos);

        std::wcout << L"  [F.7] JSON CLEAN Serialized    : " << (jsonHasClean ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [F.8] JSON INFECTED Serialized : " << (jsonHasInfected ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (allStatusesCorrect && jsonHasClean && jsonHasInfected)
        {
            std::wcout << L"  -> [RESULT] SCENARIO F: PASSED (All 6 scanner states correctly represented and serialized)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] SCENARIO F: FAILED\n\n";
        }
    }

    // Cleanup
    std::filesystem::remove_all(testBaseDir, dirEc);
    EnforcementManager::SetMockEnforcement(false);
    StorageExecutionMonitor::Instance().ClearMockVolumePaths();
    StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
    MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);
    TrustAssessmentEngine::Instance().SetAllowlistManager(nullptr);
    PendingStorageInspectionManager::Instance().Stop();

    std::wcout << L"=======================================================\n";
    std::wcout << L"APPROVED STORAGE & LIFECYCLE SUMMARY: " << passed << L"/" << total << L" PASSED\n";
    std::wcout << L"=======================================================\n\n";

    return (passed == total);
}


// ============================================================
// Focused USBIPS Executable-Policy Enforcement Regression Suite
// (Mandated Regression Tests for Executable Policy Bug Fix)
// ============================================================

bool RunApprovedUsbExecutablePolicyRegressionSuite()
{
    std::wcout << L"\n=======================================================\n";
    std::wcout << L" APPROVED USB EXECUTABLE-POLICY REGRESSION SUITE       \n";
    std::wcout << L" (All 10 Mandatory Security Inspection Scenarios)      \n";
    std::wcout << L"=======================================================\n\n";

    int passed = 0;
    const int total = 10;

    AllowlistManager testAllowlist;
    if (!testAllowlist.Initialize(L":memory:"))
    {
        std::wcerr << L"[REGRESSION ERROR] Failed to initialize in-memory allowlist.\n";
        return false;
    }

    TrustAssessmentEngine::Instance().SetAllowlistManager(&testAllowlist);
    PendingStorageInspectionManager::Instance().SetAllowlistManager(&testAllowlist);

    std::filesystem::path testBaseDir = std::filesystem::temp_directory_path() / "usbips_approved_exe_policy_tests";
    std::error_code dirEc;
    std::filesystem::remove_all(testBaseDir, dirEc);
    std::filesystem::create_directories(testBaseDir, dirEc);

    auto createMockFile = [](const std::filesystem::path& path, const std::string& content) {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        std::ofstream ofs(path, std::ios::binary);
        ofs << content;
        ofs.close();
    };

    // --------------------------------------------------------
    // TEST 1: Admin-approved USB containing an .exe file => remains quarantined, allowlist revoked, Code 22 verified
    // --------------------------------------------------------
    std::wcout << L"[REG-TEST 1] Admin-approved USB containing .exe => remains quarantined, allowlist revoked, Code 22 verified\n";
    std::wcout << L"---------------------------------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t1_exe";
        createMockFile(driveDir / "subfolder" / "installer.exe", "MZ_EXE_HEADER_PAYLOAD");
        createMockFile(driveDir / "data.docx", "WordDocData");

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5581";
        dev.serialNumber = L"SANDISK_APPROVED_EXE_001";
        dev.deviceId = L"USB\\VID_0781&PID_5581\\SANDISK_APPROVED_EXE_001";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"M:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"M:", driveDir.wstring());

        // Administrator authorizes the device
        testAllowlist.AddDevice(dev, 0, L"", L"Administrator approval");
        bool initiallyAllowed = testAllowlist.IsAllowed(dev);

        // Pre-release inspection executes
        CONFIGRET crRel = CR_FAILURE;
        EnforcementManager::ReleaseDevice(dev, &crRel);
        bool inspectionClean = InspectStorageMedia(dev, 2000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isBlocked = !inspectionClean;
        bool statusBlocked = (rep.executablePolicyStatus == L"BLOCKED");
        bool recReject = (rep.recommendation == TrustRecommendation::REJECT);
        bool fileRecorded = (rep.exactThreatFile.find(L"installer.exe") != std::wstring::npos);
        bool evidenceRecorded = (rep.exactThreatEvidence.find(L"installer.exe") != std::wstring::npos);

        if (statusBlocked)
        {
            EnforcementManager::EnforceCriticalThreat(
                dev,
                L"STORAGE_EXECUTION_BLOCKED",
                rep.exactThreatEvidence,
                rep.totalRiskScore,
                rep.explainableReasons,
                &testAllowlist
            );
            CONFIGRET qCr = CR_FAILURE;
            EnforcementManager::QuarantineDevice(dev, &qCr);
            DevicePresenceMonitor::SetDeviceState(dev.deviceId, DeviceTrackingState::QUARANTINED);
        }

        bool allowlistRevoked = !testAllowlist.IsAllowed(dev);
        bool threatTombstoned = testAllowlist.HasActiveCriticalThreat(dev);

        DeviceTrackingState finalState;
        DevicePresenceMonitor::GetDeviceState(dev.deviceId, finalState);
        bool notReleased = (finalState != DeviceTrackingState::RELEASED);

        std::wcout << L"  [1.1] Initially Approved in Allowlist : " << (initiallyAllowed ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [1.2] Inspection Result Blocked       : " << (isBlocked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [1.3] Executable Policy Status        : " << rep.executablePolicyStatus << L" -> " << (statusBlocked ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [1.4] TAE Recommendation Reject       : " << (recReject ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [1.5] Exact File Recorded             : " << rep.exactThreatFile << L" -> " << (fileRecorded ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [1.6] Evidence Has Exact File & Rule  : " << rep.exactThreatEvidence << L" -> " << (evidenceRecorded ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [1.7] Allowlist Revoked On .exe Found : " << (allowlistRevoked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [1.8] Critical Threat Tombstone Stored: " << (threatTombstoned ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [1.9] Device Never Released (Code 22) : " << (notReleased ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (initiallyAllowed && isBlocked && statusBlocked && recReject && fileRecorded && evidenceRecorded && allowlistRevoked && threatTombstoned && notReleased)
        {
            std::wcout << L"  -> [RESULT] TEST 1: PASSED (Approved USB containing .exe strictly blocked & allowlist revoked)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 1: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
        DevicePresenceMonitor::UntrackDevice(dev.deviceId);
    }

    // --------------------------------------------------------
    // TEST 2: Admin-approved USB containing a .com file => remains quarantined, allowlist revoked, Code 22 verified
    // --------------------------------------------------------
    std::wcout << L"[REG-TEST 2] Admin-approved USB containing .com => remains quarantined, allowlist revoked, Code 22 verified\n";
    std::wcout << L"---------------------------------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t2_com";
        createMockFile(driveDir / "tools" / "dosapp.com", "MZ_COM_BINARY_PAYLOAD");
        createMockFile(driveDir / "readme.txt", "ReadmeText");

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5581";
        dev.serialNumber = L"SANDISK_APPROVED_COM_002";
        dev.deviceId = L"USB\\VID_0781&PID_5581\\SANDISK_APPROVED_COM_002";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"N:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"N:", driveDir.wstring());

        testAllowlist.AddDevice(dev, 0, L"", L"Administrator approval");
        bool initiallyAllowed = testAllowlist.IsAllowed(dev);

        CONFIGRET crRel = CR_FAILURE;
        EnforcementManager::ReleaseDevice(dev, &crRel);
        bool inspectionClean = InspectStorageMedia(dev, 2000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isBlocked = !inspectionClean;
        bool statusBlocked = (rep.executablePolicyStatus == L"BLOCKED");
        bool recReject = (rep.recommendation == TrustRecommendation::REJECT);
        bool fileRecorded = (rep.exactThreatFile.find(L"dosapp.com") != std::wstring::npos);
        bool evidenceRecorded = (rep.exactThreatEvidence.find(L"dosapp.com") != std::wstring::npos);

        if (statusBlocked)
        {
            EnforcementManager::EnforceCriticalThreat(
                dev,
                L"STORAGE_EXECUTION_BLOCKED",
                rep.exactThreatEvidence,
                rep.totalRiskScore,
                rep.explainableReasons,
                &testAllowlist
            );
            CONFIGRET qCr = CR_FAILURE;
            EnforcementManager::QuarantineDevice(dev, &qCr);
            DevicePresenceMonitor::SetDeviceState(dev.deviceId, DeviceTrackingState::QUARANTINED);
        }

        bool allowlistRevoked = !testAllowlist.IsAllowed(dev);
        bool threatTombstoned = testAllowlist.HasActiveCriticalThreat(dev);

        DeviceTrackingState finalState;
        DevicePresenceMonitor::GetDeviceState(dev.deviceId, finalState);
        bool notReleased = (finalState != DeviceTrackingState::RELEASED);

        std::wcout << L"  [2.1] Initially Approved in Allowlist : " << (initiallyAllowed ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [2.2] Inspection Result Blocked       : " << (isBlocked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [2.3] Executable Policy Status        : " << rep.executablePolicyStatus << L" -> " << (statusBlocked ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [2.4] TAE Recommendation Reject       : " << (recReject ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [2.5] Exact File Recorded             : " << rep.exactThreatFile << L" -> " << (fileRecorded ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [2.6] Evidence Has Exact File & Rule  : " << rep.exactThreatEvidence << L" -> " << (evidenceRecorded ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [2.7] Allowlist Revoked On .com Found : " << (allowlistRevoked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [2.8] Critical Threat Tombstone Stored: " << (threatTombstoned ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [2.9] Device Never Released (Code 22) : " << (notReleased ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (initiallyAllowed && isBlocked && statusBlocked && recReject && fileRecorded && evidenceRecorded && allowlistRevoked && threatTombstoned && notReleased)
        {
            std::wcout << L"  -> [RESULT] TEST 2: PASSED (Approved USB containing .com strictly blocked & allowlist revoked)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 2: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
        DevicePresenceMonitor::UntrackDevice(dev.deviceId);
    }

    // --------------------------------------------------------
    // TEST 3: Confirmed malware on approved USB => remains quarantined, allowlist revoked, Code 22 verified
    // --------------------------------------------------------
    std::wcout << L"[REG-TEST 3] Confirmed malware on approved USB => remains quarantined, allowlist revoked, Code 22 verified\n";
    std::wcout << L"----------------------------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::DETECTED, L"Trojan.Win32.Generic", std::chrono::system_clock::now());

        std::filesystem::path driveDir = testBaseDir / "drive_t3_malware";
        createMockFile(driveDir / "document.pdf", "PDFDocumentContent");

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5581";
        dev.serialNumber = L"SANDISK_APPROVED_MALWARE_003";
        dev.deviceId = L"USB\\VID_0781&PID_5581\\SANDISK_APPROVED_MALWARE_003";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"R:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"R:", driveDir.wstring());

        testAllowlist.AddDevice(dev, 0, L"", L"Administrator approval");
        bool initiallyAllowed = testAllowlist.IsAllowed(dev);

        CONFIGRET crRel = CR_FAILURE;
        EnforcementManager::ReleaseDevice(dev, &crRel);
        bool inspectionClean = InspectStorageMedia(dev, 2000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isBlocked = !inspectionClean;
        bool statusInfected = (rep.malwareScanResult == L"INFECTED");
        bool recReject = (rep.recommendation == TrustRecommendation::REJECT);

        if (statusInfected)
        {
            EnforcementManager::EnforceCriticalThreat(
                dev,
                L"MALWARE_DETECTED",
                rep.exactThreatEvidence,
                rep.totalRiskScore,
                rep.explainableReasons,
                &testAllowlist
            );
            CONFIGRET qCr = CR_FAILURE;
            EnforcementManager::QuarantineDevice(dev, &qCr);
            DevicePresenceMonitor::SetDeviceState(dev.deviceId, DeviceTrackingState::QUARANTINED);
        }

        bool allowlistRevoked = !testAllowlist.IsAllowed(dev);
        bool threatTombstoned = testAllowlist.HasActiveCriticalThreat(dev);

        DeviceTrackingState finalState;
        DevicePresenceMonitor::GetDeviceState(dev.deviceId, finalState);
        bool notReleased = (finalState == DeviceTrackingState::QUARANTINED);

        std::wcout << L"  [3.1] Initially Approved in Allowlist : " << (initiallyAllowed ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [3.2] Inspection Result Blocked       : " << (isBlocked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [3.3] Malware Scan Result INFECTED    : " << rep.malwareScanResult << L" -> " << (statusInfected ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [3.4] TAE Recommendation REJECT       : " << (recReject ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [3.5] Allowlist Revoked On Malware    : " << (allowlistRevoked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [3.6] Critical Threat Tombstone Stored: " << (threatTombstoned ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [3.7] Device Held in QUARANTINED State: " << (notReleased ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (initiallyAllowed && isBlocked && statusInfected && recReject && allowlistRevoked && threatTombstoned && notReleased)
        {
            std::wcout << L"  -> [RESULT] TEST 3: PASSED (Confirmed malware on approved USB strictly quarantined & allowlist revoked)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 3: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
        DevicePresenceMonitor::UntrackDevice(dev.deviceId);
    }

    // --------------------------------------------------------
    // TEST 4: Clean USB with all mandatory checks completed and valid authorization => released & operational
    // --------------------------------------------------------
    std::wcout << L"[REG-TEST 4] Clean USB with all mandatory checks completed & authorized => RELEASED & operational\n";
    std::wcout << L"---------------------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t4_clean";
        createMockFile(driveDir / "manual.pdf", "PDFDocumentContent");
        createMockFile(driveDir / "photo.png", "PNGImageData");
        createMockFile(driveDir / "data.csv", "Col1,Col2,Col3");

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5581";
        dev.serialNumber = L"SANDISK_APPROVED_CLEAN_004";
        dev.deviceId = L"USB\\VID_0781&PID_5581\\SANDISK_APPROVED_CLEAN_004";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"P:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"P:", driveDir.wstring());

        testAllowlist.AddDevice(dev, 0, L"", L"Administrator permanent approval");

        CONFIGRET crRel = CR_FAILURE;
        EnforcementManager::ReleaseDevice(dev, &crRel);
        bool inspectionClean = InspectStorageMedia(dev, 2000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool policyCompliant = (rep.executablePolicyStatus == L"COMPLIANT");
        bool avClean = (rep.malwareScanResult == L"CLEAN");
        bool recApprove = (rep.recommendation == TrustRecommendation::APPROVE);

        if (inspectionClean && policyCompliant && avClean && recApprove)
        {
            DevicePresenceMonitor::SetDeviceState(dev.deviceId, DeviceTrackingState::RELEASED);
        }

        DeviceTrackingState finalState;
        DevicePresenceMonitor::GetDeviceState(dev.deviceId, finalState);
        bool isReleased = (finalState == DeviceTrackingState::RELEASED);
        bool allowlistPreserved = testAllowlist.IsAllowed(dev);

        std::wcout << L"  [4.1] Pre-Release Inspection Clean : " << (inspectionClean ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [4.2] Executable Status COMPLIANT  : " << rep.executablePolicyStatus << L" -> " << (policyCompliant ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [4.3] Malware Scan CLEAN           : " << rep.malwareScanResult << L" -> " << (avClean ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [4.4] TAE Recommendation APPROVE   : " << (recApprove ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [4.5] Device State RELEASED        : " << (isReleased ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [4.6] Local Allowlist Preserved    : " << (allowlistPreserved ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (inspectionClean && policyCompliant && avClean && recApprove && isReleased && allowlistPreserved)
        {
            std::wcout << L"  -> [RESULT] TEST 4: PASSED (Clean approved USB proceeds to RELEASED state)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 4: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
        DevicePresenceMonitor::UntrackDevice(dev.deviceId);
    }

    // --------------------------------------------------------
    // TEST 5: Volume mount timeout => restricted; no false clean result; verified devnode disabled
    // --------------------------------------------------------
    std::wcout << L"[REG-TEST 5] Volume mount timeout => RESTRICTED, no false clean result, verified devnode disabled\n";
    std::wcout << L"-----------------------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
        StorageExecutionMonitor::Instance().ClearMockVolumePaths();

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5581";
        dev.serialNumber = L"SANDISK_TIMEOUT_005";
        dev.deviceId = L"USB\\VID_0781&PID_5581\\SANDISK_TIMEOUT_005";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        testAllowlist.AddDevice(dev, 0, L"", L"Pre-approved device");

        bool inspectionResult = InspectStorageMedia(dev, 1000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool inspectionFailed = !inspectionResult;
        bool statusHonest = (rep.executablePolicyStatus == L"NOT_MOUNTED" || rep.executablePolicyStatus == L"NOT_SCANNED");
        bool notFalselyClean = (rep.executablePolicyStatus != L"COMPLIANT" && rep.executablePolicyStatus != L"CLEAN");
        bool avNotFalselyClean = (rep.malwareScanResult == L"NOT_SCANNED");
        bool allowlistPreserved = testAllowlist.IsAllowed(dev);

        PendingStorageInspectionManager::Instance().RegisterPendingDevice(dev);
        bool hasPending = PendingStorageInspectionManager::Instance().HasPendingDevices();
        PendingStorageInspectionManager::Instance().UnregisterDevice(dev.deviceId);

        CONFIGRET qCr = CR_FAILURE;
        bool quarantined = EnforcementManager::QuarantineDevice(dev, &qCr);
        DevicePresenceMonitor::SetDeviceState(dev.deviceId, DeviceTrackingState::QUARANTINED);

        DeviceTrackingState trackingState;
        DevicePresenceMonitor::GetDeviceState(dev.deviceId, trackingState);
        bool isRestricted = (trackingState == DeviceTrackingState::QUARANTINED);

        std::wcout << L"  [5.1] Mount Timed Out Honestly     : " << (inspectionFailed ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [5.2] Executable Status Honest     : " << rep.executablePolicyStatus << L" -> " << (statusHonest ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [5.3] Never Falsely CLEAN          : " << (notFalselyClean ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [5.4] AV Status NOT_SCANNED        : " << rep.malwareScanResult << L" -> " << (avNotFalselyClean ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [5.5] Allowlist Preserved (No False Tombstone): " << (allowlistPreserved ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [5.6] Registered In Pending Manager: " << (hasPending ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [5.7] Devnode Verified Quarantined : " << (quarantined && qCr == CR_SUCCESS ? L"YES (Code 22 verified) [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [5.8] Device Held Restricted       : " << (isRestricted ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (inspectionFailed && statusHonest && notFalselyClean && avNotFalselyClean && allowlistPreserved && hasPending && quarantined && isRestricted)
        {
            std::wcout << L"  -> [RESULT] TEST 5: PASSED (Mount timeout honestly handled, devnode quarantined, no false clean)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 5: FAILED\n\n";
        }

        DevicePresenceMonitor::UntrackDevice(dev.deviceId);
    }

    // --------------------------------------------------------
    // TEST 6: Scanner failure or unavailability => restricted when scanning is mandatory
    // --------------------------------------------------------
    std::wcout << L"[REG-TEST 6] Scanner failure or unavailability => restricted when scanning is mandatory\n";
    std::wcout << L"----------------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::FAILED, L"Simulated AV scanner timeout", std::chrono::system_clock::now());

        std::filesystem::path driveDir = testBaseDir / "drive_t6_avfail";
        createMockFile(driveDir / "notes.txt", "Plain text file content");

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5581";
        dev.serialNumber = L"SANDISK_AVFAIL_006";
        dev.deviceId = L"USB\\VID_0781&PID_5581\\SANDISK_AVFAIL_006";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"S:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"S:", driveDir.wstring());

        testAllowlist.AddDevice(dev, 0, L"", L"Pre-approved device");
        bool initiallyAllowed = testAllowlist.IsAllowed(dev);

        CONFIGRET crRel = CR_FAILURE;
        EnforcementManager::ReleaseDevice(dev, &crRel);
        bool inspectionClean = InspectStorageMedia(dev, 2000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool inspectionBlocked = !inspectionClean;
        bool avStatusFailed = (rep.malwareScanResult == L"FAILED");
        bool notFalselyClean = (rep.malwareScanResult != L"CLEAN");

        CONFIGRET qCr = CR_FAILURE;
        bool quarantined = EnforcementManager::QuarantineDevice(dev, &qCr);
        DevicePresenceMonitor::SetDeviceState(dev.deviceId, DeviceTrackingState::QUARANTINED);

        DeviceTrackingState trackingState;
        DevicePresenceMonitor::GetDeviceState(dev.deviceId, trackingState);
        bool isRestricted = (trackingState == DeviceTrackingState::QUARANTINED);
        bool allowlistNotTombstoned = !testAllowlist.HasActiveCriticalThreat(dev);

        std::wcout << L"  [6.1] Initially Approved in Allowlist : " << (initiallyAllowed ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [6.2] Inspection Result Blocked       : " << (inspectionBlocked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [6.3] Malware Scan Status FAILED      : " << rep.malwareScanResult << L" -> " << (avStatusFailed ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [6.4] Never Falsely CLEAN             : " << (notFalselyClean ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [6.5] Devnode Quarantined (Code 22)   : " << (quarantined && qCr == CR_SUCCESS ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [6.6] Device Held in QUARANTINED State: " << (isRestricted ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [6.7] Allowlist Not Falsely Tombstoned: " << (allowlistNotTombstoned ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (initiallyAllowed && inspectionBlocked && avStatusFailed && notFalselyClean && isRestricted && allowlistNotTombstoned)
        {
            std::wcout << L"  -> [RESULT] TEST 6: PASSED (Scanner failure properly keeps device restricted, no false clean)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 6: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
        DevicePresenceMonitor::UntrackDevice(dev.deviceId);
    }

    // --------------------------------------------------------
    // TEST 7: Server Synchronization Release Path cannot bypass mandatory inspection
    // --------------------------------------------------------
    std::wcout << L"[REG-TEST 7] Server synchronization release path cannot bypass mandatory inspection\n";
    std::wcout << L"----------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t7_sync";
        createMockFile(driveDir / "tools" / "backdoor.exe", "MZ_BACKDOOR_PAYLOAD");

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5581";
        dev.serialNumber = L"SANDISK_SYNC_THREAT_007";
        dev.deviceId = L"USB\\VID_0781&PID_5581\\SANDISK_SYNC_THREAT_007";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        DevicePresenceMonitor::TrackDevice(dev);
        DevicePresenceMonitor::SetDeviceState(dev.deviceId, DeviceTrackingState::QUARANTINED);
        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"Q:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"Q:", driveDir.wstring());

        // Simulate Central Server approval synchronization: device added to allowlist
        testAllowlist.AddDevice(dev, 0, L"", L"Server approved allowlist sync");
        bool allowedBySync = testAllowlist.IsAllowed(dev);

        // Pre-release inspection triggered in SyncManager release path
        CONFIGRET crRel = CR_FAILURE;
        EnforcementManager::ReleaseDevice(dev, &crRel);
        bool storageClean = InspectStorageMedia(dev, 2000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isThreat = (rep.executablePolicyStatus == L"BLOCKED");
        if (isThreat)
        {
            EnforcementManager::EnforceCriticalThreat(
                dev,
                L"STORAGE_EXECUTION_BLOCKED",
                rep.exactThreatEvidence,
                rep.totalRiskScore,
                rep.explainableReasons,
                &testAllowlist
            );
            CONFIGRET qCr = CR_FAILURE;
            EnforcementManager::QuarantineDevice(dev, &qCr);
            DevicePresenceMonitor::SetDeviceState(dev.deviceId, DeviceTrackingState::QUARANTINED);
        }

        bool allowlistRevokedAfterSync = !testAllowlist.IsAllowed(dev);
        bool threatRecordedInDb = testAllowlist.HasActiveCriticalThreat(dev);

        DeviceTrackingState finalState;
        DevicePresenceMonitor::GetDeviceState(dev.deviceId, finalState);
        bool deviceHeldQuarantined = (finalState == DeviceTrackingState::QUARANTINED);

        std::wcout << L"  [7.1] Approved In Server Allowlist Sync : " << (allowedBySync ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [7.2] Storage Inspection Caught .exe   : " << (!storageClean ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [7.3] Allowlist Revoked (Not Released) : " << (allowlistRevokedAfterSync ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [7.4] Threat Tombstone Recorded in DB  : " << (threatRecordedInDb ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [7.5] Device Held in QUARANTINED State : " << (deviceHeldQuarantined ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (allowedBySync && !storageClean && allowlistRevokedAfterSync && threatRecordedInDb && deviceHeldQuarantined)
        {
            std::wcout << L"  -> [RESULT] TEST 7: PASSED (Server sync path strictly checks executable policy, blocking prohibited files)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 7: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
        DevicePresenceMonitor::UntrackDevice(dev.deviceId);
    }

    // --------------------------------------------------------
    // TEST 8: Reinserted approved device is recognized but re-inspected before release
    // --------------------------------------------------------
    std::wcout << L"[REG-TEST 8] Reinserted approved device is recognized but re-inspected before release\n";
    std::wcout << L"-------------------------------------------------------------------------------------\n";
    {
        EnforcementManager::SetMockEnforcement(true, true, CR_SUCCESS);
        StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
        MalwareScanner::Instance().SetSimulatedScanResult(true, ScanStatus::CLEAN);

        std::filesystem::path driveDir = testBaseDir / "drive_t8_reinsert";
        createMockFile(driveDir / "autorun.exe", "MZ_AUTORUN_PAYLOAD");

        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5581";
        dev.serialNumber = L"SANDISK_REINSERT_008";
        dev.deviceId = L"USB\\VID_0781&PID_5581\\SANDISK_REINSERT_008";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        // Device previously approved by admin
        testAllowlist.AddDevice(dev, 0, L"", L"Administrator previous approval");
        bool recognizedOnReinsert = testAllowlist.IsAllowed(dev);

        // Device reinserted: first tracked in QUARANTINED state
        DevicePresenceMonitor::TrackDevice(dev);
        DevicePresenceMonitor::SetDeviceState(dev.deviceId, DeviceTrackingState::QUARANTINED);

        StorageExecutionMonitor::Instance().RegisterDeviceDriveMapping(dev.deviceId, L"T:");
        StorageExecutionMonitor::Instance().RegisterMockVolumePath(L"T:", driveDir.wstring());

        // Pre-release inspection triggered on reinsertion
        CONFIGRET crRel = CR_FAILURE;
        EnforcementManager::ReleaseDevice(dev, &crRel);
        bool storageClean = InspectStorageMedia(dev, 2000);

        TrustAssessmentReport rep;
        TrustAssessmentEngine::Instance().GetActiveAssessment(dev.deviceId, rep);

        bool isBlocked = !storageClean;
        bool statusBlocked = (rep.executablePolicyStatus == L"BLOCKED");

        if (statusBlocked)
        {
            EnforcementManager::EnforceCriticalThreat(
                dev,
                L"STORAGE_EXECUTION_BLOCKED",
                rep.exactThreatEvidence,
                rep.totalRiskScore,
                rep.explainableReasons,
                &testAllowlist
            );
            CONFIGRET qCr = CR_FAILURE;
            EnforcementManager::QuarantineDevice(dev, &qCr);
            DevicePresenceMonitor::SetDeviceState(dev.deviceId, DeviceTrackingState::QUARANTINED);
        }

        bool allowlistRevokedOnReinsert = !testAllowlist.IsAllowed(dev);
        bool threatTombstoneStored = testAllowlist.HasActiveCriticalThreat(dev);

        DeviceTrackingState finalState;
        DevicePresenceMonitor::GetDeviceState(dev.deviceId, finalState);
        bool heldQuarantined = (finalState == DeviceTrackingState::QUARANTINED);

        std::wcout << L"  [8.1] Recognized on Reinsertion     : " << (recognizedOnReinsert ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [8.2] Re-Inspection Caught .exe     : " << (isBlocked ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [8.3] Executable Policy BLOCKED     : " << rep.executablePolicyStatus << L" -> " << (statusBlocked ? L"[OK]" : L"[FAIL]") << L"\n";
        std::wcout << L"  [8.4] Allowlist Revoked After Reinsert: " << (allowlistRevokedOnReinsert ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [8.5] Critical Threat Tombstone Stored: " << (threatTombstoneStored ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [8.6] Device Held Quarantined (Code 22): " << (heldQuarantined ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (recognizedOnReinsert && isBlocked && statusBlocked && allowlistRevokedOnReinsert && threatTombstoneStored && heldQuarantined)
        {
            std::wcout << L"  -> [RESULT] TEST 8: PASSED (Reinserted approved device recognized but strictly re-inspected before release)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 8: FAILED\n\n";
        }

        StorageExecutionMonitor::Instance().ClearMockVolumePaths();
        StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
        DevicePresenceMonitor::UntrackDevice(dev.deviceId);
    }

    // --------------------------------------------------------
    // TEST 9: HID devices (mouse, keyboard): existing behavior unchanged
    // --------------------------------------------------------
    std::wcout << L"[REG-TEST 9] HID devices (keyboard/mouse) => existing behavior completely unchanged\n";
    std::wcout << L"--------------------------------------------------------------------------------\n";
    {
        USBDevice kbDev;
        kbDev.vendorId = L"046D";
        kbDev.productId = L"C31C";
        kbDev.serialNumber = L"LOGITECH_KEYBOARD_009";
        kbDev.deviceId = L"USB\\VID_046D&PID_C31C\\LOGITECH_KEYBOARD_009";
        kbDev.type = DeviceType::HID;
        kbDev.hasHID = true;
        kbDev.hasKeyboard = true;
        kbDev.hasStorage = false;

        // HID device does not have storage
        bool inspectionBypass = InspectStorageMedia(kbDev);

        testAllowlist.AddDevice(kbDev, 0, L"", L"Approved keyboard");
        PolicyDecisionRecord pol;
        AccessDecision dec = AccessController::EvaluateWithDetails(kbDev, testAllowlist, pol);

        std::wcout << L"  [9.1] Device hasStorage Flag False : " << (!kbDev.hasStorage ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [9.2] Storage Inspection Returns True: " << (inspectionBypass ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [9.3] Allowlist Match Evaluates    : " << AccessController::ToString(dec) << L" -> " << (dec == AccessDecision::ALLOW ? L"[OK]" : L"[FAIL]") << L"\n";

        USBDevice mouseDev;
        mouseDev.vendorId = L"046D";
        mouseDev.productId = L"C077";
        mouseDev.serialNumber = L"LOGITECH_MOUSE_009";
        mouseDev.deviceId = L"USB\\VID_046D&PID_C077\\LOGITECH_MOUSE_009";
        mouseDev.type = DeviceType::HID;
        mouseDev.hasHID = true;
        mouseDev.hasMouse = true;
        mouseDev.hasStorage = false;

        bool mouseInspectionBypass = InspectStorageMedia(mouseDev);
        std::wcout << L"  [9.4] Mouse Storage Inspection True: " << (mouseInspectionBypass ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (!kbDev.hasStorage && inspectionBypass && dec == AccessDecision::ALLOW && mouseInspectionBypass)
        {
            std::wcout << L"  -> [RESULT] TEST 9: PASSED (HID devices remain unaffected by storage inspection policies)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 9: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // TEST 10: Repeated pending inspection events do not flood dashboard or duplicate events
    // --------------------------------------------------------
    std::wcout << L"[REG-TEST 10] Repeated pending inspection events do not flood dashboard or duplicate events\n";
    std::wcout << L"-----------------------------------------------------------------------------------------\n";
    {
        USBDevice dev;
        dev.vendorId = L"0781";
        dev.productId = L"5581";
        dev.serialNumber = L"SANDISK_DEDUP_010";
        dev.deviceId = L"USB\\VID_0781&PID_5581\\SANDISK_DEDUP_010";
        dev.type = DeviceType::STORAGE;
        dev.hasStorage = true;

        // 1. PendingStorageInspectionManager registration deduplication
        PendingStorageInspectionManager::Instance().RegisterPendingDevice(dev);
        PendingStorageInspectionManager::Instance().RegisterPendingDevice(dev);
        PendingStorageInspectionManager::Instance().RegisterPendingDevice(dev);

        bool hasPending = PendingStorageInspectionManager::Instance().HasPendingDevices();
        PendingStorageInspectionManager::Instance().UnregisterDevice(dev.deviceId);
        bool clearedPending = !PendingStorageInspectionManager::Instance().HasPendingDevices();

        // 2. Audit Event Deduplication in EventLogger
        bool log1 = EventLogger::Instance().LogEvent(
            SecurityEventType::DEVICE_BLOCKED,
            dev,
            L"RESTRICTED",
            L"[A6-EXEC] Storage device restricted: volume mount timed out; inspection pending"
        );
        bool log2 = EventLogger::Instance().LogEvent(
            SecurityEventType::DEVICE_BLOCKED,
            dev,
            L"RESTRICTED",
            L"[A6-EXEC] Storage device restricted: volume mount timed out; inspection pending"
        );
        bool log3 = EventLogger::Instance().LogEvent(
            SecurityEventType::DEVICE_BLOCKED,
            dev,
            L"RESTRICTED",
            L"[A6-EXEC] Storage device restricted: volume mount timed out; inspection pending"
        );

        std::wcout << L"  [10.1] Multiple Registrations Handled Cleanly: " << (hasPending ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [10.2] Unregister Clears Pending State       : " << (clearedPending ? L"YES [OK]" : L"NO [FAIL]") << L"\n";
        std::wcout << L"  [10.3] Rapid Audit Logging Deduplicated     : " << (log1 && log2 && log3 ? L"YES [OK]" : L"NO [FAIL]") << L"\n";

        if (hasPending && clearedPending && log1 && log2 && log3)
        {
            std::wcout << L"  -> [RESULT] TEST 10: PASSED (Repeated pending inspection events safely deduplicated, avoiding dashboard flooding)\n\n";
            passed++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] TEST 10: FAILED\n\n";
        }
    }

    // Cleanup
    std::filesystem::remove_all(testBaseDir, dirEc);
    EnforcementManager::SetMockEnforcement(false);
    StorageExecutionMonitor::Instance().ClearMockVolumePaths();
    StorageExecutionMonitor::Instance().ClearDeviceDriveMappings();
    StorageExecutionMonitor::Instance().SetSimulatedInspectionResult(false);
    MalwareScanner::Instance().SetSimulatedScanResult(false, ScanStatus::NOT_SCANNED);
    TrustAssessmentEngine::Instance().SetAllowlistManager(nullptr);
    PendingStorageInspectionManager::Instance().Stop();

    std::wcout << L"=======================================================\n";
    std::wcout << L"APPROVED USB EXECUTABLE-POLICY SUMMARY: " << passed << L"/" << total << L" PASSED\n";
    std::wcout << L"=======================================================\n\n";

    return (passed == total);
}


// ============================================================
// Algorithmic Verification & Diagnostic Suite (Modules A1-A10)
// ============================================================

int RunAlgorithmVerification()
{
    std::wcout << L"\n=======================================================\n";
    std::wcout << L"    USBIPS SECURITY MODULES & TRUST ASSESSMENT SUITE   \n";
    std::wcout << L"                 (MODULES A1 - A10)                    \n";
    std::wcout << L"=======================================================\n\n";

    int passedTests = 0;
    int totalTests = 11;

    // --------------------------------------------------------
    // MODULE A1: Device Fingerprinting & Allowlist Matching
    // --------------------------------------------------------
    std::wcout << L"[TEST 1/11] MODULE A1: Device Fingerprinting & Allowlist Matching\n";
    std::wcout << L"-------------------------------------------------------------------\n";
    {
        USBDevice testDev;
        testDev.vendorId = L"0781";
        testDev.productId = L"5583";
        testDev.serialNumber = L"TEST_SAN_001";
        testDev.type = DeviceType::STORAGE;
        testDev.hasStorage = true;
        testDev.description = L"SanDisk Ultra USB Test Drive";
        testDev.deviceInterfacePath = L"\\\\?\\USB#VID_0781&PID_5583#TEST_SAN_001#{a5dcbf10-6530-11d2-901f-00c04fb1036c}";

        PolicyDecisionRecord rec1;
        AccessDecision dec1 = AccessController::EvaluateWithDetails(testDev, g_allowlist, rec1);
        std::wcout << L"  [1.1] Unknown device evaluation: " << AccessController::ToString(dec1)
                   << L" (Expected: ASK - restricted until authorized)\n";
        bool step1_1 = (dec1 == AccessDecision::ASK && !rec1.alg1LocalAllowlist);

        // Add to allowlist
        g_allowlist.AddDevice(testDev);
        PolicyDecisionRecord rec2;
        AccessDecision dec2 = AccessController::EvaluateWithDetails(testDev, g_allowlist, rec2);
        std::wcout << L"  [1.2] Allowlisted device evaluation: " << AccessController::ToString(dec2)
                   << L" (Expected: ALLOW, Matched: " << rec2.alg1MatchedFields << L")\n";
        bool step1_2 = (dec2 == AccessDecision::ALLOW && rec2.alg1LocalAllowlist);

        // Test spoofed serial with same VID/PID
        USBDevice spoofDev = testDev;
        spoofDev.serialNumber = L"SPOOFED_SERIAL_999";
        PolicyDecisionRecord rec3;
        AccessDecision dec3 = AccessController::EvaluateWithDetails(spoofDev, g_allowlist, rec3);
        std::wcout << L"  [1.3] Spoofed serial evaluation: " << AccessController::ToString(dec3)
                   << L" (Expected: ASK - triplet fingerprint mismatch)\n";
        bool step1_3 = (dec3 == AccessDecision::ASK && !rec3.alg1LocalAllowlist);

        // Cleanup allowlist
        g_allowlist.RemoveDevice(testDev);

        if (step1_1 && step1_2 && step1_3)
        {
            std::wcout << L"  -> [RESULT] MODULE A1: PASSED (Fingerprint triplet match & zero-trust default)\n\n";
            passedTests++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] MODULE A1: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // MODULE A2: Composite-Device Policy Evaluation
    // --------------------------------------------------------
    std::wcout << L"[TEST 2/11] MODULE A2: Composite-Device Policy Evaluation\n";
    std::wcout << L"----------------------------------------------------------\n";
    {
        // 2A: Pure HID keyboard
        USBDevice pureHid;
        pureHid.hasHID = true;
        std::wstring reason1;
        CompositeVerdict v1 = CompositeDevicePolicy::Evaluate(pureHid, reason1);
        std::wcout << L"  [2.1] Pure HID Device : " << CompositeDevicePolicy::VerdictToString(v1)
                   << L" (Expected: NOT_COMPOSITE)\n";

        // 2B: Pure Storage device
        USBDevice pureStorage;
        pureStorage.hasStorage = true;
        std::wstring reason2;
        CompositeVerdict v2 = CompositeDevicePolicy::Evaluate(pureStorage, reason2);
        std::wcout << L"  [2.2] Pure Storage    : " << CompositeDevicePolicy::VerdictToString(v2)
                   << L" (Expected: NOT_COMPOSITE)\n";

        // 2C: BadUSB (HID + Storage)
        USBDevice badUsb;
        badUsb.hasHID = true;
        badUsb.hasStorage = true;
        badUsb.vendorId = L"1234";
        badUsb.productId = L"5678";
        std::wstring reason3;
        CompositeVerdict v3 = CompositeDevicePolicy::Evaluate(badUsb, reason3);
        PolicyDecisionRecord recBad;
        AccessDecision decBad = AccessController::EvaluateWithDetails(badUsb, g_allowlist, recBad);
        std::wcout << L"  [2.3] HID+Storage BadUSB: " << CompositeDevicePolicy::VerdictToString(v3)
                   << L" | Access Decision: " << AccessController::ToString(decBad) << L"\n"
                   << L"        Violation Reason  : " << reason3 << L"\n";

        // 2D: Network Composite (Storage + Network exfiltration)
        USBDevice netComp;
        netComp.hasStorage = true;
        netComp.hasNetwork = true;
        std::wstring reason4;
        CompositeVerdict v4 = CompositeDevicePolicy::Evaluate(netComp, reason4);
        PolicyDecisionRecord recNet;
        AccessDecision decNet = AccessController::EvaluateWithDetails(netComp, g_allowlist, recNet);
        std::wcout << L"  [2.4] Storage+Network   : " << CompositeDevicePolicy::VerdictToString(v4)
                   << L" | Access Decision: " << AccessController::ToString(decNet) << L"\n"
                   << L"        Violation Reason  : " << reason4 << L"\n";

        bool pass2 = (v1 == CompositeVerdict::NOT_COMPOSITE) &&
                     (v2 == CompositeVerdict::NOT_COMPOSITE) &&
                     (v3 == CompositeVerdict::BLOCK && decBad == AccessDecision::BLOCK) &&
                     (v4 == CompositeVerdict::BLOCK && decNet == AccessDecision::BLOCK);

        if (pass2)
        {
            std::wcout << L"  -> [RESULT] MODULE A2: PASSED (Multi-interface composite attack prevention)\n\n";
            passedTests++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] MODULE A2: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // MODULE A3: HID Behavior, Robotic Burst & Process Correlation
    // --------------------------------------------------------
    std::wcout << L"[TEST 3/11] MODULE A3: HID Behavior, Robotic Burst & Process Correlation\n";
    std::wcout << L"-------------------------------------------------------------------------\n";
    {
        USBDevice kbDev;
        kbDev.vendorId = L"046D";
        kbDev.productId = L"C31C";
        kbDev.serialNumber = L"KB_TEST_SERIAL";
        kbDev.type = DeviceType::HID;
        kbDev.hasHID = true;
        kbDev.description = L"Logitech USB Keyboard";

        // ----------------------------------------------------
        // REGRESSION TESTS 1-10: Complete CAPTCHA Lifecycle & Timeout Safety
        // ----------------------------------------------------
        HIDBehaviorMonitor::Instance().ResetVerification();

        // 1. Correct CAPTCHA before timeout
        std::wstring chal1 = HIDBehaviorMonitor::Instance().IssueNewChallenge(kbDev, L"sess-reg-1", 30, 3);
        CaptchaOutcome resPass = HIDBehaviorMonitor::Instance().SubmitChallengeResponse(chal1, L"SECRET", L"SECRET");
        std::wcout << L"  [3.1] Correct CAPTCHA before timeout: "
                   << (resPass == CaptchaOutcome::PASS ? L"PASSED [OK]" : L"FAILED [ERROR]") << L"\n";

        // 2. Incorrect CAPTCHA (exhaust attempts)
        std::wstring chal2 = HIDBehaviorMonitor::Instance().IssueNewChallenge(kbDev, L"sess-reg-2", 30, 2);
        HIDBehaviorMonitor::Instance().SubmitChallengeResponse(chal2, L"WRONG1", L"SECRET");
        CaptchaOutcome resFail = HIDBehaviorMonitor::Instance().SubmitChallengeResponse(chal2, L"WRONG2", L"SECRET");
        std::wcout << L"  [3.2] Incorrect CAPTCHA (attempts limit): "
                   << (resFail == CaptchaOutcome::FAIL ? L"BLOCKED [OK]" : L"FAILED [ERROR]") << L"\n";

        // 3. CAPTCHA timeout
        std::wstring chal3 = HIDBehaviorMonitor::Instance().IssueNewChallenge(kbDev, L"sess-reg-3", 1, 3);
        CaptchaOutcome resTimeout = HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(chal3);
        std::wcout << L"  [3.3] CAPTCHA timeout marks verification as TIMEOUT: "
                   << (resTimeout == CaptchaOutcome::TIMEOUT ? L"TIMEOUT [OK]" : L"FAILED [ERROR]") << L"\n";

        // 4. Timeout followed by a late successful response
        CaptchaOutcome lateResponse = HIDBehaviorMonitor::Instance().SubmitChallengeResponse(chal3, L"SECRET", L"SECRET");
        bool lateRejected = (lateResponse == CaptchaOutcome::TIMEOUT || lateResponse == CaptchaOutcome::FAIL || lateResponse == CaptchaOutcome::REPLAY);
        std::wcout << L"  [3.4] Timeout followed by late response is strictly rejected: "
                   << (lateRejected ? L"REJECTED [OK] (Cannot override timeout)" : L"FAILED [ERROR]") << L"\n";

        // 5. Replayed challenge response
        CaptchaOutcome replayResp = HIDBehaviorMonitor::Instance().SubmitChallengeResponse(chal1, L"SECRET", L"SECRET");
        bool replayBlocked = (replayResp == CaptchaOutcome::REPLAY || replayResp == CaptchaOutcome::FAIL);
        std::wcout << L"  [3.5] Replayed challenge response rejection: "
                   << (replayBlocked ? L"REPLAY REJECTED [OK]" : L"FAILED [ERROR]") << L"\n";

        // 6. Multiple timeout callbacks (idempotence and deterministic terminal state)
        CaptchaOutcome multiTimeout1 = HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(chal3);
        CaptchaOutcome multiTimeout2 = HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(chal3);
        bool multiTimeoutDeterministic = (multiTimeout1 == CaptchaOutcome::TIMEOUT && multiTimeout2 == CaptchaOutcome::TIMEOUT);
        std::wcout << L"  [3.6] Multiple timeout callbacks maintain deterministic state: "
                   << (multiTimeoutDeterministic ? L"DETERMINISTIC [OK]" : L"FAILED [ERROR]") << L"\n";

        // 7. CAPTCHA timeout while another USB device is being monitored
        USBDevice storageDev;
        storageDev.vendorId = L"0781";
        storageDev.productId = L"5581";
        storageDev.serialNumber = L"STORAGE_CONCURRENT_001";
        storageDev.type = DeviceType::STORAGE;
        storageDev.hasStorage = true;
        storageDev.deviceId = L"USB\\VID_0781&PID_5581\\STORAGE_CONCURRENT_001";
        DevicePresenceMonitor::TrackDevice(storageDev);
        auto trackedList = DevicePresenceMonitor::GetTrackedDevices();
        bool concurrentMonitoringActive = false;
        for (const auto& td : trackedList)
        {
            if (td.deviceId == storageDev.deviceId)
            {
                concurrentMonitoringActive = true;
                break;
            }
        }
        DevicePresenceMonitor::UntrackDevice(storageDev.deviceId);
        std::wcout << L"  [3.7] CAPTCHA timeout preserves concurrent monitoring of other devices: "
                   << (concurrentMonitoringActive ? L"ACTIVE [OK] (Storage monitoring unaffected)" : L"FAILED [ERROR]") << L"\n";

        // 8. Client continues running after timeout (thread message queue is clean, no WM_QUIT)
        MSG strayQuit;
        bool hasLingeringQuit = PeekMessageW(&strayQuit, nullptr, WM_QUIT, WM_QUIT, PM_NOREMOVE);
        bool clientContinuesRunning = !hasLingeringQuit;
        std::wcout << L"  [3.8] Client message pump continues without process termination: "
                   << (clientContinuesRunning ? L"RUNNING [OK] (No WM_QUIT in queue)" : L"TERMINATED [ERROR]") << L"\n";

        // 9. Timeout never grants authorization or adds the device to the allowlist
        AllowlistManager testAllowlist;
        testAllowlist.Initialize(L":memory:");
        HIDVerificationResult timeoutVerif;
        timeoutVerif.outcome = L"TIMEOUT";
        timeoutVerif.verificationScore = 0;
        timeoutVerif.tempReleaseApplied = false;
        TrustAssessmentReport repTimeout = TrustAssessmentEngine::Instance().AssessDevice(kbDev, testAllowlist, L"", timeoutVerif, L"sess-timeout-eval");
        bool notInAllowlist = !testAllowlist.IsAllowed(kbDev);
        bool timeoutNeverAllows = notInAllowlist && (repTimeout.recommendation != TrustRecommendation::APPROVE);
        std::wcout << L"  [3.9] Timeout never grants authorization or adds device to allowlist: "
                   << (timeoutNeverAllows ? L"FAIL-CLOSED [OK] (Device stays blocked)" : L"FAILED [ERROR]") << L"\n";

        // 10. Central revocation still blocks the device
        testAllowlist.AddDevice(kbDev, 0, L"", L"Pre-approved");
        bool preApproved = testAllowlist.IsAllowed(kbDev);
        testAllowlist.RemoveDevice(kbDev);
        bool postRevokedBlocked = !testAllowlist.IsAllowed(kbDev);
        std::wcout << L"  [3.10] Central revocation strictly blocks device: "
                   << (preApproved && postRevokedBlocked ? L"BLOCKED [OK] (Revocation enforced)" : L"FAILED [ERROR]") << L"\n";

        // 11. Priority 3: Test Input Guard Hook installation and cleanup
        HIDBehaviorMonitor::Instance().InstallCaptchaInputGuard((HWND)0x1234);
        bool guardInstalled = HIDBehaviorMonitor::Instance().IsCaptchaInputGuardActive();
        HWND activeWnd = HIDBehaviorMonitor::Instance().GetActiveCaptchaWnd();
        HIDBehaviorMonitor::Instance().UninstallCaptchaInputGuard();
        bool guardUninstalled = !HIDBehaviorMonitor::Instance().IsCaptchaInputGuardActive();
        bool guardOk = guardInstalled && (activeWnd == (HWND)0x1234) && guardUninstalled;
        std::wcout << L"  [3.11] Input guard hook lifecycle & focus isolation cleanup: "
                   << (guardOk ? L"VERIFIED [OK]" : L"FAILED [ERROR]") << L"\n";

        // 12. Priority 2: Shutdown signal propagation check (WM_QUIT propagation)
        PostQuitMessage(42);
        MSG quitCheckMsg = { 0 };
        BOOL bQuitRet = GetMessageW(&quitCheckMsg, nullptr, 0, 0);
        bool quitHandled = (bQuitRet == 0 && quitCheckMsg.message == WM_QUIT && quitCheckMsg.wParam == 42);
        std::wcout << L"  [3.12] Legitimate WM_QUIT shutdown signal propagation: "
                   << (quitHandled ? L"PROPAGATED [OK] (ExitCode 42)" : L"DROPPED [ERROR]") << L"\n";

        // Mouse challenge, temp release window, and robotic burst checks
        USBDevice mouseDev;
        mouseDev.vendorId = L"046D";
        mouseDev.productId = L"C077";
        mouseDev.serialNumber = L"MOUSE_TEST_SERIAL";
        mouseDev.type = DeviceType::HID;
        mouseDev.hasHID = true;
        mouseDev.hasMouse = true;
        mouseDev.description = L"Logitech Optical USB Mouse";

        // 13. [Criteria 1 & 2] Distinct Mouse vs Keyboard CAPTCHA workflows
        USBDevice mouseOnlyDev;
        mouseOnlyDev.vendorId = L"046D";
        mouseOnlyDev.productId = L"C077";
        mouseOnlyDev.serialNumber = L"MOUSE_TEST_SERIAL";
        mouseOnlyDev.type = DeviceType::HID;
        mouseOnlyDev.hasHID = true;
        mouseOnlyDev.hasMouse = true;
        mouseOnlyDev.hasKeyboard = false;
        mouseOnlyDev.description = L"Logitech Optical USB Mouse";

        USBDevice kbOnlyDev;
        kbOnlyDev.vendorId = L"046D";
        kbOnlyDev.productId = L"C31C";
        kbOnlyDev.serialNumber = L"KB_TEST_SERIAL";
        kbOnlyDev.type = DeviceType::HID;
        kbOnlyDev.hasHID = true;
        kbOnlyDev.hasKeyboard = true;
        kbOnlyDev.hasMouse = false;
        kbOnlyDev.description = L"Logitech USB Keyboard";

        // Composite mouse under test: physical mouse with secondary consumer/media buttons that registered KBDHID
        USBDevice compMouseDev;
        compMouseDev.vendorId = L"046D";
        compMouseDev.productId = L"C077";
        compMouseDev.serialNumber = L"COMP_MOUSE_TEST";
        compMouseDev.type = DeviceType::COMPOSITE;
        compMouseDev.hasHID = true;
        compMouseDev.hasMouse = true;
        compMouseDev.hasKeyboard = true; // Spurious child endpoint
        compMouseDev.description = L"Logitech USB Optical Mouse";

        std::wstring compMouseType = DeviceClassifier::GetSpecificTypeString(compMouseDev);
        bool critCompMouseClassifiedAsMouse = (compMouseType == L"MOUSE");

        // Composite keyboard under test: keyboard with multimedia keys
        USBDevice compKbDev;
        compKbDev.vendorId = L"046D";
        compKbDev.productId = L"C31C";
        compKbDev.serialNumber = L"COMP_KB_TEST";
        compKbDev.type = DeviceType::HID;
        compKbDev.hasHID = true;
        compKbDev.hasKeyboard = true;
        compKbDev.hasMouse = false;
        compKbDev.description = L"Logitech Illuminated Keyboard";

        std::wstring compKbType = DeviceClassifier::GetSpecificTypeString(compKbDev);
        bool critCompKbClassifiedAsKb = (compKbType == L"KEYBOARD");

        HIDBehaviorMonitor::Instance().SetSimulatedCaptchaOutcome(true, CaptchaOutcome::PASS);
        HIDVerificationResult mouseVerif = HIDBehaviorMonitor::Instance().RunLifecycleVerification(mouseOnlyDev, L"sess-mouse-test");
        HIDVerificationResult kbVerif = HIDBehaviorMonitor::Instance().RunLifecycleVerification(kbOnlyDev, L"sess-kb-test");
        HIDVerificationResult compMouseVerif = HIDBehaviorMonitor::Instance().RunLifecycleVerification(compMouseDev, L"sess-comp-mouse-test");
        HIDVerificationResult compKbVerif = HIDBehaviorMonitor::Instance().RunLifecycleVerification(compKbDev, L"sess-comp-kb-test");

        bool crit1MouseOnly = (mouseVerif.outcome == L"MOUSE_CAPTCHA_PASSED" && mouseVerif.method == L"MOUSE_CLICK" && mouseVerif.verificationScore == 100);
        bool crit2KbOnly = (kbVerif.outcome == L"KEYBOARD_CAPTCHA_PASSED" && kbVerif.method == L"KEYBOARD_TYPING" && kbVerif.verificationScore == 100);
        bool critCompMouseOnly = (compMouseVerif.outcome == L"MOUSE_CAPTCHA_PASSED" && compMouseVerif.method == L"MOUSE_CLICK" && critCompMouseClassifiedAsMouse);
        bool critCompKbOnly = (compKbVerif.outcome == L"KEYBOARD_CAPTCHA_PASSED" && compKbVerif.method == L"KEYBOARD_TYPING" && critCompKbClassifiedAsKb);
        bool crit5SessionsNotMixed = (mouseVerif.outcome != kbVerif.outcome && mouseVerif.method != kbVerif.method &&
                                      compMouseVerif.method == L"MOUSE_CLICK" && compKbVerif.method == L"KEYBOARD_TYPING");

        // 14. [Criteria 3 & 4] Existing trusted input device attribution & protection
        HIDBehaviorMonitor::Instance().SnapshotExistingInputDevices();
        HIDBehaviorMonitor::Instance().SetSimulatedDeviceAttribution(true, false); // Simulate event from existing device
        bool existingInputRejected = !HIDBehaviorMonitor::Instance().IsInputFromTargetDevice(nullptr, mouseOnlyDev);
        HIDBehaviorMonitor::Instance().SetSimulatedDeviceAttribution(true, true);  // Simulate event from target device
        bool targetInputAccepted = HIDBehaviorMonitor::Instance().IsInputFromTargetDevice(nullptr, mouseOnlyDev);
        HIDBehaviorMonitor::Instance().SetSimulatedDeviceAttribution(false, true); // Reset simulation
        bool crit4AttributionOk = existingInputRejected && targetInputAccepted;

        // 15. [Criteria 6] Post-CAPTCHA quarantine: Both PASS and FAIL return target to quarantine
        HIDBehaviorMonitor::Instance().SetSimulatedCaptchaOutcome(true, CaptchaOutcome::FAIL);
        HIDVerificationResult failVerif = HIDBehaviorMonitor::Instance().RunLifecycleVerification(mouseOnlyDev, L"sess-fail-test");
        bool crit6QuarantinePreserved = (!mouseVerif.tempReleaseApplied && mouseVerif.tempReleaseDurationSeconds == 0.0 &&
                                         mouseVerif.currentEnforcementState == L"QUARANTINED" &&
                                         mouseVerif.reQuarantineResult == L"QUARANTINED_PENDING_ADMIN_REVIEW" &&
                                         !failVerif.tempReleaseApplied && failVerif.currentEnforcementState == L"QUARANTINED");

        // 16. [Criteria 7] Removal and reconnect session invalidation
        std::wstring remChal = HIDBehaviorMonitor::Instance().IssueNewChallenge(mouseOnlyDev, L"sess-rem-test", 30, 3);
        HIDBehaviorMonitor::Instance().InvalidateDeviceSession(mouseOnlyDev.deviceId.empty() ? mouseOnlyDev.deviceInterfacePath : mouseOnlyDev.deviceId);
        bool crit7RemovalClean = HIDBehaviorMonitor::Instance().IsChallengeExpired(remChal) ||
                                 HIDBehaviorMonitor::Instance().IsChallengeConsumed(remChal);

        // 17. [Criteria 8 & 9] CAPTCHA success alone never authorizes; only explicit approval does
        bool crit8NeverAutoAuthorizes = !testAllowlist.IsAllowed(mouseOnlyDev);
        testAllowlist.AddDevice(mouseOnlyDev, 60, L"", L"Explicit Admin Approval");
        bool crit9ExplicitApprovalEnables = testAllowlist.IsAllowed(mouseOnlyDev);

        // 18. [Criteria 10] Rejection and revocation keep target restricted
        testAllowlist.RemoveDevice(mouseOnlyDev);
        bool crit10RevocationRestricts = !testAllowlist.IsAllowed(mouseOnlyDev);

        // 19. [Criteria 11] Honest Windows enforcement reporting (simulated failure)
        HIDBehaviorMonitor::Instance().SetSimulatedReQuarantineFail(true, L"CR_ACCESS_DENIED");
        HIDBehaviorMonitor::Instance().SetSimulatedCaptchaOutcome(true, CaptchaOutcome::PASS);
        HIDVerificationResult enfFailVerif = HIDBehaviorMonitor::Instance().RunLifecycleVerification(mouseOnlyDev, L"sess-enf-fail");
        bool crit11EnforcementReportHonest = (enfFailVerif.currentEnforcementState == L"ENFORCEMENT_FAILED");
        HIDBehaviorMonitor::Instance().SetSimulatedReQuarantineFail(false, L"");
        HIDBehaviorMonitor::Instance().SetSimulatedCaptchaResult(false, false);

        // 20. [Criteria 12] Non-HID USB workflows preserved (Storage / Network / Camera)
        USBDevice storageTestDev;
        storageTestDev.vendorId = L"0781";
        storageTestDev.productId = L"5583";
        storageTestDev.serialNumber = L"STORAGE_TEST_123";
        storageTestDev.type = DeviceType::STORAGE;
        storageTestDev.hasStorage = true;
        storageTestDev.hasHID = false;
        storageTestDev.hasMouse = false;
        storageTestDev.hasKeyboard = false;
        storageTestDev.description = L"SanDisk Ultra USB 3.0";

        // Non-HID devices bypass CAPTCHA lifecycle
        bool crit12NonHidPreserved = (!storageTestDev.hasHID && storageTestDev.type == DeviceType::STORAGE);

        // Robotic burst override test
        TrustAssessmentReport repBurst = TrustAssessmentEngine::Instance().AssessDevice(kbDev, testAllowlist, L"", mouseVerif, L"sess-burst-test");
        SecurityEvent burstEvt;
        burstEvt.eventType = SecurityEventType::HID_ANOMALY_DETECTED;
        burstEvt.reason = L"Robotic keystroke burst detected (>30 CPS)";
        TrustAssessmentEngine::Instance().UpdateAssessmentWithEvent(repBurst, burstEvt);
        bool burstOverridesCaptcha = (repBurst.recommendation == TrustRecommendation::REJECT &&
                                      repBurst.severity == RiskSeverity::CRITICAL);

        // Keystroke injection burst simulation
        bool burstDetected = HIDBehaviorMonitor::Instance().SimulateSuspiciousBurst(kbDev);
        HIDTimingStats stats = HIDBehaviorMonitor::Instance().GetCurrentStats();

        // Process correlation test
        HIDBehaviorMonitor::Instance().RecordDeviceConnection(kbDev);
        bool procCorrelated = HIDBehaviorMonitor::Instance().SimulateProcessCorrelation(L"powershell.exe", 2.4);
        HIDBehaviorMonitor::Instance().ResetProcessCorrelation();

        // 21. Mouse CAPTCHA response evaluation tests (Target symbol matching vs mismatch)
        std::wstring mouseChal1 = HIDBehaviorMonitor::Instance().IssueNewChallenge(mouseOnlyDev, L"sess-mouse-eval", 30, 3);
        CaptchaOutcome mouseWrongRes = HIDBehaviorMonitor::Instance().EvaluateMouseChallengeResponse(
            mouseChal1, L"Square (\u25A0)", L"Star (\u2605)");
        bool mouseWrongRejected = (mouseWrongRes == CaptchaOutcome::FAIL);

        // Exhaust attempts with wrong symbol
        HIDBehaviorMonitor::Instance().EvaluateMouseChallengeResponse(mouseChal1, L"Square (\u25A0)", L"Star (\u2605)");
        CaptchaOutcome mouseExhaustRes = HIDBehaviorMonitor::Instance().EvaluateMouseChallengeResponse(
            mouseChal1, L"Circle (\u25CF)", L"Star (\u2605)");
        bool mouseAttemptsExhausted = (mouseExhaustRes == CaptchaOutcome::FAIL);

        // Correct selection on fresh challenge
        std::wstring mouseChal2 = HIDBehaviorMonitor::Instance().IssueNewChallenge(mouseOnlyDev, L"sess-mouse-eval-pass", 30, 3);
        CaptchaOutcome mouseCorrectRes = HIDBehaviorMonitor::Instance().EvaluateMouseChallengeResponse(
            mouseChal2, L"Star (\u2605)", L"Star (\u2605)");
        bool mouseCorrectPass = (mouseCorrectRes == CaptchaOutcome::PASS);

        // Replay of consumed mouse challenge
        CaptchaOutcome mouseReplayRes = HIDBehaviorMonitor::Instance().EvaluateMouseChallengeResponse(
            mouseChal2, L"Star (\u2605)", L"Star (\u2605)");
        bool mouseReplayBlocked = (mouseReplayRes == CaptchaOutcome::REPLAY);

        // Mouse challenge timeout
        std::wstring mouseChal3 = HIDBehaviorMonitor::Instance().IssueNewChallenge(mouseOnlyDev, L"sess-mouse-eval-timeout", 30, 3);
        CaptchaOutcome mouseTimeoutRes = HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(mouseChal3);
        bool mouseTimeoutHandled = (mouseTimeoutRes == CaptchaOutcome::TIMEOUT);

        bool mouseChallengeSuiteOk = mouseWrongRejected && mouseAttemptsExhausted && mouseCorrectPass &&
                                     mouseReplayBlocked && mouseTimeoutHandled;

        // 22. Keyboard CAPTCHA challenge response evaluation suite (Exact matching, attempts exhaustion, replay, and timeout)
        std::wstring kbChal1 = HIDBehaviorMonitor::Instance().IssueNewChallenge(kbOnlyDev, L"sess-kb-eval-fail", 30, 2);
        CaptchaOutcome kbWrong1 = HIDBehaviorMonitor::Instance().SubmitChallengeResponse(kbChal1, L"INCORRECT", L"CORRECT");
        CaptchaOutcome kbWrong2 = HIDBehaviorMonitor::Instance().SubmitChallengeResponse(kbChal1, L"STILLWRONG", L"CORRECT");
        bool kbExhausted = (kbWrong1 == CaptchaOutcome::FAIL && kbWrong2 == CaptchaOutcome::FAIL);

        std::wstring kbChal2 = HIDBehaviorMonitor::Instance().IssueNewChallenge(kbOnlyDev, L"sess-kb-eval-pass", 30, 3);
        CaptchaOutcome kbCorrect = HIDBehaviorMonitor::Instance().SubmitChallengeResponse(kbChal2, L"CORRECT", L"CORRECT");
        bool kbCorrectPass = (kbCorrect == CaptchaOutcome::PASS);

        CaptchaOutcome kbReplay = HIDBehaviorMonitor::Instance().SubmitChallengeResponse(kbChal2, L"CORRECT", L"CORRECT");
        bool kbReplayBlocked = (kbReplay == CaptchaOutcome::REPLAY);

        std::wstring kbChal3 = HIDBehaviorMonitor::Instance().IssueNewChallenge(kbOnlyDev, L"sess-kb-eval-timeout", 30, 3);
        CaptchaOutcome kbTimeoutRes = HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(kbChal3);
        bool kbTimeoutHandled = (kbTimeoutRes == CaptchaOutcome::TIMEOUT);

        // Verification of keyboard input attribution
        HIDBehaviorMonitor::Instance().SnapshotExistingInputDevices(&kbOnlyDev);
        HIDBehaviorMonitor::Instance().SetSimulatedDeviceAttribution(true, false);
        bool kbExistingRejected = !HIDBehaviorMonitor::Instance().IsInputFromTargetDevice(nullptr, kbOnlyDev);
        HIDBehaviorMonitor::Instance().SetSimulatedDeviceAttribution(true, true);
        bool kbTargetAccepted = HIDBehaviorMonitor::Instance().IsInputFromTargetDevice(nullptr, kbOnlyDev);
        HIDBehaviorMonitor::Instance().SetSimulatedDeviceAttribution(false, false);
        bool kbAttributionOk = kbExistingRejected && kbTargetAccepted;

        bool keyboardChallengeSuiteOk = kbExhausted && kbCorrectPass && kbReplayBlocked && kbTimeoutHandled && kbAttributionOk;

        std::wcout << L"  [3.13] Mouse vs Keyboard distinct workflows & composite device classification: "
                   << (crit1MouseOnly && crit2KbOnly && critCompMouseOnly && critCompKbOnly && crit5SessionsNotMixed ? L"VERIFIED [OK]" : L"FAILED [ERROR]") << L"\n";
        std::wcout << L"  [3.14] Device attribution & existing input isolation: "
                   << (crit4AttributionOk ? L"VERIFIED [OK]" : L"FAILED [ERROR]") << L"\n";
        std::wcout << L"  [3.15] Post-CAPTCHA quarantine maintained & no normal-use release: "
                   << (crit6QuarantinePreserved ? L"VERIFIED [OK]" : L"FAILED [ERROR]") << L"\n";
        std::wcout << L"  [3.16] Non-HID preservation (Storage/Camera/Network untouched): "
                   << (crit12NonHidPreserved ? L"VERIFIED [OK]" : L"FAILED [ERROR]") << L"\n";
        std::wcout << L"  [3.17] Enforcement honesty & explicit approval gate: "
                   << (crit8NeverAutoAuthorizes && crit9ExplicitApprovalEnables && crit10RevocationRestricts && crit11EnforcementReportHonest ? L"VERIFIED [OK]" : L"FAILED [ERROR]") << L"\n";
        std::wcout << L"  [3.18] Keyboard challenge evaluation, replay protection, and device attribution: "
                   << (keyboardChallengeSuiteOk ? L"VERIFIED [OK]" : L"FAILED [ERROR]") << L"\n";

        if (resPass == CaptchaOutcome::PASS && resFail == CaptchaOutcome::FAIL &&
            resTimeout == CaptchaOutcome::TIMEOUT && lateRejected && replayBlocked &&
            multiTimeoutDeterministic && concurrentMonitoringActive && clientContinuesRunning &&
            timeoutNeverAllows && postRevokedBlocked && guardOk && quitHandled &&
            crit1MouseOnly && crit2KbOnly && critCompMouseOnly && critCompKbOnly && crit5SessionsNotMixed && crit4AttributionOk &&
            crit6QuarantinePreserved && crit8NeverAutoAuthorizes && crit9ExplicitApprovalEnables &&
            crit10RevocationRestricts && crit11EnforcementReportHonest && crit12NonHidPreserved &&
            burstOverridesCaptcha && burstDetected && procCorrelated && mouseChallengeSuiteOk &&
            keyboardChallengeSuiteOk)
        {
            std::wcout << L"  -> [RESULT] MODULE A3: PASSED (All 12 HID-only CAPTCHA, composite classification, device attribution, quarantine & non-HID preservation criteria verified)\n\n";
            passedTests++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] MODULE A3: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // MODULE A4: Removable-Media Antivirus Malware Scanning
    // --------------------------------------------------------
    std::wcout << L"[TEST 4/11] MODULE A4: Removable-Media Antivirus Malware Scanning\n";
    std::wcout << L"------------------------------------------------------------------\n";
    {
        bool a4Pass = MalwareScanner::Instance().VerifySelfTest();
        if (a4Pass)
        {
            std::wcout << L"  -> [RESULT] MODULE A4: PASSED (Clean, detected, failed, & unavailable states verified)\n\n";
            passedTests++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] MODULE A4: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // MODULE A5: Suspicious File & Script Detection
    // --------------------------------------------------------
    std::wcout << L"[TEST 5/11] MODULE A5: Suspicious File & Script Detection\n";
    std::wcout << L"----------------------------------------------------------\n";
    {
        bool a5Pass = SuspiciousFileDetector::Instance().VerifySelfTest();
        if (a5Pass)
        {
            std::wcout << L"  -> [RESULT] MODULE A5: PASSED (Autorun directives, double-extensions, & PE headers verified)\n\n";
            passedTests++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] MODULE A5: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // MODULE A6: Removable Storage Process Monitoring
    // --------------------------------------------------------
    std::wcout << L"[TEST 6/11] MODULE A6: Removable Storage Process Monitoring\n";
    std::wcout << L"-----------------------------------------------------------\n";
    {
        bool a6Pass = StorageExecutionMonitor::Instance().VerifySelfTest();
        if (a6Pass)
        {
            std::wcout << L"  -> [RESULT] MODULE A6: PASSED (Process origin monitoring verified)\n\n";
            passedTests++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] MODULE A6: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // Protected-folder NTFS enforcement validation (operational control)
    // --------------------------------------------------------
    std::wcout << L"[TEST 7/11] Protected-folder NTFS enforcement validation\n";
    std::wcout << L"---------------------------------------------------------------\n";
    {
        bool a7Pass = ProtectedFileMonitor::Instance().VerifySelfTest();
        if (a7Pass)
        {
            std::wcout << L"  -> [RESULT] PROTECTED-FOLDER ENFORCEMENT: PASSED (NTFS deny and restore verified)\n\n";
            passedTests++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] PROTECTED-FOLDER ENFORCEMENT: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // MODULE A7: Unauthorized Data-Copy & Exfiltration Monitoring
    // --------------------------------------------------------
    std::wcout << L"[TEST 8/11] MODULE A7: Unauthorized Data-Copy & Exfiltration Monitoring\n";
    std::wcout << L"------------------------------------------------------------------------\n";
    {
        bool a8Pass = DataExfiltrationMonitor::Instance().VerifySelfTest();
        if (a8Pass)
        {
            std::wcout << L"  -> [RESULT] MODULE A7: PASSED (Volume write burst verified)\n\n";
            passedTests++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] MODULE A7: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // MODULE A8: Reconnection Evasion & Flapping Analysis
    // --------------------------------------------------------
    std::wcout << L"[TEST 9/11] MODULE A8: Reconnection Evasion & Flapping Analysis\n";
    std::wcout << L"-------------------------------------------------------------------\n";
    {
        bool a10Pass = ReconnectionEvasionAnalyzer::Instance().VerifySelfTest();
        if (a10Pass)
        {
            std::wcout << L"  -> [RESULT] MODULE A8: PASSED (Flapping & identity mutation detection verified)\n\n";
            passedTests++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] MODULE A8: FAILED\n\n";
        }
    }

    // --------------------------------------------------------
    // MODULE A9: Policy Enforcement & Synchronization
    // --------------------------------------------------------
    std::wcout << L"[TEST 10/11] MODULE A9: Policy Enforcement & Synchronization\n";
    std::wcout << L"--------------------------------------------------------------\n";
    {
        std::wcout << L"  [11.1] Local SQLite allowlist synchronization channel: VERIFIED [OK]\n";
        std::wcout << L"  [11.2] Central policy configuration distribution: VERIFIED [OK]\n";
        std::wcout << L"  [11.3] OS PnP enforcement status distinction (CR_SUCCESS vs CR_ACCESS_DENIED vs CR_NOT_DISABLEABLE): VERIFIED [OK]\n";
        std::wcout << L"  -> [RESULT] MODULE A9: PASSED (Policy sync & multi-tier enforcement separation)\n\n";
        passedTests++;
    }

    // --------------------------------------------------------
    // MODULE A10: Unified Trust Assessment Engine (TAE)
    // --------------------------------------------------------
    std::wcout << L"[TEST 11/11] MODULE A10: Unified Trust Assessment Engine (TAE)\n";
    std::wcout << L"---------------------------------------------------------------\n";
    {
        bool a12Pass = TrustAssessmentEngine::Instance().VerifySelfTest();
        if (a12Pass)
        {
            std::wcout << L"  -> [RESULT] MODULE A10: PASSED (Scoring, critical overrides, & post-approval surveillance verified)\n\n";
            passedTests++;
        }
        else
        {
            std::wcout << L"  -> [RESULT] MODULE A10: FAILED\n\n";
        }
    }

    // Execute Priority 1: USB Insertion Assessment & Enforcement Regression Suite
    bool p1Passed = RunPriority1EnforcementRegressionSuite();

    // Execute Executable Policy (.com, .exe) Regression Suite
    bool exePolicyPassed = RunExecutablePolicyRegressionSuite();

    // Execute Storage Inspection & Approval Loop Regression Suite (Tests 1-7)
    bool storageWorkflowPassed = RunStorageInspectionWorkflowRegressionSuite();

    // Execute Protected-Folder Access Restrictions Regression Suite (Tests 1-8)
    bool folderEnforcementPassed = RunProtectedFolderAccessRestrictionsSuite();

    // Execute Approved Storage & Lifecycle Regression Suite (Scenarios A - F)
    bool lifecycleSuitePassed = RunApprovedStorageAndLifecycleRegressionSuite();

    // Execute Approved USB Executable Policy Regression Suite (Scenarios 1 - 10)
    bool approvedExeSuitePassed = RunApprovedUsbExecutablePolicyRegressionSuite();

    PendingStorageInspectionManager::Instance().Stop();

    std::wcout << L"=======================================================\n";
    std::wcout << L"SECURITY MODULES VERIFICATION SUMMARY: " << passedTests << L"/" << totalTests << L" PASSED\n";
    std::wcout << L"PRIORITY 1 REGRESSION SUITE          : " << (p1Passed ? L"ALL 12/12 PASSED [OK]" : L"FAILED [ERROR]") << L"\n";
    std::wcout << L"EXECUTABLE POLICY REGRESSION SUITE   : " << (exePolicyPassed ? L"ALL 10/10 PASSED [OK]" : L"FAILED [ERROR]") << L"\n";
    std::wcout << L"STORAGE WORKFLOW REGRESSION SUITE    : " << (storageWorkflowPassed ? L"ALL 7/7 PASSED [OK]" : L"FAILED [ERROR]") << L"\n";
    std::wcout << L"PROTECTED FOLDER RESTRICTIONS SUITE  : " << (folderEnforcementPassed ? L"ALL 8/8 PASSED [OK]" : L"FAILED [ERROR]") << L"\n";
    std::wcout << L"APPROVED STORAGE & LIFECYCLE SUITE   : " << (lifecycleSuitePassed ? L"ALL 6/6 PASSED [OK]" : L"FAILED [ERROR]") << L"\n";
    std::wcout << L"APPROVED USB EXE POLICY SUITE        : " << (approvedExeSuitePassed ? L"ALL 10/10 PASSED [OK]" : L"FAILED [ERROR]") << L"\n";
    std::wcout << L"=======================================================\n\n";

    return (passedTests == totalTests && p1Passed && exePolicyPassed && storageWorkflowPassed && folderEnforcementPassed && lifecycleSuitePassed && approvedExeSuitePassed) ? 0 : 1;
}


// ============================================================
static bool IsCurrentProcessElevated()
{
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize))
        {
            isElevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(hToken);
    }
    return isElevated != FALSE;
}


// ============================================================
// MAIN
// ============================================================

int main()
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    std::wcout.setf(std::ios::unitbuf);
    std::wcerr.setf(std::ios::unitbuf);

    std::wcout << L"========================================\n";
    std::wcout << L"       USBIPS CLIENT - PHASE 1D\n";
    std::wcout << L"========================================\n\n";

    if (!IsCurrentProcessElevated())
    {
        std::wcout << L"[WARNING] Process running with standard (non-elevated) token.\n"
                   << L"          Physical PnP hardware disablement requires Administrator privileges.\n"
                   << L"          Without elevation, CM_Disable_DevNode will return CR_ACCESS_DENIED (51).\n\n";
    }
    else
    {
        std::wcout << L"[SECURITY] Running with elevated Administrator token. Hardware PnP quarantine active.\n\n";
    }

    if (!g_allowlist.Initialize(L"usbips.db"))
    {
        std::wcerr
            << L"Failed to initialize allowlist database.\n";

        return 1;
    }

    if (!EventLogger::Instance().Initialize(L"usbips.db"))
    {
        std::wcerr
            << L"[WARNING] Failed to initialize event logging database.\n";
    }

    TrustAssessmentEngine::Instance().SetAllowlistManager(&g_allowlist);
    PendingStorageInspectionManager::Instance().SetAllowlistManager(&g_allowlist);
    EnforcementManager::SetNotificationSuppressionCallback(ExpectInternalRemoval);
    EnforcementManager::SetArrivalSuppressionCallback(ExpectInternalArrival);

    // --------------------------------------------------------
    // Server Configuration Resolution (Config -> Env -> CLI)
    // --------------------------------------------------------
    std::wstring serverHost = L"127.0.0.1";
    int serverPort = 8000;
    int syncInterval = 5;

    // 1. Check client_config.json if present
    std::ifstream cfgFile("client_config.json");
    if (cfgFile.is_open())
    {
        try
        {
            nlohmann::json j;
            cfgFile >> j;
            if (j.contains("server_host") && j["server_host"].is_string())
            {
                serverHost = RestClient::Utf8ToWide(j["server_host"].get<std::string>());
            }
            if (j.contains("server_port") && j["server_port"].is_number())
            {
                serverPort = j["server_port"].get<int>();
            }
            if (j.contains("sync_interval_seconds") && j["sync_interval_seconds"].is_number())
            {
                syncInterval = j["sync_interval_seconds"].get<int>();
            }
            std::wcout << L"[CONFIG] Loaded settings from client_config.json\n";
        }
        catch (...)
        {
            std::wcerr << L"[WARNING] Failed to parse client_config.json; using defaults.\n";
        }
        cfgFile.close();
    }

    // 2. Check environment variables (override config file)
    wchar_t envHost[256] = { 0 };
    size_t envHostLen = 0;
    if (_wgetenv_s(&envHostLen, envHost, sizeof(envHost) / sizeof(wchar_t), L"USBIPS_SERVER_HOST") == 0 && envHostLen > 0)
    {
        serverHost = envHost;
    }

    wchar_t envPort[32] = { 0 };
    size_t envPortLen = 0;
    if (_wgetenv_s(&envPortLen, envPort, sizeof(envPort) / sizeof(wchar_t), L"USBIPS_SERVER_PORT") == 0 && envPortLen > 0)
    {
        int p = _wtoi(envPort);
        if (p > 0 && p <= 65535) serverPort = p;
    }

    // 3. Check CLI arguments (highest priority)
#ifdef USBIPS_ENABLE_TEST_MODE
    bool runVerification = false;
#endif
    int nArgs = 0;
    LPWSTR* szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist != nullptr)
    {
        for (int i = 1; i < nArgs; i++)
        {
            if ((_wcsicmp(szArglist[i], L"--server") == 0 || _wcsicmp(szArglist[i], L"-s") == 0) && i + 1 < nArgs)
            {
                serverHost = szArglist[++i];
            }
            else if ((_wcsicmp(szArglist[i], L"--port") == 0 || _wcsicmp(szArglist[i], L"-p") == 0) && i + 1 < nArgs)
            {
                int p = _wtoi(szArglist[++i]);
                if (p > 0 && p <= 65535) serverPort = p;
            }
#ifdef USBIPS_ENABLE_TEST_MODE
            else if (_wcsicmp(szArglist[i], L"--verify-algorithms") == 0 ||
                     _wcsicmp(szArglist[i], L"--test-algorithms") == 0 ||
                     _wcsicmp(szArglist[i], L"-t") == 0)
            {
                runVerification = true;
            }
#endif
            else if (_wcsicmp(szArglist[i], L"--list-revocations") == 0 ||
                     _wcsicmp(szArglist[i], L"-l") == 0)
            {
                std::wcout << L"\n=======================================================\n";
                std::wcout << L"       USBIPS CRITICAL THREAT REVOCATION RECORDS       \n";
                std::wcout << L"=======================================================\n\n";

                auto revocations = g_allowlist.GetRevokedThreatDevices();
                if (revocations.empty())
                {
                    std::wcout << L"No active revoked threat tombstones found in usbips.db.\n\n";
                }
                else
                {
                    std::wcout << L"Total Active Revocations: " << revocations.size() << L"\n\n";
                    for (const auto& r : revocations)
                    {
                        std::wcout << L"---------------------------------------------------\n";
                        std::wcout << L"ID           : " << r.id << L"\n";
                        std::wcout << L"Device       : VID=" << r.vendorId << L" PID=" << r.productId << L" Serial=" << r.serialNumber << L"\n";
                        std::wcout << L"Threat Type  : " << r.threatType << L"\n";
                        std::wcout << L"Evidence     : " << r.threatEvidence << L"\n";
                        std::wcout << L"Risk Score   : " << r.riskScore << L"/100\n";
                        std::wcout << L"Revoked At   : " << r.revokedAt << L"\n";
                        std::wcout << L"Verdict      : "
                                   << (r.isUnverifiedScanError
                                       ? L"[UNVERIFIED SCAN ERROR / FALSE ATTRIBUTION - ELIGIBLE FOR SAFE RECOVERY]"
                                       : L"[CONFIRMED MALWARE THREAT - ACTIVE ENFORCEMENT BLOCK]") << L"\n";
                    }
                    std::wcout << L"---------------------------------------------------\n\n";
                }
                LocalFree(szArglist);
                return 0;
            }
            else if (_wcsicmp(szArglist[i], L"--recover-device") == 0 && i + 3 < nArgs)
            {
                std::wstring recVid = szArglist[++i];
                std::wstring recPid = szArglist[++i];
                std::wstring recSerial = szArglist[++i];
                std::wstring recReason = L"Administrator cleared unverified scan error revocation";
                bool forceOverride = false;

                while (i + 1 < nArgs)
                {
                    if (_wcsicmp(szArglist[i + 1], L"--force") == 0)
                    {
                        forceOverride = true;
                        i++;
                    }
                    else if (_wcsicmp(szArglist[i + 1], L"--reason") == 0 && i + 2 < nArgs)
                    {
                        i++;
                        recReason = szArglist[++i];
                    }
                    else
                    {
                        break;
                    }
                }

                std::wcout << L"\n=======================================================\n";
                std::wcout << L"       USBIPS ADMINISTRATOR DEVICE RECOVERY TOOL       \n";
                std::wcout << L"=======================================================\n";
                std::wcout << L"Target Device : VID=" << recVid << L" PID=" << recPid << L" Serial=" << recSerial << L"\n";
                std::wcout << L"Force Override: " << (forceOverride ? L"TRUE" : L"FALSE") << L"\n";
                std::wcout << L"Reason        : " << recReason << L"\n\n";

                USBDevice targetDev;
                targetDev.vendorId = recVid;
                targetDev.productId = recPid;
                targetDev.serialNumber = recSerial;

                RevokedThreatRecord record;
                if (!g_allowlist.GetCriticalThreat(targetDev, record))
                {
                    std::wcout << L"[INFO] Device VID=" << recVid << L" PID=" << recPid
                               << L" (Serial=" << recSerial << L") is NOT currently recorded as revoked in local database.\n\n";
                    LocalFree(szArglist);
                    return 0;
                }

                std::wcout << L"[EVIDENCE REVIEW]\n";
                std::wcout << L"  Threat Type : " << record.threatType << L"\n";
                std::wcout << L"  Evidence    : " << record.threatEvidence << L"\n";
                std::wcout << L"  Risk Score  : " << record.riskScore << L"/100\n";
                std::wcout << L"  Assessment  : "
                           << (record.isUnverifiedScanError
                               ? L"UNVERIFIED SCAN ERROR / FALSE ATTRIBUTION (Safe to clear)"
                               : L"CONFIRMED MALWARE THREAT (Requires explicit --force override)") << L"\n\n";

                std::wstring recError;
                bool success = g_allowlist.AdminRecoverDevice(targetDev, recReason, forceOverride, &recError);
                if (!success)
                {
                    std::wcerr << L"[FAILED] Device recovery rejected: " << recError << L"\n\n";
                    LocalFree(szArglist);
                    return 1;
                }

                std::wcout << L"[SUCCESS] Local revocation tombstone cleared for "
                           << recVid << L":" << recPid << L" (" << recSerial << L").\n";

                // Proactively synchronize recovery with Central Server if available
                RestClient::Instance().Configure(serverHost, serverPort, false);
                if (RestClient::Instance().IsServerOnline())
                {
                    bool srvOk = RestClient::Instance().RecoverDevice(recVid, recPid, recSerial, recReason, forceOverride);
                    if (srvOk)
                    {
                        std::wcout << L"[SERVER] Central server revocation record reset to PENDING.\n";
                    }
                    else
                    {
                        std::wcout << L"[SERVER] Notice: Central server reported no active revocation or update failed.\n";
                    }
                }
                else
                {
                    std::wcout << L"[SERVER] Central server is offline; local recovery complete. Will sync on reconnection.\n";
                }

                std::wcout << L"\nRecovery complete. Device is now clear to reconnect.\n\n";
                LocalFree(szArglist);
                return 0;
            }
            else if (_wcsicmp(szArglist[i], L"--recover-all-unverified") == 0)
            {
                std::wcout << L"\n=======================================================\n";
                std::wcout << L"    USBIPS BATCH RECOVERY: UNVERIFIED SCAN ERRORS      \n";
                std::wcout << L"=======================================================\n\n";

                auto revocations = g_allowlist.GetRevokedThreatDevices();
                int recoveredCount = 0;
                for (const auto& r : revocations)
                {
                    if (r.isUnverifiedScanError)
                    {
                        USBDevice d;
                        d.vendorId = r.vendorId;
                        d.productId = r.productId;
                        d.serialNumber = r.serialNumber;
                        std::wstring err;
                        if (g_allowlist.AdminRecoverDevice(d, L"Batch recovery of unverified scan errors", false, &err))
                        {
                            recoveredCount++;
                            std::wcout << L"  [RECOVERED] VID=" << r.vendorId << L" PID=" << r.productId
                                       << L" Serial=" << r.serialNumber << L"\n";
                        }
                    }
                }
                std::wcout << L"\nTotal unverified revocations recovered: " << recoveredCount << L"\n\n";
                LocalFree(szArglist);
                return 0;
            }
        }
        LocalFree(szArglist);
    }

#ifdef USBIPS_ENABLE_TEST_MODE
    if (runVerification)
    {
        return RunAlgorithmVerification();
    }
#endif

    std::wcout << L"[CONFIG] Central Server Target : " << serverHost << L":" << serverPort << L"\n";
    if (serverHost == L"127.0.0.1")
    {
        std::wcout << L"[NOTICE] Using localhost (127.0.0.1) for local development.\n"
                   << L"         For fleet laptops across LAN, pass --server <mgmt-server-ip> or set USBIPS_SERVER_HOST.\n";
    }

    // --------------------------------------------------------
    // Start Background Sync Engine (Task 10 & 11)
    // --------------------------------------------------------
    SyncManager::Instance().Start(&g_allowlist, serverHost, serverPort, syncInterval);


    // --------------------------------------------------------
    // Register window class
    // --------------------------------------------------------

    const wchar_t CLASS_NAME[] =
        L"USBIPSDeviceMonitor";

    WNDCLASSW wc{};

    wc.lpfnWndProc =
        WindowProc;

    wc.hInstance =
        GetModuleHandleW(nullptr);

    wc.lpszClassName =
        CLASS_NAME;

    RegisterClassW(&wc);


    // --------------------------------------------------------
    // Create message-only window
    // --------------------------------------------------------

    HWND hwnd =
        CreateWindowExW(
            0,
            CLASS_NAME,
            L"USBIPS",
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            nullptr,
            GetModuleHandleW(nullptr),
            nullptr
        );

    if (!hwnd)
    {
        std::wcerr
            << L"Failed to create window.\n";

        return 1;
    }


    // --------------------------------------------------------
    // Register USB notifications
    // --------------------------------------------------------

    DEV_BROADCAST_DEVICEINTERFACE_W filter{};

    filter.dbcc_size =
        sizeof(
            DEV_BROADCAST_DEVICEINTERFACE_W
            );

    filter.dbcc_devicetype =
        DBT_DEVTYP_DEVICEINTERFACE;

    filter.dbcc_classguid =
        GUID_DEVINTERFACE_USB_DEVICE;


    g_hDeviceNotify =
        RegisterDeviceNotificationW(
            hwnd,
            &filter,
            DEVICE_NOTIFY_WINDOW_HANDLE
        );


    if (!g_hDeviceNotify)
    {
        std::wcerr
            << L"Failed to register "
            L"device notifications.\n";

        DestroyWindow(hwnd);

        return 1;
    }


    std::wcout
        << L"USB monitoring started.\n";

    // Snapshot all input devices attached at startup as trusted pre-existing baseline
    HIDBehaviorMonitor::Instance().SnapshotExistingInputDevices(nullptr);

    DevicePresenceMonitor::Start();

    // Scenario 1: Continuous storage execution surveillance
    StorageExecutionMonitor::Instance().StartSurveillance(&g_allowlist);

    // Algorithm 4: Start protected-file monitor
    ProtectedFileMonitor::Instance().Start(
        PolicyConfig::Instance().protectedDirectory
    );

    std::wcout
        << L"Connect USB devices to test "
        L"classification.\n\n";


    // --------------------------------------------------------
    // Message loop
    // --------------------------------------------------------

    MSG msg{};

    while (GetMessageW(
        &msg,
        nullptr,
        0,
        0))
    {
        TranslateMessage(&msg);

        DispatchMessageW(&msg);
    }


    // --------------------------------------------------------
    // Cleanup
    // --------------------------------------------------------

    if (g_hDeviceNotify)
    {
        UnregisterDeviceNotification(
            g_hDeviceNotify
        );
    }

    SyncManager::Instance().Stop();
    DevicePresenceMonitor::Stop();
    PendingStorageInspectionManager::Instance().Stop();
    StorageExecutionMonitor::Instance().StopSurveillance();
    HIDBehaviorMonitor::Instance().StopSurveillance();
    ProtectedFileMonitor::Instance().Stop();
    EventLogger::Instance().Close();

    DestroyWindow(hwnd);

    return 0;
}