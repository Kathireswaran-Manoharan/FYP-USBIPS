#include "EnforcementManager.h"
#include "../Allowlist/AllowlistManager.h"
#include "../Presence/DevicePresenceMonitor.h"
#include "../Logging/EventLogger.h"
#include "../Network/RestClient.h"
#include "../Classifier/DeviceClassifier.h"
#include "../AccessControl/ProtectedFolderPolicy.h"

#include <windows.h>
#include <cfgmgr32.h>
#include <iostream>

#pragma comment(lib, "cfgmgr32.lib")

static bool s_mockEnforcement = false;
static bool s_mockSuccess = true;
static CONFIGRET s_mockCode = CR_SUCCESS;
static EnforcementManager::NotificationSuppressionCallback s_suppressionCb = nullptr;
static EnforcementManager::NotificationSuppressionCallback s_arrivalSuppressionCb = nullptr;

void EnforcementManager::SetMockEnforcement(bool enable, bool simulateSuccess, CONFIGRET simulatedCode)
{
    s_mockEnforcement = enable;
    s_mockSuccess = simulateSuccess;
    s_mockCode = simulatedCode;
}

bool EnforcementManager::IsMockEnforcement()
{
    return s_mockEnforcement;
}

void EnforcementManager::SetNotificationSuppressionCallback(NotificationSuppressionCallback cb)
{
    s_suppressionCb = cb;
}

void EnforcementManager::SetArrivalSuppressionCallback(NotificationSuppressionCallback cb)
{
    s_arrivalSuppressionCb = cb;
}

const wchar_t* EnforcementManager::ConfigRetToString(CONFIGRET cr)
{
    switch (cr)
    {
    case CR_SUCCESS:          return L"CR_SUCCESS (0: Devnode operation succeeded)";
    case CR_ACCESS_DENIED:    return L"CR_ACCESS_DENIED (51: Elevation/Administrator privileges required)";
    case CR_NOT_DISABLEABLE:  return L"CR_NOT_DISABLEABLE (40: Protected by Windows PnP; device cannot be disabled at OS level)";
    case CR_REMOVE_VETOED:    return L"CR_REMOVE_VETOED (35: Removal vetoed by driver/storage handle)";
    case CR_NO_SUCH_DEVINST:  return L"CR_NO_SUCH_DEVINST (13: DevNode not found)";
    default:                  return L"CONFIGRET_ERROR";
    }
}


bool EnforcementManager::LocateDeviceNode(
    const USBDevice& device,
    DEVINST& devInst,
    CONFIGRET* outResult)
{
    if (s_mockEnforcement)
    {
        if (outResult) *outResult = s_mockCode;
        devInst = 1;
        return s_mockSuccess;
    }

    if (outResult) *outResult = CR_FAILURE;

    if (device.deviceId.empty())
    {
        std::wcerr
            << L"[ENFORCEMENT ERROR] Device ID is empty.\n";

        return false;
    }

    // Safety check: Never disable a Root Hub or system USB host controller
    std::wstring devIdUpper = device.deviceId;
    for (auto& c : devIdUpper) c = towupper(c);
    if (devIdUpper.find(L"ROOT_HUB") != std::wstring::npos || devIdUpper.find(L"ROOTHUB") != std::wstring::npos)
    {
        std::wcerr << L"[ENFORCEMENT SAFETY] Refusing to locate/disable Root Hub node: " << device.deviceId << L"\n";
        if (outResult) *outResult = CR_NOT_DISABLEABLE;
        return false;
    }

    devInst = 0;

    CONFIGRET result =
        CM_Locate_DevNodeW(
            &devInst,
            const_cast<DEVINSTID_W>(
                device.deviceId.c_str()
            ),
            CM_LOCATE_DEVNODE_NORMAL
        );

    if (outResult) *outResult = result;

    if (result != CR_SUCCESS)
    {
        std::wcerr
            << L"[ENFORCEMENT ERROR] "
            << L"Could not locate device node.\n";

        std::wcerr
            << L"Device ID : "
            << device.deviceId
            << L"\n";

        std::wcerr
            << L"CONFIGRET : "
            << result
            << L" (" << ConfigRetToString(result) << L")\n";

        return false;
    }

    return true;
}

bool EnforcementManager::VerifyDeviceDisabled(const USBDevice& device)
{
    if (s_mockEnforcement)
    {
        return s_mockSuccess && (s_mockCode == CR_SUCCESS);
    }

    DEVINST devInst = 0;
    if (!LocateDeviceNode(device, devInst))
    {
        return false;
    }

    ULONG status = 0, problem = 0;
    if (CM_Get_DevNode_Status(&status, &problem, devInst, 0) == CR_SUCCESS)
    {
        return (problem == CM_PROB_DISABLED);
    }
    return false;
}

bool EnforcementManager::VerifyDeviceEnabled(const USBDevice& device)
{
    if (s_mockEnforcement)
    {
        return s_mockSuccess && (s_mockCode == CR_SUCCESS);
    }

    DEVINST devInst = 0;
    if (!LocateDeviceNode(device, devInst))
    {
        return false;
    }

    ULONG status = 0, problem = 0;
    if (CM_Get_DevNode_Status(&status, &problem, devInst, 0) == CR_SUCCESS)
    {
        return (problem == 0 && (status & DN_STARTED));
    }
    return false;
}

ThreatEnforcementResult EnforcementManager::EnforceCriticalThreat(
    const USBDevice& device,
    const std::wstring& threatType,
    const std::wstring& threatEvidence,
    int riskScore,
    const std::vector<std::wstring>& reasons,
    AllowlistManager* allowlist,
    DWORD offendingPid)
{
    ThreatEnforcementResult res;
    res.quarantineAttempted = true;

    std::wcout << L"\n=======================================================\n";
    std::wcout << L"[CENTRAL ENFORCEMENT] Confirmed Critical Threat Detected!\n";
    std::wcout << L"[CENTRAL ENFORCEMENT] Threat Type : " << threatType << L"\n";
    std::wcout << L"[CENTRAL ENFORCEMENT] Device      : " << device.vendorId << L":" << device.productId
               << L" (Serial: " << device.serialNumber << L")\n";
    std::wcout << L"[CENTRAL ENFORCEMENT] Evidence    : " << threatEvidence << L"\n";
    std::wcout << L"[CENTRAL ENFORCEMENT] Risk Score  : " << riskScore << L"/100 (CRITICAL)\n";
    std::wcout << L"=======================================================\n";

    // 1. Offending Process Termination
    if (offendingPid != 0 && offendingPid != GetCurrentProcessId())
    {
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, offendingPid);
        if (hProc != NULL)
        {
            if (TerminateProcess(hProc, 1))
            {
                res.processTerminated = true;
                std::wcout << L"[CENTRAL ENFORCEMENT] Terminated offending process PID: " << offendingPid << L"\n";
            }
            CloseHandle(hProc);
        }
    }

    // 2. Hardware Disablement via Windows PnP (CM_Disable_DevNode)
    if (s_suppressionCb && !device.deviceInterfacePath.empty())
    {
        s_suppressionCb(device.deviceInterfacePath);
    }

    CONFIGRET crResult = CR_FAILURE;
    bool disabled = QuarantineDevice(device, &crResult);
    res.configRet = crResult;
    res.quarantineApplied = disabled;

    // 3. Verify actual Windows device state
    bool verified = false;
    if (s_mockEnforcement)
    {
        verified = s_mockSuccess && (crResult == CR_SUCCESS);
    }
    else if (disabled && crResult == CR_SUCCESS)
    {
        verified = VerifyDeviceDisabled(device);
    }
    res.verificationSuccess = verified;

    if (disabled && verified)
    {
        res.finalEnforcementState = L"QUARANTINED_VERIFIED_CODE_22";
        std::wcout << L"[CENTRAL ENFORCEMENT] DevNode disablement verified: Code 22 (CM_PROB_DISABLED) [OK]\n";
    }
    else if (disabled && !verified)
    {
        res.finalEnforcementState = L"QUARANTINED_UNVERIFIED";
        std::wcout << L"[CENTRAL ENFORCEMENT] DevNode disablement returned CR_SUCCESS; verification pending.\n";
    }
    else
    {
        res.finalEnforcementState = L"ENFORCEMENT_FAILED (" + std::wstring(ConfigRetToString(crResult)) + L")";
        res.failureReason = ConfigRetToString(crResult);
        std::wcerr << L"[CENTRAL ENFORCEMENT FAILURE] Windows refused device disablement: "
                   << ConfigRetToString(crResult) << L"\n";
        std::wcerr << L"[SECURITY NOTICE] Device locked in local zero-trust restricted state.\n";
    }

    // 4. Update tracking state in DevicePresenceMonitor
    DevicePresenceMonitor::SetDeviceState(device.deviceId, DeviceTrackingState::QUARANTINED);

    // 5. Revoke local authorization & record critical threat in AllowlistManager
    if (allowlist)
    {
        allowlist->RemoveDevice(device);
        allowlist->RecordCriticalThreat(device, threatType, threatEvidence, riskScore);
        res.allowlistRevoked = true;
        std::wcout << L"[CENTRAL ENFORCEMENT] Local allowlist revoked and threat recorded.\n";
    }

    // 6. Report Revocation & Policy Violation Incident to Central Server
    PolicyViolationIncident inc;
    inc.clientId = EventLogger::Instance().GetClientId();
    inc.vendorId = device.vendorId;
    inc.productId = device.productId;
    inc.serialNumber = device.serialNumber;
    inc.deviceId = device.deviceId;
    inc.deviceType = DeviceClassifier::ToString(device.type);
    inc.description = device.description;
    inc.folderPath = L"REMOVABLE_STORAGE";
    inc.operation = threatType;
    inc.attributionTier = L"DEFINITIVE";
    inc.attributionEvidence = threatEvidence;
    inc.enforcementApplied = disabled;
    inc.enforcementVerified = verified;
    inc.enforcementCode = ConfigRetToString(crResult);

    RestClient::Instance().ReportPolicyViolation(inc);
    res.incidentReported = true;

    // 7. Local Security Event Log
    std::wstring logReason = L"Confirmed critical threat [" + threatType + L"]: " + threatEvidence +
                             L" | Risk: " + std::to_wstring(riskScore) + L"/100" +
                             L" | Enforcement: " + res.finalEnforcementState;
    EventLogger::Instance().LogEvent(
        SecurityEventType::DEVICE_BLOCKED,
        device,
        L"BLOCK",
        logReason
    );

    std::wcout << L"=======================================================\n\n";
    return res;
}


bool EnforcementManager::QuarantineDevice(
    const USBDevice& device,
    CONFIGRET* outResult)
{
    if (s_suppressionCb)
    {
        if (!device.deviceInterfacePath.empty()) s_suppressionCb(device.deviceInterfacePath);
        if (!device.deviceId.empty()) s_suppressionCb(device.deviceId);
    }

    if (s_mockEnforcement)
    {
        if (outResult) *outResult = s_mockCode;
        std::wcout << L"[ENFORCEMENT MOCK] Quarantine simulated with code: " << ConfigRetToString(s_mockCode) << L"\n";
        return s_mockSuccess;
    }

    if (outResult) *outResult = CR_FAILURE;

    std::wcout
        << L"[ENFORCEMENT] Quarantining device...\n";

    // Windows may still be completing a previous
    // enable/disable transition. Retry a few times.
    const int maxAttempts = 5;

    for (int attempt = 1;
        attempt <= maxAttempts;
        ++attempt)
    {
        DEVINST devInst = 0;

        // Always locate the device node again.
        // Do not reuse an old DEVINST.
        if (!LocateDeviceNode(device, devInst, outResult))
        {
            std::wcerr
                << L"[ENFORCEMENT ERROR] "
                << L"Could not locate device node.\n";

            return false;
        }

        if (s_suppressionCb)
        {
            if (!device.deviceInterfacePath.empty()) s_suppressionCb(device.deviceInterfacePath);
            if (!device.deviceId.empty()) s_suppressionCb(device.deviceId);
        }

        CONFIGRET result =
            CM_Disable_DevNode(
                devInst,
                CM_DISABLE_UI_NOT_OK
            );

        if (outResult) *outResult = result;

        std::wcout << L"[ENFORCEMENT] CM_Disable_DevNode (Attempt " << attempt << L"/" << maxAttempts
                   << L") on '" << device.deviceId << L"' -> Result: "
                   << result << L" (" << ConfigRetToString(result) << L")\n";

        if (result == CR_SUCCESS)
        {
            std::wcout
                << L"[ENFORCEMENT] "
                << L"Device successfully quarantined at OS level (CM_Disable_DevNode: CR_SUCCESS).\n";

            return true;
        }

        if (result == CR_REMOVE_VETOED)
        {
            std::wcout
                << L"[ENFORCEMENT] "
                << L"Device disable was vetoed. "
                << L"Retrying ("
                << attempt
                << L"/"
                << maxAttempts
                << L")...\n";

            Sleep(300);

            continue;
        }

        // Any other error (e.g. CR_ACCESS_DENIED, CR_NOT_DISABLEABLE)
        // should not be treated as a temporary removal veto.
        std::wcerr
            << L"[ENFORCEMENT ERROR] "
            << L"Failed to quarantine device at OS level.\n";

        std::wcerr
            << L"CONFIGRET : "
            << result
            << L" (" << ConfigRetToString(result) << L")\n";

        return false;
    }

    std::wcerr
        << L"[ENFORCEMENT ERROR] "
        << L"Could not quarantine device after "
        << maxAttempts
        << L" attempts.\n";

    std::wcerr
        << L"CONFIGRET : "
        << CR_REMOVE_VETOED
        << L" (" << ConfigRetToString(CR_REMOVE_VETOED) << L")\n";

    if (outResult) *outResult = CR_REMOVE_VETOED;

    return false;
}


bool EnforcementManager::ReleaseDevice(
    const USBDevice& device,
    CONFIGRET* outResult)
{
    if (s_arrivalSuppressionCb)
    {
        if (!device.deviceInterfacePath.empty()) s_arrivalSuppressionCb(device.deviceInterfacePath);
        if (!device.deviceId.empty()) s_arrivalSuppressionCb(device.deviceId);
    }

    if (s_mockEnforcement)
    {
        if (outResult) *outResult = s_mockCode;
        std::wcout << L"[ENFORCEMENT MOCK] Release simulated with code: " << ConfigRetToString(s_mockCode) << L"\n";
        return s_mockSuccess;
    }

    if (outResult) *outResult = CR_FAILURE;
    DEVINST devInst = 0;

    if (!LocateDeviceNode(device, devInst, outResult))
    {
        return false;
    }

    std::wcout
        << L"[ENFORCEMENT] "
        << L"Releasing device from quarantine...\n";

    if (s_arrivalSuppressionCb)
    {
        if (!device.deviceInterfacePath.empty()) s_arrivalSuppressionCb(device.deviceInterfacePath);
        if (!device.deviceId.empty()) s_arrivalSuppressionCb(device.deviceId);
    }

    CONFIGRET result =
        CM_Enable_DevNode(
            devInst,
            0
        );

    if (outResult) *outResult = result;

    std::wcout << L"[ENFORCEMENT] CM_Enable_DevNode on '" << device.deviceId << L"' -> Result: "
               << result << L" (" << ConfigRetToString(result) << L")\n";

    if (result != CR_SUCCESS)
    {
        std::wcerr
            << L"[ENFORCEMENT ERROR] "
            << L"Failed to enable device at OS level.\n";

        std::wcerr
            << L"CONFIGRET : "
            << result
            << L" (" << ConfigRetToString(result) << L")\n";

        return false;
    }

    std::wcout
        << L"[ENFORCEMENT] "
        << L"Device successfully enabled at OS level (CM_Enable_DevNode: CR_SUCCESS).\n";

    return true;
}