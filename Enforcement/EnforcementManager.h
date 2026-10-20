#pragma once

#include <windows.h>
#include <cfgmgr32.h>

#include <string>
#include <vector>

#include "../Models/USBDevice.h"

class AllowlistManager;

struct ThreatEnforcementResult
{
    bool quarantineAttempted = false;
    bool quarantineApplied = false;
    bool verificationSuccess = false;
    CONFIGRET configRet = CR_FAILURE;
    bool processTerminated = false;
    bool allowlistRevoked = false;
    bool incidentReported = false;
    std::wstring finalEnforcementState;
    std::wstring failureReason;
};

class EnforcementManager
{
public:

    static bool QuarantineDevice(
        const USBDevice& device,
        CONFIGRET* outResult = nullptr
    );

    static bool ReleaseDevice(
        const USBDevice& device,
        CONFIGRET* outResult = nullptr
    );

    static const wchar_t* ConfigRetToString(
        CONFIGRET cr
    );

    // State verification via CM_Get_DevNode_Status
    static bool VerifyDeviceDisabled(const USBDevice& device);
    static bool VerifyDeviceEnabled(const USBDevice& device);

    // Central Unified Enforcement Path (Requirement 3)
    static ThreatEnforcementResult EnforceCriticalThreat(
        const USBDevice& device,
        const std::wstring& threatType,
        const std::wstring& threatEvidence,
        int riskScore,
        const std::vector<std::wstring>& reasons,
        AllowlistManager* allowlist,
        DWORD offendingPid = 0
    );

    // Automated Testing & Mocked Enforcement (Requirement 7)
    static void SetMockEnforcement(
        bool enable,
        bool simulateSuccess = true,
        CONFIGRET simulatedCode = CR_SUCCESS
    );
    static bool IsMockEnforcement();

    // Notification suppression hook to avoid duplicate loops (Requirement 5)
    typedef void (*NotificationSuppressionCallback)(const std::wstring& devicePath);
    static void SetNotificationSuppressionCallback(NotificationSuppressionCallback cb);
    static void SetArrivalSuppressionCallback(NotificationSuppressionCallback cb);

private:

    static bool LocateDeviceNode(
        const USBDevice& device,
        DEVINST& devInst,
        CONFIGRET* outResult = nullptr
    );
};