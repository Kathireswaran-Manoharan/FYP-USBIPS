#pragma once

#include <string>
#include <vector>

struct PolicyConfig
{
    // Algorithm 1: Device Fingerprinting & Allowlist
    bool strictAllowlistMatching = true;
    bool failClosedWhenServerOffline = true;

    // Algorithm 2: BadUSB / HID Protection
    bool requireCaptchaForHID = true;
    int captchaTimeoutSeconds = 30;
    int captchaMaxAttempts = 3;
    int ikiBurstThresholdCPS = 30;       // Keystrokes per second injection threshold
    double ikiMinVarianceMs = 2.0;       // Subhuman variance threshold (ms)
    int hidSurveillanceWindowSeconds = 15;

    // Algorithm 3: Composite Policy
    bool blockUnauthorizedComposite = true;
    bool allowCompositeMouseKeyboard = true;

    // Algorithm 4: Protected-File & Multi-Folder Policy Access Restrictions
    std::wstring protectedDirectory = L"C:\\USBIPS_Protected";
    std::wstring canaryFileName = L"confidential_canary.txt";
    bool enforceFolderProtectionOnUsb = true;
    bool deactivateProtectionOnUsbRemoval = true;

    // Algorithm 5: Removable Storage Execution Restrictions
    bool blockStorageExecution = true;
    bool autoTerminateStorageProcesses = true;

    // Algorithm 6: USB Network & DNS Anomaly Detection
    bool blockUsbNetworkAdapters = true;
    bool alertOnGatewayOverride = true;

    // Algorithm 7: Reconnection & Policy Evasion
    int maxReconnectsPerMinute = 3;
    int flapWindowSeconds = 15;
    int evasionRiskThreshold = 70;

    // Module A3: HID-Process Correlation
    int hidProcessCorrelationWindowSeconds = 15;

    // Module A4: Removable Media Malware Scanning
    bool enableAntivirusScanning = true;
    bool requireCleanScanForMount = true;

    // Module A5: Suspicious File & Script Detection
    bool enableSuspiciousFileScan = true;

    // Module A8: Data Exfiltration & Copy Surveillance
    bool enableExfiltrationMonitoring = true;
    int exfiltrationMaxFileTouches = 10;
    int exfiltrationWindowSeconds = 30;

    // Module A12: Trust Assessment Engine
    int trustThresholdScore = 30; // Maximum risk score (0-100) for review recommendation
    bool requireCleanScanForApproval = true;

    static PolicyConfig& Instance()
    {
        static PolicyConfig instance;
        return instance;
    }
};
