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
#include <atomic>

#include "../Models/USBDevice.h"
#include <unordered_set>
#include <unordered_map>

struct HIDTimingStats
{
    double currentRateCPS = 0.0;
    double intervalVarianceMs = 0.0;
    bool anomalyDetected = false;
    std::wstring details;
};

enum class CaptchaOutcome
{
    PASS,
    FAIL,
    TIMEOUT,
    REPLAY,
    CANCELLED
};

struct ChallengeMetadata
{
    std::wstring challengeId;
    std::wstring sessionId;
    std::string deviceId;
    std::chrono::steady_clock::time_point createdAt;
    std::chrono::steady_clock::time_point deadline;
    int attemptsRemaining = 3;
    int totalAttempts = 0;
    CaptchaOutcome finalOutcome = CaptchaOutcome::FAIL;
    bool isCompleted = false;
};

struct HIDVerificationResult
{
    std::wstring challengeId;
    std::wstring sessionId;
    std::wstring outcome = L"NOT_COMPLETED"; // "PASSED", "FAILED", "TIMEOUT", "EXPIRED", "REPLAY_ATTEMPT", "CANCELLED", "NOT_COMPLETED"
    std::wstring method = L"NONE";           // "KEYBOARD_TYPING", "MOUSE_CLICK", "NONE"
    std::wstring startTimestamp;
    std::wstring completedTimestamp;
    int attemptCount = 0;
    int verificationScore = 0;               // 100 for verified human interaction, 0 for failed/expired/timeout
    double verificationDurationSeconds = 0.0;
    bool tempReleaseApplied = false;
    double tempReleaseDurationSeconds = 0.0;
    std::wstring reQuarantineResult = L"QUARANTINED";
    std::wstring currentEnforcementState = L"QUARANTINED";
    std::wstring details;
};

class HIDBehaviorMonitor
{
public:
    static HIDBehaviorMonitor& Instance();

    // Required Lifecycle: DETECTED -> QUARANTINE -> CAPTCHA -> TEMP RELEASE -> RE-QUARANTINE
    HIDVerificationResult RunLifecycleVerification(const USBDevice& device, const std::wstring& sessionId);

    // Challenge Lifecycle & Replay Protection API
    std::wstring IssueNewChallenge(const USBDevice& device, const std::wstring& sessionId, int timeoutSeconds, int maxAttempts);
    CaptchaOutcome SubmitChallengeResponse(const std::wstring& challengeId, const std::wstring& enteredCode, const std::wstring& expectedCode);
    CaptchaOutcome ExpireChallengeOnTimeout(const std::wstring& challengeId);
    bool IsChallengeExpired(const std::wstring& challengeId) const;
    bool IsChallengeConsumed(const std::wstring& challengeId) const;

    // Keyboard & Mouse Specialized Challenges
    CaptchaOutcome PromptKeyboardCaptchaChallenge(const USBDevice& device, HIDVerificationResult& outResult);
    CaptchaOutcome PromptMouseCaptchaChallenge(const USBDevice& device, HIDVerificationResult& outResult);
    CaptchaOutcome EvaluateMouseChallengeResponse(const std::wstring& challengeId, const std::wstring& selectedChoice, const std::wstring& targetSymbol);

    // Physical Device Attribution & Input Isolation
    void SnapshotExistingInputDevices(const USBDevice* targetDeviceToExclude = nullptr);
    bool IsInputFromTargetDevice(HANDLE hDevice, const USBDevice& targetDevice) const;
    std::wstring GetRawInputDevicePath(HANDLE hDevice) const;
    void InvalidateDeviceSession(const std::wstring& devicePathOrId);

    // Attribution simulation controls for automated tests
    void SetSimulatedDeviceAttribution(bool enabled, bool isTargetDevice);
    bool IsSimulatedDeviceAttributionEnabled() const;
    bool GetSimulatedIsTargetDevice() const;

    // Legacy compatibility & simulation controls
    CaptchaOutcome PromptCaptchaChallengeWithDetails(const USBDevice& device);
    bool PromptCaptchaChallenge(const USBDevice& device);
    void SetSimulatedCaptchaResult(bool enabled, bool passResult);
    void SetSimulatedCaptchaOutcome(bool enabled, CaptchaOutcome outcome);

    void SetSimulatedVerificationResult(bool enabled, const HIDVerificationResult& result);
    void SetSimulatedReplayAttempt(bool enabled);
    void SetSimulatedReQuarantineFail(bool enabled, const std::wstring& errorReason);
    void SetSimulatedTempReleaseDuration(double seconds);
    HIDVerificationResult GetLatestVerificationResult() const;
    void ResetVerification();

    // Algorithm 2B: Keystroke Surveillance & Injection Detection
    bool StartSurveillance(const USBDevice& device);
    void StopSurveillance();
    bool IsSurveillanceActive() const;

    // Record incoming keystroke timing (called from hook or simulator)
    bool RecordKeyStroke(DWORD vkCode);

    // Safe simulation for test scenario 5
    bool SimulateSuspiciousBurst(const USBDevice& device);

    // Module A3: Connection-to-Process Correlation (BadUSB payload launching)
    void RecordDeviceConnection(const USBDevice& device);
    bool CorrelateProcessLaunch(const std::wstring& processName, DWORD pid, double& outElapsedSec);
    bool SimulateProcessCorrelation(const std::wstring& procName, double elapsedSec);
    bool HasSuspiciousProcessCorrelation() const;
    std::wstring GetProcessCorrelationDetails() const;
    void ResetProcessCorrelation();

    HIDTimingStats GetCurrentStats() const;

    // Priority 3: Input Guard during CAPTCHA Challenge
    void InstallCaptchaInputGuard(HWND hCaptchaWnd);
    void UninstallCaptchaInputGuard();
    bool IsCaptchaInputGuardActive() const;
    HWND GetActiveCaptchaWnd() const;

private:
    HIDBehaviorMonitor();
    ~HIDBehaviorMonitor();

    HIDBehaviorMonitor(const HIDBehaviorMonitor&) = delete;
    HIDBehaviorMonitor& operator=(const HIDBehaviorMonitor&) = delete;

    static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK CaptchaInputGuardHookProc(int nCode, WPARAM wParam, LPARAM lParam);

private:
    mutable std::recursive_mutex m_mutex;
    HHOOK m_hook;
    HHOOK m_captchaGuardHook = nullptr;
    HWND m_hActiveCaptchaWnd = nullptr;
    std::atomic<bool> m_captchaGuardActive{false};
    USBDevice m_activeDevice;
    std::atomic<bool> m_surveillanceActive;
    std::atomic<bool> m_anomalyTriggered;

    std::vector<std::chrono::steady_clock::time_point> m_keyTimestamps;
    std::vector<double> m_intervalsMs;

    bool m_simulatedCaptchaEnabled;
    bool m_simulatedCaptchaPass;
    CaptchaOutcome m_simulatedCaptchaOutcome;

    HIDTimingStats m_latestStats;

    // Process correlation state
    std::chrono::steady_clock::time_point m_connectionTime;
    bool m_hasConnectionTime = false;
    bool m_suspiciousProcessCorrelated = false;
    std::wstring m_correlatedProcessDetails;

    // CAPTCHA Lifecycle & Replay Cache
    bool m_simulatedVerificationEnabled = false;
    HIDVerificationResult m_simulatedVerificationResult;
    bool m_simulatedReplayAttempt = false;
    bool m_simulatedReQuarantineFail = false;
    std::wstring m_simulatedReQuarantineError;
    double m_simulatedTempReleaseDuration = 0.0;
    HIDVerificationResult m_latestVerificationResult;
    std::unordered_set<std::wstring> m_consumedChallengeIds;
    std::unordered_map<std::wstring, ChallengeMetadata> m_activeChallenges;
    std::unordered_set<std::wstring> m_existingInputDevicePaths;
    bool m_simulatedDeviceAttributionEnabled = false;
    bool m_simulatedIsTargetDevice = true;
};

