#pragma once

#include "../Models/USBDevice.h"
#include <string>
#include <vector>
#include <chrono>
#include <mutex>

struct DeviceConnectionEvent
{
    std::chrono::steady_clock::time_point timestamp;
    std::wstring vendorId;
    std::wstring productId;
    std::wstring serialNumber;
    std::wstring deviceInterfacePath;
};

struct EvasionAnalysisResult
{
    bool isEvasionDetected = false;
    int evasionRiskScore = 0;       // 0 - 100
    int reconnectCountInWindow = 0;
    bool hasIdentityMutation = false;
    std::wstring primaryReason;
};

class ReconnectionEvasionAnalyzer
{
public:
    static ReconnectionEvasionAnalyzer& Instance()
    {
        static ReconnectionEvasionAnalyzer instance;
        return instance;
    }

    // Records a device connection and analyzes reconnection/flapping patterns
    EvasionAnalysisResult AnalyzeArrival(const USBDevice& device, bool recordArrival = true);

    // Returns the latest computed analysis result without modifying connection history
    EvasionAnalysisResult GetLatestResult() const;

    // Clears history (used for test teardown)
    void Reset();

    // Algorithm 7 verification self-test
    bool VerifySelfTest();

private:
    ReconnectionEvasionAnalyzer() = default;

    mutable std::mutex m_mutex;
    std::vector<DeviceConnectionEvent> m_history;
    EvasionAnalysisResult m_latestResult;
};
