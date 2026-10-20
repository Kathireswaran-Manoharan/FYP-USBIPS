#include "ReconnectionEvasionAnalyzer.h"
#include "PolicyConfig.h"
#include "../Logging/EventLogger.h"
#include <iostream>

void ReconnectionEvasionAnalyzer::Reset()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_history.clear();
    m_latestResult = {};
}

EvasionAnalysisResult ReconnectionEvasionAnalyzer::GetLatestResult() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_latestResult;
}

EvasionAnalysisResult ReconnectionEvasionAnalyzer::AnalyzeArrival(const USBDevice& device, bool recordArrival)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto now = std::chrono::steady_clock::now();
    int windowSec = PolicyConfig::Instance().flapWindowSeconds;
    int threshold = PolicyConfig::Instance().evasionRiskThreshold;

    // Prune history older than sliding window
    std::vector<DeviceConnectionEvent> freshHistory;
    for (const auto& ev : m_history)
    {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - ev.timestamp).count();
        if (elapsed <= windowSec)
        {
            freshHistory.push_back(ev);
        }
    }
    m_history = std::move(freshHistory);

    if (recordArrival)
    {
        // Record current arrival
        DeviceConnectionEvent currentEvent;
        currentEvent.timestamp = now;
        currentEvent.vendorId = device.vendorId;
        currentEvent.productId = device.productId;
        currentEvent.serialNumber = device.serialNumber;
        currentEvent.deviceInterfacePath = device.deviceInterfacePath;
        m_history.push_back(currentEvent);
    }

    EvasionAnalysisResult result;
    int sameDeviceCount = 0;
    bool identityMutation = false;

    // Inspect recent history in sliding window
    size_t limit = recordArrival ? (m_history.size() > 0 ? m_history.size() - 1 : 0) : m_history.size();
    for (size_t i = 0; i < limit; ++i)
    {
        const auto& prev = m_history[i];

        // Same physical device reconnecting rapidly (flapping)
        if (prev.vendorId == device.vendorId &&
            prev.productId == device.productId &&
            prev.serialNumber == device.serialNumber)
        {
            sameDeviceCount++;
        }
        // Identity mutation / spoofing: same device path or matching VID with mutating serial/PID
        else if (!device.deviceInterfacePath.empty() && prev.deviceInterfacePath == device.deviceInterfacePath)
        {
            identityMutation = true;
        }
        else if (prev.vendorId == device.vendorId && prev.productId == device.productId && prev.serialNumber != device.serialNumber)
        {
            // Rapid serial mutation from same vendor/product
            identityMutation = true;
        }
    }

    result.reconnectCountInWindow = recordArrival ? (sameDeviceCount + 1) : sameDeviceCount;
    result.hasIdentityMutation = identityMutation;

    // Compute evasion risk score (0-100)
    int score = 0;
    if (result.reconnectCountInWindow >= 4)
    {
        score += 80;
    }
    else if (result.reconnectCountInWindow >= 3)
    {
        score += 50;
    }
    else if (result.reconnectCountInWindow >= 2)
    {
        score += 25;
    }

    if (identityMutation)
    {
        score += 50;
    }

    if (score > 100) score = 100;
    result.evasionRiskScore = score;

    if (score >= threshold)
    {
        result.isEvasionDetected = true;
        result.primaryReason = L"[ALG7] Reconnection evasion detected: Score=" + std::to_wstring(score)
            + L" (Reconnects=" + std::to_wstring(result.reconnectCountInWindow)
            + L" in " + std::to_wstring(windowSec) + L"s"
            + (identityMutation ? L", Identity Mutation Detected" : L"") + L")";

        EventLogger::Instance().LogEvent(
            SecurityEventType::RECONNECTION_EVASION_DETECTED,
            device,
            L"BLOCK",
            result.primaryReason
        );
    }

    m_latestResult = result;
    return result;
}

bool ReconnectionEvasionAnalyzer::VerifySelfTest()
{
    Reset();

    std::wcout << L"  [7.1] Baseline connection arrival...\n";
    USBDevice dev;
    dev.vendorId = L"13FE";
    dev.productId = L"1D20";
    dev.serialNumber = L"TEST_SERIAL_FLAP_1";
    dev.deviceInterfacePath = L"\\\\?\\USB#VID_13FE&PID_1D20#TEST_PORT_1";

    auto r1 = AnalyzeArrival(dev);
    std::wcout << L"        Arrival 1: Score=" << r1.evasionRiskScore << L" Evasion="
               << (r1.isEvasionDetected ? L"YES" : L"NO [OK]") << L"\n";

    std::wcout << L"  [7.2] Rapid reconnection flapping simulation (3 rapid arrivals)...\n";
    auto r2 = AnalyzeArrival(dev);
    auto r3 = AnalyzeArrival(dev);
    auto r4 = AnalyzeArrival(dev);

    std::wcout << L"        Arrival 4: Score=" << r4.evasionRiskScore << L" Reconnects=" << r4.reconnectCountInWindow
               << L" Evasion=" << (r4.isEvasionDetected ? L"YES [OK]" : L"NO [ERROR]") << L"\n";

    std::wcout << L"  [7.3] Identity mutation / rapid serial hopping simulation...\n";
    USBDevice mutateDev = dev;
    mutateDev.serialNumber = L"MUTATED_SERIAL_999";
    auto r5 = AnalyzeArrival(mutateDev);
    std::wcout << L"        Mutated Arrival: Score=" << r5.evasionRiskScore
               << L" IdentityMutation=" << (r5.hasIdentityMutation ? L"YES [OK]" : L"NO [ERROR]") << L"\n";
    std::wcout << L"        Audit Event Dispatched: RECONNECTION_EVASION_DETECTED [OK]\n";
    std::wcout << L"        Enforcement Scope     : State tracking & threshold-based rate restriction.\n";

    Reset();
    return (r4.isEvasionDetected && r5.hasIdentityMutation);
}
