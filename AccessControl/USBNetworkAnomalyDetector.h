#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#include "../Models/USBDevice.h"
#include <string>
#include <vector>

struct NetworkAnomalyReport
{
    std::wstring adapterName;
    std::wstring adapterDescription;
    bool isUsbNetwork = false;
    bool hasRogueGateway = false;
    bool hasRogueDns = false;
    std::wstring gatewayAddress;
    std::wstring dnsAddress;
    std::wstring reason;
    bool isAnomaly = false;
};

class USBNetworkAnomalyDetector
{
public:
    static USBNetworkAnomalyDetector& Instance()
    {
        static USBNetworkAnomalyDetector instance;
        return instance;
    }

    // Inspects system network adapters for USB-based interfaces and routing/DNS anomalies
    std::vector<NetworkAnomalyReport> InspectAdapters();

    // Evaluates a candidate USB device against network anomaly rules
    bool EvaluateDevice(const USBDevice& device, NetworkAnomalyReport& outReport);

    // Algorithm 6 verification self-test
    bool VerifySelfTest();

private:
    USBNetworkAnomalyDetector() = default;
};
