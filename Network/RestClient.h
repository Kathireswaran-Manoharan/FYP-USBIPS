#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include <memory>

#include "../Models/USBDevice.h"
#include "../Models/SecurityEvent.h"
#include "../Allowlist/AllowlistManager.h"

struct TrustAssessmentReport;
struct HIDVerificationResult;

struct DeviceCheckResult
{
    bool success = false;
    int httpStatusCode = 0;
    std::wstring decision;      // "ALLOW", "ASK", "BLOCK"
    std::wstring requestId;     // Server UUID
    std::wstring requestStatus; // "PENDING", "APPROVED", "DECLINED"
    std::wstring message;
    int durationMinutes = 0;
    std::wstring expiresAt;
};

class RestClient
{
public:
    static RestClient& Instance();

    void Configure(
        const std::wstring& serverHost = L"127.0.0.1",
        int serverPort = 8000,
        bool useHttps = false
    );

    std::wstring GetServerHost() const;
    int GetServerPort() const;

    bool IsServerOnline();

    bool RegisterClient(
        const std::wstring& clientId,
        const std::wstring& hostname,
        const std::wstring& ipAddress,
        const std::wstring& osVersion,
        const std::wstring& agentVersion = L"1.0.0"
    );

    bool SendHeartbeat(
        const std::wstring& clientId,
        const std::wstring& status = L"ONLINE"
    );

    DeviceCheckResult CheckOrRequestDevice(
        const std::wstring& clientId,
        const USBDevice& device,
        const struct TrustAssessmentReport* pReport = nullptr,
        const struct HIDVerificationResult* pHidVerification = nullptr
    );

    DeviceCheckResult PollRequestStatus(
        const std::wstring& requestId
    );

    bool FetchMasterAllowlist(
        std::vector<AllowedDevice>& outDevices
    );

    bool FetchPolicyConfig(
        struct PolicyConfig& outConfig
    );

    bool UploadEventsBatch(
        const std::vector<SecurityEvent>& events,
        int& outIngestedCount
    );

    bool FetchProtectedFolderPolicies(
        std::vector<struct ProtectedFolder>& outFolders
    );

    bool ReportPolicyViolation(
        const struct PolicyViolationIncident& incident
    );

    bool RecoverDevice(
        const std::wstring& vid,
        const std::wstring& pid,
        const std::wstring& serial,
        const std::wstring& reason = L"Administrator cleared unverified scan error revocation",
        bool forceOverride = false
    );

    static std::string WideToUtf8(const std::wstring& wstr);
    static std::wstring Utf8ToWide(const std::string& str);

private:
    RestClient();
    ~RestClient();

    RestClient(const RestClient&) = delete;
    RestClient& operator=(const RestClient&) = delete;

    bool SendHttpRequest(
        const std::wstring& verb,
        const std::wstring& path,
        const std::string& requestBodyJson,
        int& outStatusCode,
        std::string& outResponseBody
    );

    std::wstring m_serverHost;
    int m_serverPort;
    bool m_useHttps;
};
