#include "RestClient.h"
#include "../Classifier/DeviceClassifier.h"
#include "../AccessControl/PolicyConfig.h"
#include "../AccessControl/TrustAssessmentEngine.h"
#include "../AccessControl/HIDBehaviorMonitor.h"
#include "../AccessControl/ProtectedFolderPolicy.h"
#include "../ThirdParty/nlohmann/json.hpp"

#include <winhttp.h>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

RestClient& RestClient::Instance()
{
    static RestClient instance;
    return instance;
}

RestClient::RestClient()
    : m_serverHost(L"127.0.0.1")
    , m_serverPort(8000)
    , m_useHttps(false)
{
}

RestClient::~RestClient()
{
}

void RestClient::Configure(const std::wstring& serverHost, int serverPort, bool useHttps)
{
    m_serverHost = serverHost;
    m_serverPort = serverPort;
    m_useHttps = useHttps;
}

std::wstring RestClient::GetServerHost() const
{
    return m_serverHost;
}

int RestClient::GetServerPort() const
{
    return m_serverPort;
}

std::string RestClient::WideToUtf8(const std::wstring& wstr)
{
    if (wstr.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.length()), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string str(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.length()), &str[0], len, nullptr, nullptr);
    return str;
}

std::wstring RestClient::Utf8ToWide(const std::string& str)
{
    if (str.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), nullptr, 0);
    if (len <= 0) return L"";
    std::wstring wstr(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), &wstr[0], len);
    return wstr;
}

bool RestClient::SendHttpRequest(
    const std::wstring& verb,
    const std::wstring& path,
    const std::string& requestBodyJson,
    int& outStatusCode,
    std::string& outResponseBody)
{
    outStatusCode = 0;
    outResponseBody.clear();

    HINTERNET hSession = WinHttpOpen(
        L"USBIPS-Client/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession)
    {
        return false;
    }

    // Set 3 second timeouts for responsiveness
    WinHttpSetTimeouts(hSession, 3000, 3000, 3000, 3000);

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        m_serverHost.c_str(),
        static_cast<INTERNET_PORT>(m_serverPort),
        0
    );
    if (!hConnect)
    {
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD dwFlags = m_useHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        verb.c_str(),
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        dwFlags
    );
    if (!hRequest)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    LPCWSTR headers = L"Content-Type: application/json; charset=utf-8\r\nAccept: application/json\r\n";
    DWORD headersLength = static_cast<DWORD>(wcslen(headers));

    LPVOID pData = requestBodyJson.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(requestBodyJson.c_str());
    DWORD dataLength = static_cast<DWORD>(requestBodyJson.size());

    BOOL bResults = WinHttpSendRequest(
        hRequest,
        headers,
        headersLength,
        pData,
        dataLength,
        dataLength,
        0
    );

    if (bResults)
    {
        bResults = WinHttpReceiveResponse(hRequest, nullptr);
        if (!bResults)
        {
            DWORD err = GetLastError();
            std::wcerr << L"[REST-CLIENT] WinHttpReceiveResponse failed for " << verb << L" " << path
                       << L" (LastError: " << err << L")\n";
        }
    }
    else
    {
        DWORD err = GetLastError();
        std::wcerr << L"[REST-CLIENT] WinHttpSendRequest failed for " << verb << L" " << path
                   << L" (LastError: " << err << L")\n";
    }

    if (bResults)
    {
        DWORD dwStatusCode = 0;
        DWORD dwSize = sizeof(dwStatusCode);
        WinHttpQueryHeaders(
            hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &dwStatusCode,
            &dwSize,
            WINHTTP_NO_HEADER_INDEX
        );
        outStatusCode = static_cast<int>(dwStatusCode);

        DWORD dwDownloaded = 0;
        char buffer[4096];
        do
        {
            dwDownloaded = 0;
            if (WinHttpReadData(hRequest, buffer, sizeof(buffer), &dwDownloaded))
            {
                if (dwDownloaded > 0)
                {
                    outResponseBody.append(buffer, dwDownloaded);
                }
            }
            else
            {
                break;
            }
        } while (dwDownloaded > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return (bResults && outStatusCode > 0);
}

bool RestClient::IsServerOnline()
{
    int statusCode = 0;
    std::string response;
    bool ok = SendHttpRequest(L"GET", L"/api/stats", "", statusCode, response);
    return (ok && statusCode == 200);
}

bool RestClient::RegisterClient(
    const std::wstring& clientId,
    const std::wstring& hostname,
    const std::wstring& ipAddress,
    const std::wstring& osVersion,
    const std::wstring& agentVersion)
{
    try
    {
        nlohmann::json payload;
        payload["client_id"] = WideToUtf8(clientId);
        payload["hostname"] = WideToUtf8(hostname);
        payload["ip_address"] = WideToUtf8(ipAddress);
        payload["os_version"] = WideToUtf8(osVersion);
        payload["agent_version"] = WideToUtf8(agentVersion);

        int statusCode = 0;
        std::string response;
        bool ok = SendHttpRequest(L"POST", L"/api/clients/register", payload.dump(), statusCode, response);
        return (ok && statusCode == 200);
    }
    catch (...)
    {
        return false;
    }
}

bool RestClient::SendHeartbeat(
    const std::wstring& clientId,
    const std::wstring& status)
{
    try
    {
        nlohmann::json payload;
        payload["client_id"] = WideToUtf8(clientId);
        payload["status"] = WideToUtf8(status);

        int statusCode = 0;
        std::string response;
        bool ok = SendHttpRequest(L"POST", L"/api/clients/heartbeat", payload.dump(), statusCode, response);
        return (ok && statusCode == 200);
    }
    catch (...)
    {
        return false;
    }
}

DeviceCheckResult RestClient::CheckOrRequestDevice(
    const std::wstring& clientId,
    const USBDevice& device,
    const TrustAssessmentReport* pReport,
    const HIDVerificationResult* pHidVerification)
{
    DeviceCheckResult result;

    try
    {
        nlohmann::json payload;
        payload["client_id"] = WideToUtf8(clientId);
        payload["vendor_id"] = WideToUtf8(device.vendorId);
        payload["product_id"] = WideToUtf8(device.productId);
        payload["serial_number"] = WideToUtf8(device.serialNumber);
        payload["device_type"] = WideToUtf8(DeviceClassifier::GetSpecificTypeString(device));
        payload["description"] = WideToUtf8(device.description);
        payload["device_path"] = WideToUtf8(device.deviceInterfacePath);

        const HIDVerificationResult* pHid = pHidVerification;
        if (!pHid && pReport)
        {
            pHid = &pReport->hidVerification;
        }

        if (pHid)
        {
            payload["session_id"] = WideToUtf8(pHid->sessionId);
            payload["captcha_challenge_id"] = WideToUtf8(pHid->challengeId);
            payload["captcha_result"] = WideToUtf8(pHid->outcome);
            payload["verification_method"] = WideToUtf8(pHid->method);
            payload["verification_start"] = WideToUtf8(pHid->startTimestamp);
            payload["verification_completed"] = WideToUtf8(pHid->completedTimestamp);
            payload["attempt_count"] = pHid->attemptCount;
            payload["verification_score"] = pHid->verificationScore;
            payload["verification_duration_seconds"] = pHid->verificationDurationSeconds;
            payload["temp_release_applied"] = pHid->tempReleaseApplied;
            payload["temp_release_duration_seconds"] = pHid->tempReleaseDurationSeconds;
            payload["re_quarantine_result"] = WideToUtf8(pHid->reQuarantineResult);
            payload["current_enforcement_state"] = WideToUtf8(pHid->currentEnforcementState);
        }

        if (pReport)
        {
            if (!payload.contains("session_id") || payload["session_id"] == "")
            {
                payload["session_id"] = WideToUtf8(pReport->sessionId);
            }
            payload["total_risk_score"] = pReport->totalRiskScore;
            payload["severity"] = WideToUtf8(RiskSeverityToString(pReport->severity));
            payload["recommendation"] = WideToUtf8(TrustRecommendationToString(pReport->recommendation));
            payload["assessment_summary"] = WideToUtf8(pReport->summary);
            payload["algorithms_json"] = WideToUtf8(TrustAssessmentEngine::Instance().SerializeAlgorithmsJson(*pReport));
            if (!payload.contains("current_enforcement_state") || payload["current_enforcement_state"] == "")
            {
                payload["current_enforcement_state"] = WideToUtf8(pReport->actualWindowsEnforcement);
            }
        }

        int statusCode = 0;
        std::string response;
        bool ok = SendHttpRequest(L"POST", L"/api/devices/check-or-request", payload.dump(), statusCode, response);

        result.httpStatusCode = statusCode;
        if (ok && statusCode == 200)
        {
            auto parsed = nlohmann::json::parse(response);
            result.success = true;
            result.decision = L"BLOCK";
            if (parsed.contains("decision") && !parsed["decision"].is_null())
            {
                result.decision = Utf8ToWide(parsed["decision"].get<std::string>());
            }
            if (parsed.contains("request_id") && !parsed["request_id"].is_null())
            {
                result.requestId = Utf8ToWide(parsed["request_id"].get<std::string>());
            }
            if (parsed.contains("request_status") && !parsed["request_status"].is_null())
            {
                result.requestStatus = Utf8ToWide(parsed["request_status"].get<std::string>());
            }
            if (parsed.contains("message") && !parsed["message"].is_null())
            {
                result.message = Utf8ToWide(parsed["message"].get<std::string>());
            }
            if (parsed.contains("duration_minutes") && !parsed["duration_minutes"].is_null())
            {
                result.durationMinutes = parsed["duration_minutes"].get<int>();
            }
            if (parsed.contains("expires_at") && !parsed["expires_at"].is_null())
            {
                result.expiresAt = Utf8ToWide(parsed["expires_at"].get<std::string>());
            }
            std::wcout << L"[SERVER-AUTH] POST /api/devices/check-or-request -> HTTP " << statusCode
                       << L" Decision=" << result.decision << L" Status=" << result.requestStatus
                       << L" RequestID=" << result.requestId << L" (" << result.message << L")\n";
        }
        else
        {
            result.success = false;
            result.decision = L"BLOCK";
            result.message = (statusCode > 0)
                ? (L"Server returned HTTP " + std::to_wstring(statusCode) + (response.empty() ? L"" : (L": " + Utf8ToWide(response))))
                : L"Server unreachable (connection failed)";
            std::wcerr << L"[SERVER-AUTH ERROR] POST /api/devices/check-or-request -> HTTP " << statusCode
                       << L" (" << result.message << L")\n";
        }
    }
    catch (const std::exception& ex)
    {
        result.success = false;
        result.decision = L"BLOCK";
        result.message = L"JSON parse error or internal exception: " + Utf8ToWide(ex.what());
        std::wcerr << L"[SERVER-AUTH EXCEPTION] CheckOrRequestDevice: " << result.message << L"\n";
    }
    catch (...)
    {
        result.success = false;
        result.decision = L"BLOCK";
        result.message = L"Unknown exception occurred during server authorization request";
        std::wcerr << L"[SERVER-AUTH EXCEPTION] CheckOrRequestDevice: " << result.message << L"\n";
    }

    return result;
}

DeviceCheckResult RestClient::PollRequestStatus(
    const std::wstring& requestId)
{
    DeviceCheckResult result;

    if (requestId.empty())
    {
        return result;
    }

    try
    {
        std::wstring path = L"/api/requests/" + requestId;
        int statusCode = 0;
        std::string response;
        bool ok = SendHttpRequest(L"GET", path, "", statusCode, response);

        result.httpStatusCode = statusCode;
        if (ok && statusCode == 200)
        {
            auto parsed = nlohmann::json::parse(response);
            result.success = true;
            std::string statusStr = "PENDING";
            if (parsed.contains("status") && !parsed["status"].is_null())
            {
                statusStr = parsed["status"].get<std::string>();
            }
            result.requestStatus = Utf8ToWide(statusStr);

            if (parsed.contains("duration_minutes") && !parsed["duration_minutes"].is_null())
            {
                result.durationMinutes = parsed["duration_minutes"].get<int>();
            }
            if (parsed.contains("expires_at") && !parsed["expires_at"].is_null())
            {
                result.expiresAt = Utf8ToWide(parsed["expires_at"].get<std::string>());
            }

            if (statusStr == "APPROVED")
            {
                result.decision = L"ALLOW";
                result.message = L"Authorization approved by administrator";
            }
            else if (statusStr == "DECLINED")
            {
                result.decision = L"BLOCK";
                result.message = L"Authorization declined by administrator";
            }
            else if (statusStr == "REVOKED")
            {
                result.decision = L"BLOCK";
                result.message = L"Authorization revoked by administrator";
            }
            else
            {
                result.decision = L"ASK";
                result.message = L"Awaiting administrator decision in Central Management UI";
            }
        }
    }
    catch (...)
    {
        result.success = false;
    }

    return result;
}

bool RestClient::FetchMasterAllowlist(
    std::vector<AllowedDevice>& outDevices)
{
    try
    {
        int statusCode = 0;
        std::string response;
        bool ok = SendHttpRequest(L"GET", L"/api/devices", "", statusCode, response);

        if (!ok || statusCode != 200)
        {
            return false;
        }

        auto parsed = nlohmann::json::parse(response);
        if (!parsed.is_array())
        {
            return false;
        }

        outDevices.clear();
        for (const auto& item : parsed)
        {
            std::string status = "APPROVED";
            if (item.contains("status") && !item["status"].is_null())
            {
                status = item["status"].get<std::string>();
            }
            if (status != "APPROVED")
            {
                continue;
            }

            AllowedDevice dev;
            if (item.contains("id") && !item["id"].is_null())
            {
                dev.id = item["id"].get<int>();
            }
            if (item.contains("vendor_id") && !item["vendor_id"].is_null())
            {
                dev.vendorId = Utf8ToWide(item["vendor_id"].get<std::string>());
            }
            if (item.contains("product_id") && !item["product_id"].is_null())
            {
                dev.productId = Utf8ToWide(item["product_id"].get<std::string>());
            }
            if (item.contains("serial_number") && !item["serial_number"].is_null())
            {
                dev.serialNumber = Utf8ToWide(item["serial_number"].get<std::string>());
            }
            if (item.contains("device_type") && !item["device_type"].is_null())
            {
                dev.deviceType = Utf8ToWide(item["device_type"].get<std::string>());
            }
            if (item.contains("description") && !item["description"].is_null())
            {
                dev.description = Utf8ToWide(item["description"].get<std::string>());
            }
            if (item.contains("manufacturer") && !item["manufacturer"].is_null())
            {
                dev.manufacturer = Utf8ToWide(item["manufacturer"].get<std::string>());
            }
            if (item.contains("duration_minutes") && !item["duration_minutes"].is_null())
            {
                dev.durationMinutes = item["duration_minutes"].get<int>();
            }
            if (item.contains("expires_at") && !item["expires_at"].is_null())
            {
                dev.expiresAt = Utf8ToWide(item["expires_at"].get<std::string>());
            }
            if (item.contains("decision_reason") && !item["decision_reason"].is_null())
            {
                dev.decisionReason = Utf8ToWide(item["decision_reason"].get<std::string>());
            }

            outDevices.push_back(dev);
        }

        std::wcout << L"[REST] FetchMasterAllowlist: successfully synchronized " << outDevices.size() << L" approved peripheral(s).\n";
        return true;
    }
    catch (const std::exception& ex)
    {
        std::wcerr << L"[REST ERROR] FetchMasterAllowlist exception: " << Utf8ToWide(ex.what()) << L"\n";
        return false;
    }
    catch (...)
    {
        std::wcerr << L"[REST ERROR] FetchMasterAllowlist unknown exception\n";
        return false;
    }
}

bool RestClient::FetchPolicyConfig(PolicyConfig& outConfig)
{
    try
    {
        int statusCode = 0;
        std::string response;
        bool ok = SendHttpRequest(L"GET", L"/api/policies", "", statusCode, response);
        if (!ok || statusCode != 200)
        {
            return false;
        }

        auto parsed = nlohmann::json::parse(response);
        if (!parsed.is_object())
        {
            return false;
        }

        outConfig.strictAllowlistMatching = parsed.value("strict_allowlist_matching", outConfig.strictAllowlistMatching);
        outConfig.failClosedWhenServerOffline = parsed.value("fail_closed_when_server_offline", outConfig.failClosedWhenServerOffline);

        outConfig.requireCaptchaForHID = parsed.value("require_captcha_for_hid", outConfig.requireCaptchaForHID);
        outConfig.captchaTimeoutSeconds = parsed.value("captcha_timeout_seconds", outConfig.captchaTimeoutSeconds);
        outConfig.captchaMaxAttempts = parsed.value("captcha_max_attempts", outConfig.captchaMaxAttempts);
        outConfig.ikiBurstThresholdCPS = parsed.value("iki_burst_threshold_cps", outConfig.ikiBurstThresholdCPS);
        outConfig.ikiMinVarianceMs = parsed.value("iki_min_variance_ms", outConfig.ikiMinVarianceMs);
        outConfig.hidSurveillanceWindowSeconds = parsed.value("hid_surveillance_window_seconds", outConfig.hidSurveillanceWindowSeconds);

        outConfig.blockUnauthorizedComposite = parsed.value("block_unauthorized_composite", outConfig.blockUnauthorizedComposite);
        outConfig.allowCompositeMouseKeyboard = parsed.value("allow_composite_mouse_keyboard", outConfig.allowCompositeMouseKeyboard);

        if (parsed.contains("protected_directory") && parsed["protected_directory"].is_string())
        {
            outConfig.protectedDirectory = Utf8ToWide(parsed["protected_directory"].get<std::string>());
        }
        if (parsed.contains("canary_file_name") && parsed["canary_file_name"].is_string())
        {
            outConfig.canaryFileName = Utf8ToWide(parsed["canary_file_name"].get<std::string>());
        }

        outConfig.blockStorageExecution = parsed.value("block_storage_execution", outConfig.blockStorageExecution);
        outConfig.autoTerminateStorageProcesses = parsed.value("auto_terminate_storage_processes", outConfig.autoTerminateStorageProcesses);

        outConfig.blockUsbNetworkAdapters = parsed.value("block_usb_network_adapters", outConfig.blockUsbNetworkAdapters);
        outConfig.alertOnGatewayOverride = parsed.value("alert_on_gateway_override", outConfig.alertOnGatewayOverride);

        outConfig.maxReconnectsPerMinute = parsed.value("max_reconnects_per_minute", outConfig.maxReconnectsPerMinute);
        outConfig.flapWindowSeconds = parsed.value("flap_window_seconds", outConfig.flapWindowSeconds);
        outConfig.evasionRiskThreshold = parsed.value("evasion_risk_threshold", outConfig.evasionRiskThreshold);

        return true;
    }
    catch (...)
    {
        return false;
    }
}

bool RestClient::UploadEventsBatch(
    const std::vector<SecurityEvent>& events,
    int& outIngestedCount)
{
    outIngestedCount = 0;
    if (events.empty())
    {
        return true;
    }

    try
    {
        nlohmann::json root;
        nlohmann::json evtsArray = nlohmann::json::array();

        for (const auto& evt : events)
        {
            nlohmann::json obj;
            obj["event_id"] = WideToUtf8(evt.eventId);
            obj["client_id"] = WideToUtf8(evt.clientId);
            obj["timestamp"] = WideToUtf8(evt.timestamp);
            obj["event_type"] = WideToUtf8(SecurityEventTypeToString(evt.eventType));
            obj["vendor_id"] = WideToUtf8(evt.vendorId);
            obj["product_id"] = WideToUtf8(evt.productId);
            obj["serial_number"] = WideToUtf8(evt.serialNumber);
            obj["device_id"] = WideToUtf8(evt.deviceId);
            obj["device_type"] = WideToUtf8(evt.deviceType);
            obj["description"] = WideToUtf8(evt.description);
            obj["decision"] = WideToUtf8(evt.decision);
            obj["reason"] = WideToUtf8(evt.reason);

            evtsArray.push_back(obj);
        }

        root["events"] = evtsArray;

        int statusCode = 0;
        std::string response;
        bool ok = SendHttpRequest(L"POST", L"/api/events/batch", root.dump(), statusCode, response);

        if (ok && statusCode == 200)
        {
            auto parsed = nlohmann::json::parse(response);
            if (parsed.contains("inserted"))
            {
                outIngestedCount = parsed.value("inserted", 0);
            }
            else
            {
                outIngestedCount = parsed.value("ingested_count", 0);
            }
            return true;
        }

        return false;
    }
    catch (...)
    {
        return false;
    }
}

bool RestClient::FetchProtectedFolderPolicies(
    std::vector<ProtectedFolder>& outFolders)
{
    try
    {
        int statusCode = 0;
        std::string response;
        bool ok = SendHttpRequest(L"GET", L"/api/protected-folders?enabled_only=true", "", statusCode, response);

        if (!ok || statusCode != 200)
        {
            return false;
        }

        auto parsed = nlohmann::json::parse(response);
        if (!parsed.is_array())
        {
            return false;
        }

        outFolders.clear();
        for (const auto& item : parsed)
        {
            ProtectedFolder folder;
            if (item.contains("id") && !item["id"].is_null())
            {
                folder.id = item["id"].get<int>();
            }
            if (item.contains("folder_path") && !item["folder_path"].is_null())
            {
                folder.folderPath = Utf8ToWide(item["folder_path"].get<std::string>());
            }
            if (item.contains("description") && !item["description"].is_null())
            {
                folder.description = Utf8ToWide(item["description"].get<std::string>());
            }
            if (item.contains("is_enabled") && !item["is_enabled"].is_null())
            {
                folder.isEnabled = item["is_enabled"].get<bool>();
            }
            outFolders.push_back(folder);
        }

        return true;
    }
    catch (const std::exception& ex)
    {
        std::wcerr << L"[REST ERROR] FetchProtectedFolderPolicies: " << Utf8ToWide(ex.what()) << L"\n";
        return false;
    }
    catch (...)
    {
        return false;
    }
}

bool RestClient::ReportPolicyViolation(
    const PolicyViolationIncident& incident)
{
    try
    {
        nlohmann::json payload;
        payload["client_id"] = WideToUtf8(incident.clientId);
        payload["vendor_id"] = WideToUtf8(incident.vendorId);
        payload["product_id"] = WideToUtf8(incident.productId);
        payload["serial_number"] = WideToUtf8(incident.serialNumber);
        payload["device_id"] = WideToUtf8(incident.deviceId);
        payload["device_type"] = WideToUtf8(incident.deviceType);
        payload["description"] = WideToUtf8(incident.description);
        payload["folder_path"] = WideToUtf8(incident.folderPath);
        payload["operation"] = WideToUtf8(incident.operation);
        payload["attribution_tier"] = WideToUtf8(incident.attributionTier);
        payload["attribution_evidence"] = WideToUtf8(incident.attributionEvidence);
        payload["enforcement_applied"] = incident.enforcementApplied;
        payload["enforcement_verified"] = incident.enforcementVerified;
        payload["enforcement_code"] = WideToUtf8(incident.enforcementCode);

        int statusCode = 0;
        std::string response;
        bool ok = SendHttpRequest(L"POST", L"/api/incidents/policy-violation", payload.dump(), statusCode, response);

        return (ok && statusCode == 200);
    }
    catch (const std::exception& ex)
    {
        std::wcerr << L"[REST ERROR] ReportPolicyViolation: " << Utf8ToWide(ex.what()) << L"\n";
        return false;
    }
    catch (...)
    {
        return false;
    }
}

bool RestClient::RecoverDevice(
    const std::wstring& vid,
    const std::wstring& pid,
    const std::wstring& serial,
    const std::wstring& reason,
    bool forceOverride)
{
    try
    {
        nlohmann::json payload;
        payload["vendor_id"] = WideToUtf8(vid);
        payload["product_id"] = WideToUtf8(pid);
        payload["serial_number"] = WideToUtf8(serial);
        payload["admin_user"] = "Administrator";
        payload["reason"] = WideToUtf8(reason);
        payload["force_override"] = forceOverride;

        int statusCode = 0;
        std::string response;
        bool ok = SendHttpRequest(L"POST", L"/api/devices/recover", payload.dump(), statusCode, response);
        return (ok && statusCode == 200);
    }
    catch (const std::exception& ex)
    {
        std::wcerr << L"[REST ERROR] RecoverDevice: " << Utf8ToWide(ex.what()) << L"\n";
        return false;
    }
    catch (...)
    {
        return false;
    }
}

