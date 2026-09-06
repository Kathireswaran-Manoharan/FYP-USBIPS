#include "RestClient.h"
#include "../Classifier/DeviceClassifier.h"
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
    const USBDevice& device)
{
    DeviceCheckResult result;

    try
    {
        nlohmann::json payload;
        payload["client_id"] = WideToUtf8(clientId);
        payload["vendor_id"] = WideToUtf8(device.vendorId);
        payload["product_id"] = WideToUtf8(device.productId);
        payload["serial_number"] = WideToUtf8(device.serialNumber);
        payload["device_type"] = WideToUtf8(DeviceClassifier::ToString(device.type));
        payload["description"] = WideToUtf8(device.description);
        payload["device_path"] = WideToUtf8(device.deviceInterfacePath);

        int statusCode = 0;
        std::string response;
        bool ok = SendHttpRequest(L"POST", L"/api/devices/check-or-request", payload.dump(), statusCode, response);

        result.httpStatusCode = statusCode;
        if (ok && statusCode == 200)
        {
            auto parsed = nlohmann::json::parse(response);
            result.success = true;
            result.decision = Utf8ToWide(parsed.value("decision", "BLOCK"));
            result.requestId = Utf8ToWide(parsed.value("request_id", ""));
            result.requestStatus = Utf8ToWide(parsed.value("request_status", ""));
            result.message = Utf8ToWide(parsed.value("message", ""));
        }
        else
        {
            result.success = false;
            result.decision = L"BLOCK";
            result.message = L"Server unreachable or returned HTTP error";
        }
    }
    catch (...)
    {
        result.success = false;
        result.decision = L"BLOCK";
        result.message = L"JSON parse error or internal exception";
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
            result.requestId = requestId;
            std::string statusStr = parsed.value("status", "PENDING");
            result.requestStatus = Utf8ToWide(statusStr);

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
            std::string status = item.value("status", "APPROVED");
            if (status != "APPROVED")
            {
                continue;
            }

            AllowedDevice dev;
            dev.id = item.value("id", 0);
            dev.vendorId = Utf8ToWide(item.value("vendor_id", ""));
            dev.productId = Utf8ToWide(item.value("product_id", ""));
            dev.serialNumber = Utf8ToWide(item.value("serial_number", ""));
            dev.deviceType = Utf8ToWide(item.value("device_type", "OTHER"));
            dev.description = Utf8ToWide(item.value("description", ""));
            dev.manufacturer = Utf8ToWide(item.value("manufacturer", ""));

            outDevices.push_back(dev);
        }

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
            outIngestedCount = parsed.value("ingested_count", 0);
            return true;
        }

        return false;
    }
    catch (...)
    {
        return false;
    }
}
