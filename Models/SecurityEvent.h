#pragma once

#include <string>

enum class SecurityEventType
{
    DEVICE_CONNECTED,
    DEVICE_QUARANTINED,
    DEVICE_RELEASED,
    DEVICE_REMOVED,
    ALLOWLIST_MATCH,
    UNKNOWN_DEVICE,
    USER_APPROVED,
    USER_REJECTED,
    DEVICE_BLOCKED
};

inline const wchar_t* SecurityEventTypeToString(SecurityEventType type)
{
    switch (type)
    {
    case SecurityEventType::DEVICE_CONNECTED:
        return L"DEVICE_CONNECTED";
    case SecurityEventType::DEVICE_QUARANTINED:
        return L"DEVICE_QUARANTINED";
    case SecurityEventType::DEVICE_RELEASED:
        return L"DEVICE_RELEASED";
    case SecurityEventType::DEVICE_REMOVED:
        return L"DEVICE_REMOVED";
    case SecurityEventType::ALLOWLIST_MATCH:
        return L"ALLOWLIST_MATCH";
    case SecurityEventType::UNKNOWN_DEVICE:
        return L"UNKNOWN_DEVICE";
    case SecurityEventType::USER_APPROVED:
        return L"USER_APPROVED";
    case SecurityEventType::USER_REJECTED:
        return L"USER_REJECTED";
    case SecurityEventType::DEVICE_BLOCKED:
        return L"DEVICE_BLOCKED";
    default:
        return L"UNKNOWN_EVENT";
    }
}

struct SecurityEvent
{
    std::wstring eventId;
    std::wstring clientId;
    std::wstring timestamp;
    SecurityEventType eventType = SecurityEventType::DEVICE_CONNECTED;

    std::wstring vendorId;
    std::wstring productId;
    std::wstring serialNumber;
    std::wstring deviceId;
    std::wstring deviceType;
    std::wstring description;

    std::wstring decision;
    std::wstring reason;
    std::wstring syncStatus = L"PENDING";
};
