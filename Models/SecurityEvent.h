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
    DEVICE_BLOCKED,
    HID_CAPTCHA_REQUIRED,
    HID_CAPTCHA_PASSED,
    HID_CAPTCHA_FAILED,
    HID_CAPTCHA_TIMEOUT,
    HID_CAPTCHA_EXPIRED,
    HID_CAPTCHA_REPLAY_ATTEMPT,
    MOUSE_CAPTCHA_PASSED,
    MOUSE_CAPTCHA_FAILED,
    MOUSE_CAPTCHA_TIMEOUT,
    MOUSE_CAPTCHA_CANCELLED,
    KEYBOARD_CAPTCHA_PASSED,
    KEYBOARD_CAPTCHA_FAILED,
    KEYBOARD_CAPTCHA_TIMEOUT,
    KEYBOARD_CAPTCHA_CANCELLED,
    HID_TEMP_VERIFICATION_RELEASE,
    HID_RE_QUARANTINE_ENFORCED,
    DEVICE_EXPIRED,
    HID_ANOMALY_DETECTED,
    COMPOSITE_POLICY_VIOLATION,
    PROTECTED_FILE_ACCESS,
    STORAGE_EXECUTION_BLOCKED,
    RECONNECTION_EVASION_DETECTED,
    MALWARE_DETECTED,
    SUSPICIOUS_FILE_DETECTED,
    DATA_EXFILTRATION_DETECTED,
    TRUST_ASSESSMENT_COMPLETED,
    INCIDENT_POLICY_VIOLATION
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
    case SecurityEventType::HID_CAPTCHA_REQUIRED:
        return L"HID_CAPTCHA_REQUIRED";
    case SecurityEventType::HID_CAPTCHA_PASSED:
        return L"HID_CAPTCHA_PASSED";
    case SecurityEventType::HID_CAPTCHA_FAILED:
        return L"HID_CAPTCHA_FAILED";
    case SecurityEventType::HID_CAPTCHA_TIMEOUT:
        return L"HID_CAPTCHA_TIMEOUT";
    case SecurityEventType::HID_CAPTCHA_EXPIRED:
        return L"HID_CAPTCHA_EXPIRED";
    case SecurityEventType::HID_CAPTCHA_REPLAY_ATTEMPT:
        return L"HID_CAPTCHA_REPLAY_ATTEMPT";
    case SecurityEventType::MOUSE_CAPTCHA_PASSED:
        return L"MOUSE_CAPTCHA_PASSED";
    case SecurityEventType::MOUSE_CAPTCHA_FAILED:
        return L"MOUSE_CAPTCHA_FAILED";
    case SecurityEventType::MOUSE_CAPTCHA_TIMEOUT:
        return L"MOUSE_CAPTCHA_TIMEOUT";
    case SecurityEventType::MOUSE_CAPTCHA_CANCELLED:
        return L"MOUSE_CAPTCHA_CANCELLED";
    case SecurityEventType::KEYBOARD_CAPTCHA_PASSED:
        return L"KEYBOARD_CAPTCHA_PASSED";
    case SecurityEventType::KEYBOARD_CAPTCHA_FAILED:
        return L"KEYBOARD_CAPTCHA_FAILED";
    case SecurityEventType::KEYBOARD_CAPTCHA_TIMEOUT:
        return L"KEYBOARD_CAPTCHA_TIMEOUT";
    case SecurityEventType::KEYBOARD_CAPTCHA_CANCELLED:
        return L"KEYBOARD_CAPTCHA_CANCELLED";
    case SecurityEventType::HID_TEMP_VERIFICATION_RELEASE:
        return L"HID_TEMP_VERIFICATION_RELEASE";
    case SecurityEventType::HID_RE_QUARANTINE_ENFORCED:
        return L"HID_RE_QUARANTINE_ENFORCED";
    case SecurityEventType::DEVICE_EXPIRED:
        return L"DEVICE_EXPIRED";
    case SecurityEventType::HID_ANOMALY_DETECTED:
        return L"HID_ANOMALY_DETECTED";
    case SecurityEventType::COMPOSITE_POLICY_VIOLATION:
        return L"COMPOSITE_POLICY_VIOLATION";
    case SecurityEventType::PROTECTED_FILE_ACCESS:
        return L"PROTECTED_FILE_ACCESS";
    case SecurityEventType::STORAGE_EXECUTION_BLOCKED:
        return L"STORAGE_EXECUTION_BLOCKED";
    case SecurityEventType::RECONNECTION_EVASION_DETECTED:
        return L"RECONNECTION_EVASION_DETECTED";
    case SecurityEventType::MALWARE_DETECTED:
        return L"MALWARE_DETECTED";
    case SecurityEventType::SUSPICIOUS_FILE_DETECTED:
        return L"SUSPICIOUS_FILE_DETECTED";
    case SecurityEventType::DATA_EXFILTRATION_DETECTED:
        return L"DATA_EXFILTRATION_DETECTED";
    case SecurityEventType::TRUST_ASSESSMENT_COMPLETED:
        return L"TRUST_ASSESSMENT_COMPLETED";
    case SecurityEventType::INCIDENT_POLICY_VIOLATION:
        return L"INCIDENT_POLICY_VIOLATION";
    default:
        return L"UNKNOWN_EVENT";
    }
}

inline SecurityEventType StringToSecurityEventType(const std::wstring& str)
{
    if (str == L"DEVICE_CONNECTED") return SecurityEventType::DEVICE_CONNECTED;
    if (str == L"DEVICE_QUARANTINED") return SecurityEventType::DEVICE_QUARANTINED;
    if (str == L"DEVICE_RELEASED") return SecurityEventType::DEVICE_RELEASED;
    if (str == L"DEVICE_REMOVED") return SecurityEventType::DEVICE_REMOVED;
    if (str == L"ALLOWLIST_MATCH") return SecurityEventType::ALLOWLIST_MATCH;
    if (str == L"UNKNOWN_DEVICE") return SecurityEventType::UNKNOWN_DEVICE;
    if (str == L"USER_APPROVED") return SecurityEventType::USER_APPROVED;
    if (str == L"USER_REJECTED") return SecurityEventType::USER_REJECTED;
    if (str == L"DEVICE_BLOCKED") return SecurityEventType::DEVICE_BLOCKED;
    if (str == L"HID_CAPTCHA_REQUIRED") return SecurityEventType::HID_CAPTCHA_REQUIRED;
    if (str == L"HID_CAPTCHA_PASSED") return SecurityEventType::HID_CAPTCHA_PASSED;
    if (str == L"HID_CAPTCHA_FAILED") return SecurityEventType::HID_CAPTCHA_FAILED;
    if (str == L"HID_CAPTCHA_TIMEOUT") return SecurityEventType::HID_CAPTCHA_TIMEOUT;
    if (str == L"HID_CAPTCHA_EXPIRED") return SecurityEventType::HID_CAPTCHA_EXPIRED;
    if (str == L"HID_CAPTCHA_REPLAY_ATTEMPT") return SecurityEventType::HID_CAPTCHA_REPLAY_ATTEMPT;
    if (str == L"MOUSE_CAPTCHA_PASSED") return SecurityEventType::MOUSE_CAPTCHA_PASSED;
    if (str == L"MOUSE_CAPTCHA_FAILED") return SecurityEventType::MOUSE_CAPTCHA_FAILED;
    if (str == L"MOUSE_CAPTCHA_TIMEOUT") return SecurityEventType::MOUSE_CAPTCHA_TIMEOUT;
    if (str == L"MOUSE_CAPTCHA_CANCELLED") return SecurityEventType::MOUSE_CAPTCHA_CANCELLED;
    if (str == L"KEYBOARD_CAPTCHA_PASSED") return SecurityEventType::KEYBOARD_CAPTCHA_PASSED;
    if (str == L"KEYBOARD_CAPTCHA_FAILED") return SecurityEventType::KEYBOARD_CAPTCHA_FAILED;
    if (str == L"KEYBOARD_CAPTCHA_TIMEOUT") return SecurityEventType::KEYBOARD_CAPTCHA_TIMEOUT;
    if (str == L"KEYBOARD_CAPTCHA_CANCELLED") return SecurityEventType::KEYBOARD_CAPTCHA_CANCELLED;
    if (str == L"HID_TEMP_VERIFICATION_RELEASE") return SecurityEventType::HID_TEMP_VERIFICATION_RELEASE;
    if (str == L"HID_RE_QUARANTINE_ENFORCED") return SecurityEventType::HID_RE_QUARANTINE_ENFORCED;
    if (str == L"DEVICE_EXPIRED") return SecurityEventType::DEVICE_EXPIRED;
    if (str == L"HID_ANOMALY_DETECTED") return SecurityEventType::HID_ANOMALY_DETECTED;
    if (str == L"COMPOSITE_POLICY_VIOLATION") return SecurityEventType::COMPOSITE_POLICY_VIOLATION;
    if (str == L"PROTECTED_FILE_ACCESS") return SecurityEventType::PROTECTED_FILE_ACCESS;
    if (str == L"STORAGE_EXECUTION_BLOCKED") return SecurityEventType::STORAGE_EXECUTION_BLOCKED;
    if (str == L"RECONNECTION_EVASION_DETECTED") return SecurityEventType::RECONNECTION_EVASION_DETECTED;
    if (str == L"MALWARE_DETECTED") return SecurityEventType::MALWARE_DETECTED;
    if (str == L"SUSPICIOUS_FILE_DETECTED") return SecurityEventType::SUSPICIOUS_FILE_DETECTED;
    if (str == L"DATA_EXFILTRATION_DETECTED") return SecurityEventType::DATA_EXFILTRATION_DETECTED;
    if (str == L"TRUST_ASSESSMENT_COMPLETED") return SecurityEventType::TRUST_ASSESSMENT_COMPLETED;
    if (str == L"INCIDENT_POLICY_VIOLATION") return SecurityEventType::INCIDENT_POLICY_VIOLATION;
    return SecurityEventType::DEVICE_CONNECTED;
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
    std::wstring algorithm = L"DEVICE_FINGERPRINT";
    int riskScore = 0;
    std::wstring enforcementResult = L"SUCCESS";
    std::wstring syncStatus = L"PENDING";
};
