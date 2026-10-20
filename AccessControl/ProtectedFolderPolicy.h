#pragma once

#include <string>

struct ProtectedFolder
{
    int id = 0;
    std::wstring folderPath;
    std::wstring description;
    bool isEnabled = true;
};

struct PolicyViolationIncident
{
    std::wstring clientId;
    std::wstring vendorId;
    std::wstring productId;
    std::wstring serialNumber;
    std::wstring deviceId;
    std::wstring deviceType = L"STORAGE";
    std::wstring description;
    std::wstring folderPath;
    std::wstring operation;
    std::wstring attributionTier;   // L"DEFINITIVE", L"PROBABILISTIC", L"UNCERTAIN"
    std::wstring attributionEvidence;
    bool enforcementApplied = false;
    bool enforcementVerified = false;
    std::wstring enforcementCode;
};
