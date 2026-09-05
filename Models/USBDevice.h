#pragma once

#include <string>
#include <vector>

enum class DeviceType
{
    HID,
    STORAGE,
    NETWORK,
    OTHER
};

struct USBDevice
{
    // --------------------------------------------------------
    // Basic identity
    // --------------------------------------------------------

    std::wstring deviceInterfacePath;
    std::wstring deviceId;

    std::wstring vendorId;
    std::wstring productId;
    std::wstring productRevision;
    std::wstring serialNumber;


    // --------------------------------------------------------
    // Windows device information
    // --------------------------------------------------------

    std::wstring description;
    std::wstring manufacturer;
    std::wstring hardwareIds;


    // --------------------------------------------------------
    // Classification information
    // --------------------------------------------------------

    DeviceType type = DeviceType::OTHER;

    bool hasHID = false;
    bool hasStorage = false;
    bool hasNetwork = false;

    std::vector<std::wstring> detectedClasses;
};