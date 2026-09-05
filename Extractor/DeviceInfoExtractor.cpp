#include "DeviceInfoExtractor.h"

#include <windows.h>
#include <setupapi.h>
#include <usbiodef.h>

#include <vector>
#include <regex>

#pragma comment(lib, "setupapi.lib")


// ============================================================
// Extract VID / PID
// ============================================================

bool DeviceInfoExtractor::ExtractVidPid(
    const std::wstring& devicePath,
    std::wstring& vid,
    std::wstring& pid)
{
    std::wregex pattern(
        L"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})"
    );

    std::wsmatch match;

    if (std::regex_search(
        devicePath,
        match,
        pattern))
    {
        vid = match[1].str();
        pid = match[2].str();

        return true;
    }

    return false;
}


// ============================================================
// Extract instance component
// ============================================================

std::wstring DeviceInfoExtractor::ExtractInstancePart(
    const std::wstring& devicePath)
{
    size_t firstHash =
        devicePath.find(L'#');

    if (firstHash == std::wstring::npos)
        return L"";

    size_t secondHash =
        devicePath.find(
            L'#',
            firstHash + 1
        );

    if (secondHash == std::wstring::npos)
        return L"";

    size_t thirdHash =
        devicePath.find(
            L'#',
            secondHash + 1
        );

    if (thirdHash == std::wstring::npos)
        return L"";

    return devicePath.substr(
        secondHash + 1,
        thirdHash - secondHash - 1
    );
}


// ============================================================
// Find device by interface path
// ============================================================

static bool FindDeviceByInterfacePath(
    const std::wstring& devicePath,
    SP_DEVINFO_DATA& deviceInfoData,
    HDEVINFO& deviceInfoSet)
{
    deviceInfoSet = SetupDiGetClassDevsW(
        &GUID_DEVINTERFACE_USB_DEVICE,
        nullptr,
        nullptr,
        DIGCF_PRESENT |
        DIGCF_DEVICEINTERFACE
    );

    if (deviceInfoSet == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    for (DWORD index = 0; ; index++)
    {
        SP_DEVICE_INTERFACE_DATA interfaceData{};

        interfaceData.cbSize =
            sizeof(SP_DEVICE_INTERFACE_DATA);

        if (!SetupDiEnumDeviceInterfaces(
            deviceInfoSet,
            nullptr,
            &GUID_DEVINTERFACE_USB_DEVICE,
            index,
            &interfaceData))
        {
            if (GetLastError() ==
                ERROR_NO_MORE_ITEMS)
            {
                break;
            }

            continue;
        }

        DWORD requiredSize = 0;

        SetupDiGetDeviceInterfaceDetailW(
            deviceInfoSet,
            &interfaceData,
            nullptr,
            0,
            &requiredSize,
            nullptr
        );

        if (requiredSize == 0)
            continue;

        std::vector<BYTE> buffer(
            requiredSize
        );

        auto detailData =
            reinterpret_cast<
            PSP_DEVICE_INTERFACE_DETAIL_DATA_W
            >(buffer.data());

        detailData->cbSize =
            sizeof(
                SP_DEVICE_INTERFACE_DETAIL_DATA_W
                );

        SP_DEVINFO_DATA currentDevice{};

        currentDevice.cbSize =
            sizeof(SP_DEVINFO_DATA);

        if (!SetupDiGetDeviceInterfaceDetailW(
            deviceInfoSet,
            &interfaceData,
            detailData,
            requiredSize,
            nullptr,
            &currentDevice))
        {
            continue;
        }

        std::wstring currentPath =
            detailData->DevicePath;

        if (_wcsicmp(
            currentPath.c_str(),
            devicePath.c_str()) == 0)
        {
            deviceInfoData =
                currentDevice;

            return true;
        }
    }

    SetupDiDestroyDeviceInfoList(
        deviceInfoSet
    );

    deviceInfoSet =
        INVALID_HANDLE_VALUE;

    return false;
}


// ============================================================
// Get Windows device property
// ============================================================

static std::wstring GetDeviceProperty(
    HDEVINFO deviceInfoSet,
    SP_DEVINFO_DATA& deviceInfoData,
    DWORD property)
{
    DWORD dataType = 0;
    DWORD requiredSize = 0;

    SetupDiGetDeviceRegistryPropertyW(
        deviceInfoSet,
        &deviceInfoData,
        property,
        &dataType,
        nullptr,
        0,
        &requiredSize
    );

    if (requiredSize == 0)
        return L"";

    std::vector<BYTE> buffer(
        requiredSize
    );

    if (!SetupDiGetDeviceRegistryPropertyW(
        deviceInfoSet,
        &deviceInfoData,
        property,
        &dataType,
        buffer.data(),
        requiredSize,
        nullptr))
    {
        return L"";
    }

    if (dataType == REG_SZ ||
        dataType == REG_EXPAND_SZ)
    {
        return std::wstring(
            reinterpret_cast<wchar_t*>(
                buffer.data()
                )
        );
    }

    return L"";
}


// ============================================================
// Main extraction function
// ============================================================

bool DeviceInfoExtractor::Extract(
    const std::wstring& devicePath,
    USBDevice& device)
{
    device.deviceInterfacePath =
        devicePath;

    // VID / PID
    ExtractVidPid(
        devicePath,
        device.vendorId,
        device.productId
    );

    // Serial / instance component
    device.serialNumber =
        ExtractInstancePart(
            devicePath
        );

    // Find Windows device
    SP_DEVINFO_DATA deviceInfoData{};

    HDEVINFO deviceInfoSet =
        INVALID_HANDLE_VALUE;

    if (!FindDeviceByInterfacePath(
        devicePath,
        deviceInfoData,
        deviceInfoSet))
    {
        return false;
    }

    // Description
    device.description =
        GetDeviceProperty(
            deviceInfoSet,
            deviceInfoData,
            SPDRP_DEVICEDESC
        );

    // Manufacturer
    device.manufacturer =
        GetDeviceProperty(
            deviceInfoSet,
            deviceInfoData,
            SPDRP_MFG
        );

    // Hardware IDs
    device.hardwareIds =
        GetDeviceProperty(
            deviceInfoSet,
            deviceInfoData,
            SPDRP_HARDWAREID
        );

    // Device Instance ID
    WCHAR instanceId[512]{};

    if (SetupDiGetDeviceInstanceIdW(
        deviceInfoSet,
        &deviceInfoData,
        instanceId,
        512,
        nullptr))
    {
        device.deviceId =
            instanceId;
    }

    SetupDiDestroyDeviceInfoList(
        deviceInfoSet
    );

    return true;
}