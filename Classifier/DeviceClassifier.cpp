#include "DeviceClassifier.h"

#include <windows.h>
#include <cfgmgr32.h>

#include <algorithm>
#include <string>
#include <vector>

#pragma comment(lib, "cfgmgr32.lib")


// ============================================================
// Convert DeviceType to text
// ============================================================

const wchar_t* DeviceClassifier::ToString(
    DeviceType type)
{
    switch (type)
    {
    case DeviceType::HID:
        return L"HID";

    case DeviceType::STORAGE:
        return L"STORAGE";

    case DeviceType::NETWORK:
        return L"NETWORK";

    default:
        return L"OTHER";
    }
}


// ============================================================
// Get a registry property from a device node
// ============================================================

static std::wstring GetDevNodeProperty(
    DEVINST devInst,
    ULONG property)
{
    ULONG dataType = 0;
    ULONG size = 0;

    // First call: determine required buffer size.
    CONFIGRET result =
        CM_Get_DevNode_Registry_PropertyW(
            devInst,
            property,
            &dataType,
            nullptr,
            &size,
            0
        );

    if (result != CR_BUFFER_SMALL ||
        size == 0)
    {
        return L"";
    }

    std::vector<BYTE> buffer(size);

    // Second call: retrieve the actual property.
    result =
        CM_Get_DevNode_Registry_PropertyW(
            devInst,
            property,
            &dataType,
            buffer.data(),
            &size,
            0
        );

    if (result != CR_SUCCESS)
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
// Get device instance ID
// ============================================================

static std::wstring GetDevNodeInstanceId(
    DEVINST devInst)
{
    WCHAR buffer[MAX_DEVICE_ID_LEN];

    CONFIGRET result =
        CM_Get_Device_IDW(
            devInst,
            buffer,
            MAX_DEVICE_ID_LEN,
            0
        );

    if (result != CR_SUCCESS)
    {
        return L"";
    }

    return std::wstring(buffer);
}


// ============================================================
// Convert string to uppercase
// ============================================================

static std::wstring ToUpper(
    std::wstring value)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](wchar_t c)
        {
            return static_cast<wchar_t>(
                towupper(c)
                );
        }
    );

    return value;
}


// ============================================================
// Determine whether a devnode represents HID
// ============================================================

static bool IsHIDClass(
    const std::wstring& className,
    const std::wstring& deviceId,
    const std::wstring& service)
{
    std::wstring cls =
        ToUpper(className);

    std::wstring id =
        ToUpper(deviceId);

    std::wstring svc =
        ToUpper(service);


    // Windows HID setup class

    if (cls == L"HIDCLASS")
    {
        return true;
    }


    // HID instance IDs

    if (id.find(L"HID\\") == 0)
    {
        return true;
    }


    // HID USB service

    if (svc == L"HIDUSB")
    {
        return true;
    }


    return false;
}


// ============================================================
// Determine whether a devnode represents storage
// ============================================================

static bool IsStorageClass(
    const std::wstring& className,
    const std::wstring& deviceId,
    const std::wstring& service)
{
    std::wstring cls =
        ToUpper(className);

    std::wstring id =
        ToUpper(deviceId);

    std::wstring svc =
        ToUpper(service);


    // USB mass-storage device

    if (cls == L"USBSTOR")
    {
        return true;
    }


    // Disk drive

    if (cls == L"DISKDRIVE")
    {
        return true;
    }


    // Storage volume

    if (cls == L"VOLUME")
    {
        return true;
    }


    // USB storage instance

    if (id.find(L"USBSTOR\\") == 0)
    {
        return true;
    }


    // USB storage service

    if (svc == L"USBSTOR")
    {
        return true;
    }


    return false;
}


// ============================================================
// Determine whether a devnode represents networking
// ============================================================

static bool IsNetworkClass(
    const std::wstring& className,
    const std::wstring& deviceId,
    const std::wstring& service)
{
    std::wstring cls =
        ToUpper(className);

    std::wstring id =
        ToUpper(deviceId);

    std::wstring svc =
        ToUpper(service);


    // Windows network adapter setup class

    if (cls == L"NET")
    {
        return true;
    }


    // Network adapter device IDs

    if (id.find(L"ROOT\\NET") == 0)
    {
        return true;
    }


    // NDIS network driver service

    if (svc == L"NDIS")
    {
        return true;
    }


    return false;
}


// ============================================================
// Analyze one device node
// ============================================================

static void AnalyzeDevNode(
    DEVINST devInst,
    USBDevice& device)
{
    std::wstring className =
        GetDevNodeProperty(
            devInst,
            CM_DRP_CLASS
        );

    std::wstring service =
        GetDevNodeProperty(
            devInst,
            CM_DRP_SERVICE
        );

    std::wstring deviceId =
        GetDevNodeInstanceId(
            devInst
        );


    // --------------------------------------------------------
    // Store detected class
    // --------------------------------------------------------

    if (!className.empty())
    {
        if (std::find(
            device.detectedClasses.begin(),
            device.detectedClasses.end(),
            className)
            ==
            device.detectedClasses.end())
        {
            device.detectedClasses.push_back(
                className
            );
        }
    }


    // --------------------------------------------------------
    // HID
    // --------------------------------------------------------

    if (IsHIDClass(
        className,
        deviceId,
        service))
    {
        device.hasHID = true;
    }


    // --------------------------------------------------------
    // Storage
    // --------------------------------------------------------

    if (IsStorageClass(
        className,
        deviceId,
        service))
    {
        device.hasStorage = true;
    }


    // --------------------------------------------------------
    // Network
    // --------------------------------------------------------

    if (IsNetworkClass(
        className,
        deviceId,
        service))
    {
        device.hasNetwork = true;
    }
}


// ============================================================
// Recursively inspect children
// ============================================================

static void AnalyzeChildren(
    DEVINST parentDevInst,
    USBDevice& device,
    int depth = 0)
{
    // Safety limit
    if (depth > 20)
    {
        return;
    }


    DEVINST childDevInst = 0;

    CONFIGRET result =
        CM_Get_Child(
            &childDevInst,
            parentDevInst,
            0
        );

    if (result != CR_SUCCESS)
    {
        return;
    }


    while (true)
    {
        // Analyze current child

        AnalyzeDevNode(
            childDevInst,
            device
        );


        // Recursively inspect grandchildren

        AnalyzeChildren(
            childDevInst,
            device,
            depth + 1
        );


        // Move to next sibling

        DEVINST siblingDevInst = 0;

        result =
            CM_Get_Sibling(
                &siblingDevInst,
                childDevInst,
                0
            );

        if (result != CR_SUCCESS)
        {
            break;
        }

        childDevInst =
            siblingDevInst;
    }
}


// ============================================================
// Analyze the complete device tree
// ============================================================

bool DeviceClassifier::AnalyzeDeviceTree(
    USBDevice& device)
{
    if (device.deviceId.empty())
    {
        return false;
    }


    // --------------------------------------------------------
    // Locate root device node
    // --------------------------------------------------------

    DEVINST rootDevInst = 0;

    CONFIGRET result =
        CM_Locate_DevNodeW(
            &rootDevInst,
            const_cast<
            DEVINSTID_W
            >(device.deviceId.c_str()),
            CM_LOCATE_DEVNODE_NORMAL
        );


    if (result != CR_SUCCESS)
    {
        return false;
    }


    // --------------------------------------------------------
    // Analyze the root itself
    // --------------------------------------------------------

    AnalyzeDevNode(
        rootDevInst,
        device
    );


    // --------------------------------------------------------
    // Analyze children recursively
    // --------------------------------------------------------

    AnalyzeChildren(
        rootDevInst,
        device
    );


    return true;
}


// ============================================================
// Main classification function
// ============================================================

bool DeviceClassifier::Classify(
    USBDevice& device)
{
    // Reset previous classification

    device.type =
        DeviceType::OTHER;

    device.hasHID =
        false;

    device.hasStorage =
        false;

    device.hasNetwork =
        false;

    device.detectedClasses.clear();


    // Analyze Windows device tree

    if (!AnalyzeDeviceTree(device))
    {
        return false;
    }


    // --------------------------------------------------------
    // Determine primary type
    // --------------------------------------------------------

    int capabilityCount = 0;

    if (device.hasHID)
        capabilityCount++;

    if (device.hasStorage)
        capabilityCount++;

    if (device.hasNetwork)
        capabilityCount++;


    if (capabilityCount == 1)
    {
        if (device.hasHID)
        {
            device.type =
                DeviceType::HID;
        }
        else if (device.hasStorage)
        {
            device.type =
                DeviceType::STORAGE;
        }
        else if (device.hasNetwork)
        {
            device.type =
                DeviceType::NETWORK;
        }
    }
    else
    {
        // Multiple capabilities or none

        device.type =
            DeviceType::OTHER;
    }


    return true;
}