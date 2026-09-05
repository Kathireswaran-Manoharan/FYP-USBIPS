#include "EnforcementManager.h"

#include <windows.h>
#include <cfgmgr32.h>
#include <iostream>

#pragma comment(lib, "cfgmgr32.lib")


bool EnforcementManager::LocateDeviceNode(
    const USBDevice& device,
    DEVINST& devInst)
{
    if (device.deviceId.empty())
    {
        std::wcerr
            << L"[ENFORCEMENT ERROR] Device ID is empty.\n";

        return false;
    }

    devInst = 0;

    CONFIGRET result =
        CM_Locate_DevNodeW(
            &devInst,
            const_cast<DEVINSTID_W>(
                device.deviceId.c_str()
            ),
            CM_LOCATE_DEVNODE_NORMAL
        );

    if (result != CR_SUCCESS)
    {
        std::wcerr
            << L"[ENFORCEMENT ERROR] "
            << L"Could not locate device node.\n";

        std::wcerr
            << L"Device ID : "
            << device.deviceId
            << L"\n";

        std::wcerr
            << L"CONFIGRET : "
            << result
            << L"\n";

        return false;
    }

    return true;
}


bool EnforcementManager::QuarantineDevice(
    const USBDevice& device)
{
    std::wcout
        << L"[ENFORCEMENT] Quarantining device...\n";

    // Windows may still be completing a previous
    // enable/disable transition. Retry a few times.
    const int maxAttempts = 5;

    for (int attempt = 1;
        attempt <= maxAttempts;
        ++attempt)
    {
        DEVINST devInst = 0;

        // Always locate the device node again.
        // Do not reuse an old DEVINST.
        if (!LocateDeviceNode(device, devInst))
        {
            std::wcerr
                << L"[ENFORCEMENT ERROR] "
                << L"Could not locate device node.\n";

            return false;
        }

        CONFIGRET result =
            CM_Disable_DevNode(
                devInst,
                CM_DISABLE_UI_NOT_OK
            );

        if (result == CR_SUCCESS)
        {
            std::wcout
                << L"[ENFORCEMENT] "
                << L"Device successfully quarantined.\n";

            return true;
        }

        if (result == CR_REMOVE_VETOED)
        {
            std::wcout
                << L"[ENFORCEMENT] "
                << L"Device disable was vetoed. "
                << L"Retrying ("
                << attempt
                << L"/"
                << maxAttempts
                << L")...\n";

            Sleep(300);

            continue;
        }

        // Any other error should not be treated as
        // a temporary removal veto.
        std::wcerr
            << L"[ENFORCEMENT ERROR] "
            << L"Failed to quarantine device.\n";

        std::wcerr
            << L"CONFIGRET : "
            << result
            << L"\n";

        return false;
    }

    std::wcerr
        << L"[ENFORCEMENT ERROR] "
        << L"Could not quarantine device after "
        << maxAttempts
        << L" attempts.\n";

    std::wcerr
        << L"CONFIGRET : "
        << CR_REMOVE_VETOED
        << L" (CR_REMOVE_VETOED)\n";

    std::wcerr
        << L"[SECURITY] Device will remain quarantined.\n";

    return false;
}


bool EnforcementManager::ReleaseDevice(
    const USBDevice& device)
{
    DEVINST devInst = 0;

    if (!LocateDeviceNode(device, devInst))
    {
        return false;
    }

    std::wcout
        << L"[ENFORCEMENT] "
        << L"Releasing device from quarantine...\n";

    CONFIGRET result =
        CM_Enable_DevNode(
            devInst,
            0
        );

    if (result != CR_SUCCESS)
    {
        std::wcerr
            << L"[ENFORCEMENT ERROR] "
            << L"Failed to enable device.\n";

        std::wcerr
            << L"CONFIGRET : "
            << result
            << L"\n";

        return false;
    }

    std::wcout
        << L"[ENFORCEMENT] "
        << L"Device successfully enabled.\n";

    return true;
}