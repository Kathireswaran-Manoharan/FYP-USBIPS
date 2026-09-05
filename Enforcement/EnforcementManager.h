#pragma once

#include <windows.h>
#include <cfgmgr32.h>

#include "../Models/USBDevice.h"

class EnforcementManager
{
public:

    static bool QuarantineDevice(
        const USBDevice& device
    );

    static bool ReleaseDevice(
        const USBDevice& device
    );

private:

    static bool LocateDeviceNode(
        const USBDevice& device,
        DEVINST& devInst
    );
};