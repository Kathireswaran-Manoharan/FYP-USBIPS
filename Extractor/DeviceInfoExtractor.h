#pragma once
#pragma once

#include <string>
#include "../Models/USBDevice.h"

class DeviceInfoExtractor
{
public:

    static bool Extract(
        const std::wstring& devicePath,
        USBDevice& device
    );

private:

    static bool ExtractVidPid(
        const std::wstring& devicePath,
        std::wstring& vid,
        std::wstring& pid
    );

    static std::wstring ExtractInstancePart(
        const std::wstring& devicePath
    );
};