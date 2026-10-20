#pragma once

#include "../Models/USBDevice.h"

class DeviceClassifier
{
public:

    static bool Classify(
        USBDevice& device
    );

    static const wchar_t* ToString(
        DeviceType type
    );

    static std::wstring GetSpecificTypeString(
        const USBDevice& device
    );

private:

    static bool AnalyzeDeviceTree(
        USBDevice& device
    );
};