#pragma once

// CompositeDevicePolicy.h
// Algorithm 3: Composite USB Device Policy
//
// A "composite" device presents multiple USB interfaces (e.g. a keyboard that
// also enumerates a storage volume or a network adapter).  This is the classic
// BadUSB attack vector: a device masquerades as a trusted HID peripheral while
// secretly also acting as a mass-storage or RNDIS network device.
//
// Policy:
//   1. Any device with capabilityCount > 1 is classified COMPOSITE.
//   2. Only explicitly allowlisted combinations bypass this layer.
//   3. Devices with unexpected capabilities (storage + HID, network + any,
//      network + storage) are flagged COMPOSITE_POLICY_VIOLATION and blocked.
//   4. Mouse+Keyboard composite (HID only, multiple HID interfaces) is the
//      one permitted combination when allowCompositeMouseKeyboard is true.

#include "../Models/USBDevice.h"
#include "PolicyConfig.h"
#include "../Models/SecurityEvent.h"

enum class CompositeVerdict
{
    PERMIT,     // Composite allowed by policy
    BLOCK,      // Composite blocked — unexpected capabilities
    NOT_COMPOSITE  // Single-capability device; not evaluated here
};

class CompositeDevicePolicy
{
public:

    // Evaluate a device that has already been classified by DeviceClassifier.
    // Returns a verdict and fills outReason.
    static CompositeVerdict Evaluate(
        const USBDevice& device,
        std::wstring& outReason);

    static const wchar_t* VerdictToString(CompositeVerdict v);
};
