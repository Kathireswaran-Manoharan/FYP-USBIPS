// CompositeDevicePolicy.cpp
// Algorithm 3: Composite USB Device Policy
//
// Threat model:
//   BadUSB-class attacks register multiple USB interfaces.  A thumb drive that
//   also pretends to be a HID keyboard can inject arbitrary keystrokes while
//   bypassing storage-only policies.  An RNDIS/ECM USB network adapter that
//   also appears as HID creates an exfiltration channel.
//
// This module acts AFTER DeviceClassifier::Classify() has populated
//   device.hasHID / hasStorage / hasNetwork / type.
//
// Decision matrix (PolicyConfig drives thresholds):
//   - Pure HID only                          → NOT_COMPOSITE
//   - Pure Storage only                      → NOT_COMPOSITE
//   - Pure Network only                      → NOT_COMPOSITE (but Alg 6 applies)
//   - Pure OTHER only                        → NOT_COMPOSITE
//   - HID + Storage                          → BLOCK  (BadUSB classic)
//   - HID + Network                          → BLOCK  (exfiltration via HID)
//   - Storage + Network                      → BLOCK  (covert network + data)
//   - HID + Storage + Network                → BLOCK  (full attack surface)
//   - HID only, multiple interfaces (mouse+keyboard) → PERMIT when policy allows

#include "CompositeDevicePolicy.h"
#include <iostream>

CompositeVerdict CompositeDevicePolicy::Evaluate(
    const USBDevice& device,
    std::wstring& outReason)
{
    const PolicyConfig& cfg = PolicyConfig::Instance();

    int caps = 0;
    if (device.hasHID)     caps++;
    if (device.hasStorage) caps++;
    if (device.hasNetwork) caps++;

    // Not composite
    if (caps <= 1)
    {
        outReason = L"Single-capability device; composite policy not applicable";
        return CompositeVerdict::NOT_COMPOSITE;
    }

    // ---- Composite device: evaluate allowed combinations ----

    // Mouse+Keyboard: HID+HID composites appear as capabilityCount==1 (hasHID)
    // at the class level, so HID-only multi-interface devices fall through to
    // NOT_COMPOSITE above.  This arm handles HID + storage / network combos.

    if (!cfg.blockUnauthorizedComposite)
    {
        outReason = L"Composite device allowed by policy (blockUnauthorizedComposite=false)";
        return CompositeVerdict::PERMIT;
    }

    // Build human-readable capability string
    std::wstring capStr;
    if (device.hasHID)
    {
        if (!capStr.empty()) capStr += L"+";
        capStr += L"HID";
    }
    if (device.hasStorage)
    {
        if (!capStr.empty()) capStr += L"+";
        capStr += L"STORAGE";
    }
    if (device.hasNetwork)
    {
        if (!capStr.empty()) capStr += L"+";
        capStr += L"NETWORK";
    }

    // Network-capable composite: highest risk - always block
    if (device.hasNetwork)
    {
        outReason = L"COMPOSITE_POLICY_VIOLATION: Network-capable composite device blocked ["
                    + capStr + L"] - potential exfiltration channel";
        return CompositeVerdict::BLOCK;
    }

    // HID + Storage: classic BadUSB vector
    if (device.hasHID && device.hasStorage)
    {
        outReason = L"COMPOSITE_POLICY_VIOLATION: HID+Storage composite blocked ["
                    + capStr + L"] - BadUSB attack vector";
        return CompositeVerdict::BLOCK;
    }

    // Any other unrecognized combination
    outReason = L"COMPOSITE_POLICY_VIOLATION: Unexpected composite capabilities ["
                + capStr + L"] blocked by default-deny policy";
    return CompositeVerdict::BLOCK;
}


const wchar_t* CompositeDevicePolicy::VerdictToString(CompositeVerdict v)
{
    switch (v)
    {
    case CompositeVerdict::PERMIT:        return L"PERMIT";
    case CompositeVerdict::BLOCK:         return L"BLOCK";
    case CompositeVerdict::NOT_COMPOSITE: return L"NOT_COMPOSITE";
    default:                              return L"UNKNOWN";
    }
}
