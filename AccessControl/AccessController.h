#pragma once

#include "../Models/USBDevice.h"
#include "../Allowlist/AllowlistManager.h"

#include <string>

enum class AccessDecision
{
    ALLOW,
    BLOCK,
    ASK
};

// Rich decision record produced by EvaluateWithDetails.
struct PolicyDecisionRecord
{
    AccessDecision decision = AccessDecision::ASK;

    // Algorithm 1 — Fingerprint / Allowlist
    bool           alg1LocalAllowlist  = false;  // matched local DB
    std::wstring   alg1MatchedFields;            // e.g. "VID+PID+Serial"

    // Algorithm 3 — Composite
    bool           alg3CompositeBlock  = false;
    std::wstring   alg3Reason;

    // Algorithm 6 — Network Anomaly
    bool           alg6NetworkAnomaly  = false;
    std::wstring   alg6Reason;

    // Algorithm 7 — Reconnection Evasion
    bool           alg7EvasionDetected = false;
    std::wstring   alg7Reason;

    std::wstring   primaryReason;               // Human-readable summary
};

class AccessController
{
public:

    // Original fast path (used by existing callers)
    static AccessDecision Evaluate(
        const USBDevice& device,
        AllowlistManager& allowlist
    );

    // Extended path: runs Alg 1 + Alg 3, fills outRecord for audit log.
    static AccessDecision EvaluateWithDetails(
        const USBDevice& device,
        AllowlistManager& allowlist,
        PolicyDecisionRecord& outRecord
    );

    static const wchar_t* ToString(
        AccessDecision decision
    );
};