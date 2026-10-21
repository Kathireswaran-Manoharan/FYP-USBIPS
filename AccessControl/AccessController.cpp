#include "AccessController.h"
#include "CompositeDevicePolicy.h"
#include "ReconnectionEvasionAnalyzer.h"


// ============================================================
// Original fast path — unchanged for existing callers
// ============================================================

AccessDecision AccessController::Evaluate(
    const USBDevice& device,
    AllowlistManager& allowlist)
{
    if (allowlist.IsAllowed(device))
    {
        return AccessDecision::ALLOW;
    }

    return AccessDecision::ASK;
}


// ============================================================
// Algorithm 1, 3, 6, 7 combined evaluation
// ============================================================

AccessDecision AccessController::EvaluateWithDetails(
    const USBDevice& device,
    AllowlistManager& allowlist,
    PolicyDecisionRecord& outRecord)
{
    outRecord = {};

    // ----------------------------------------------------------
    // Algorithm 7: Reconnection Evasion & Flapping Analysis
    // Run first: rapid reconnection or serial-hopping attacks must
    // be neutralized before allowing or evaluating credentials.
    // ----------------------------------------------------------
    EvasionAnalysisResult evasion = ReconnectionEvasionAnalyzer::Instance().AnalyzeArrival(device, false);
    if (evasion.isEvasionDetected)
    {
        outRecord.alg7EvasionDetected = true;
        outRecord.alg7Reason         = evasion.primaryReason;
        outRecord.primaryReason      = evasion.primaryReason;
        outRecord.decision           = AccessDecision::BLOCK;
        return outRecord.decision;
    }

    // ----------------------------------------------------------
    // Algorithm 3: Composite-Device Policy
    // Run before allowlist — a BadUSB composite should
    // be blocked regardless of whether it has a server allowlist entry.
    // ----------------------------------------------------------
    std::wstring compositeReason;
    CompositeVerdict cv = CompositeDevicePolicy::Evaluate(device, compositeReason);

    if (cv == CompositeVerdict::BLOCK)
    {
        outRecord.alg3CompositeBlock = true;
        outRecord.alg3Reason         = compositeReason;
        outRecord.primaryReason      = L"[ALG3] " + compositeReason;
        outRecord.decision           = AccessDecision::BLOCK;
        return outRecord.decision;
    }

    // ----------------------------------------------------------
    // Algorithm 1: Device Fingerprinting & Allowlist Matching
    // Check local allowlist (VID + PID + Serial triplet).
    // ----------------------------------------------------------
    bool inLocalList = allowlist.IsAllowed(device);

    if (inLocalList)
    {
        outRecord.alg1LocalAllowlist = true;
        outRecord.alg1MatchedFields  = L"VID=" + device.vendorId
                                     + L" PID=" + device.productId
                                     + L" Serial=" + device.serialNumber;
        outRecord.primaryReason      = L"[ALG1] Device fingerprint matched local allowlist ("
                                     + outRecord.alg1MatchedFields + L")";
        outRecord.decision           = AccessDecision::ALLOW;
        return outRecord.decision;
    }

    // ----------------------------------------------------------
    // Device is not in local allowlist and not blocked by policy.
    // Escalate to central server for authorization.
    // ----------------------------------------------------------
    outRecord.primaryReason = L"[ALG1] Device fingerprint not in local allowlist -- "
                              L"requesting central server authorization";
    outRecord.decision      = AccessDecision::ASK;
    return outRecord.decision;
}


// ============================================================
// ToString
// ============================================================

const wchar_t* AccessController::ToString(
    AccessDecision decision)
{
    switch (decision)
    {
    case AccessDecision::ALLOW:  return L"ALLOW";
    case AccessDecision::BLOCK:  return L"BLOCK";
    case AccessDecision::ASK:    return L"ASK";
    default:                     return L"UNKNOWN";
    }
}