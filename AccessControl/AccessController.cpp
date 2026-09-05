#include "AccessController.h"


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


const wchar_t* AccessController::ToString(
    AccessDecision decision)
{
    switch (decision)
    {
    case AccessDecision::ALLOW:
        return L"ALLOW";

    case AccessDecision::BLOCK:
        return L"BLOCK";

    case AccessDecision::ASK:
        return L"ASK";

    default:
        return L"UNKNOWN";
    }
}