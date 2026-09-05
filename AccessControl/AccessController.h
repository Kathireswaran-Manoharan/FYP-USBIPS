#pragma once

#include "../Models/USBDevice.h"
#include "../Allowlist/AllowlistManager.h"

enum class AccessDecision
{
    ALLOW,
    BLOCK,
    ASK
};

class AccessController
{
public:

    static AccessDecision Evaluate(
        const USBDevice& device,
        AllowlistManager& allowlist
    );

    static const wchar_t* ToString(
        AccessDecision decision
    );
};