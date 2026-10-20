// HIDBehaviorMonitor.cpp
// Algorithm 2: HID Behavior Monitoring — CAPTCHA + Keystroke Injection Detection
//
// Design notes:
//   - CAPTCHA flow: presents a simple Win32 InputBox dialog; the user must type a
//     short phrase within captchaTimeoutSeconds.  Pass = HID released, Fail = blocked.
//     For non-interactive / headless environments SetSimulatedCaptchaResult can
//     short-circuit the dialog for testing.
//   - Keystroke surveillance: a low-level WH_KEYBOARD_LL hook records inter-key
//     intervals in a sliding window.  Two signals raise HID_ANOMALY_DETECTED:
//       a) Burst rate  > PolicyConfig::ikiBurstThresholdCPS  (default 30 CPS)
//       b) Interval variance < PolicyConfig::ikiMinVarianceMs (default 2 ms)
//          (human typists show >> 2 ms natural jitter)
//   - IMPORTANT: the hook fires on the thread that called StartSurveillance().
//     main.cpp's PeekMessage loop keeps that thread pumping.
//   - Enforcement: the *caller* (main.cpp WindowProc) is responsible for
//     acting on the anomaly flag by calling EventLogger and deciding to keep
//     the device quarantined.  This module only monitors; it does not call
//     EnforcementManager directly, to avoid re-entrancy.

#include "HIDBehaviorMonitor.h"
#include "PolicyConfig.h"
#include "../Logging/EventLogger.h"
#include "../Models/SecurityEvent.h"
#include "../Enforcement/EnforcementManager.h"
#include "../Classifier/DeviceClassifier.h"

#include <windows.h>
#include <numeric>
#include <cmath>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <random>
#include <algorithm>
#include <vector>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

// ============================================================
// Singleton
// ============================================================

HIDBehaviorMonitor& HIDBehaviorMonitor::Instance()
{
    static HIDBehaviorMonitor instance;
    return instance;
}

HIDBehaviorMonitor::HIDBehaviorMonitor()
    : m_hook(nullptr)
    , m_surveillanceActive(false)
    , m_anomalyTriggered(false)
    , m_simulatedCaptchaEnabled(false)
    , m_simulatedCaptchaPass(false)
    , m_simulatedCaptchaOutcome(CaptchaOutcome::FAIL)
{
}

HIDBehaviorMonitor::~HIDBehaviorMonitor()
{
    StopSurveillance();
}


static std::string WStringToUtf8(const std::wstring& wstr)
{
    if (wstr.empty()) return std::string();
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &result[0], sizeNeeded, nullptr, nullptr);
    return result;
}

std::wstring HIDBehaviorMonitor::IssueNewChallenge(const USBDevice& device, const std::wstring& sessionId, int timeoutSeconds, int maxAttempts)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    static std::atomic<uint64_t> s_chalCounter(1);
    auto now = std::chrono::steady_clock::now();
    std::wstring chalId = L"chal-" + std::to_wstring(std::chrono::system_clock::now().time_since_epoch().count()) +
                          L"-" + std::to_wstring(s_chalCounter.fetch_add(1));

    ChallengeMetadata meta;
    meta.challengeId = chalId;
    meta.sessionId = sessionId;
    meta.deviceId = WStringToUtf8(device.deviceId);
    meta.createdAt = now;
    meta.deadline = now + std::chrono::seconds(timeoutSeconds > 0 ? timeoutSeconds : 30);
    meta.attemptsRemaining = maxAttempts > 0 ? maxAttempts : 3;
    meta.totalAttempts = 0;
    meta.isCompleted = false;
    meta.finalOutcome = CaptchaOutcome::FAIL;

    m_activeChallenges[chalId] = meta;
    return chalId;
}

bool HIDBehaviorMonitor::IsChallengeExpired(const std::wstring& challengeId) const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    auto it = m_activeChallenges.find(challengeId);
    if (it == m_activeChallenges.end())
    {
        return true;
    }
    if (it->second.isCompleted && it->second.finalOutcome == CaptchaOutcome::TIMEOUT)
    {
        return true;
    }
    return (std::chrono::steady_clock::now() > it->second.deadline);
}

bool HIDBehaviorMonitor::IsChallengeConsumed(const std::wstring& challengeId) const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_consumedChallengeIds.find(challengeId) != m_consumedChallengeIds.end();
}

CaptchaOutcome HIDBehaviorMonitor::ExpireChallengeOnTimeout(const std::wstring& challengeId)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_consumedChallengeIds.insert(challengeId);
    auto it = m_activeChallenges.find(challengeId);
    if (it != m_activeChallenges.end())
    {
        it->second.isCompleted = true;
        it->second.finalOutcome = CaptchaOutcome::TIMEOUT;
        return CaptchaOutcome::TIMEOUT;
    }
    return CaptchaOutcome::TIMEOUT;
}

CaptchaOutcome HIDBehaviorMonitor::SubmitChallengeResponse(
    const std::wstring& challengeId,
    const std::wstring& enteredCode,
    const std::wstring& expectedCode)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    // 1. Replay check
    if (m_simulatedReplayAttempt || m_consumedChallengeIds.find(challengeId) != m_consumedChallengeIds.end())
    {
        return CaptchaOutcome::REPLAY;
    }

    auto it = m_activeChallenges.find(challengeId);
    if (it == m_activeChallenges.end())
    {
        return CaptchaOutcome::FAIL;
    }

    // 2. Reject late response if challenge already completed (e.g. timed out)
    if (it->second.isCompleted)
    {
        return it->second.finalOutcome;
    }

    // 3. Deadline check
    auto now = std::chrono::steady_clock::now();
    if (now > it->second.deadline)
    {
        it->second.isCompleted = true;
        it->second.finalOutcome = CaptchaOutcome::TIMEOUT;
        m_consumedChallengeIds.insert(challengeId);
        return CaptchaOutcome::TIMEOUT;
    }

    // 4. Attempt limit check & match evaluation
    it->second.totalAttempts++;
    if (_wcsicmp(enteredCode.c_str(), expectedCode.c_str()) == 0)
    {
        it->second.isCompleted = true;
        it->second.finalOutcome = CaptchaOutcome::PASS;
        m_consumedChallengeIds.insert(challengeId);
        return CaptchaOutcome::PASS;
    }
    else
    {
        it->second.attemptsRemaining--;
        if (it->second.attemptsRemaining <= 0)
        {
            it->second.isCompleted = true;
            it->second.finalOutcome = CaptchaOutcome::FAIL;
            m_consumedChallengeIds.insert(challengeId);
            return CaptchaOutcome::FAIL;
        }
        return CaptchaOutcome::FAIL;
    }
}

// ============================================================
// Algorithm 2A: Randomized Mouse-Driven Visual CAPTCHA Challenge
// ============================================================

struct InteractiveCaptchaState
{
    std::wstring challengeId;
    std::wstring targetPin;
    std::vector<std::wstring> options;
    int correctIndex = -1;
    int attemptsLeft = 3;
    int secondsLeft = 30;
    CaptchaOutcome outcome = CaptchaOutcome::FAIL;
    bool isCompleted = false;
    HWND hTargetLabel = NULL;
    HWND hTimerLabel = NULL;
    HWND hStatusLabel = NULL;
    HWND hButtons[4] = { NULL };
    HWND hCancelBtn = NULL;
    HBRUSH hBgBrush = NULL;
};

static LRESULT CALLBACK CaptchaWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    InteractiveCaptchaState* state = reinterpret_cast<InteractiveCaptchaState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (uMsg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        state = reinterpret_cast<InteractiveCaptchaState*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        return 0;
    }

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = (HDC)wParam;
        HWND hStatic = (HWND)lParam;
        SetBkMode(hdc, TRANSPARENT);
        if (state && hStatic == state->hTargetLabel)
        {
            SetTextColor(hdc, RGB(56, 189, 248)); // #38bdf8 light cyan
        }
        else if (state && hStatic == state->hTimerLabel)
        {
            SetTextColor(hdc, RGB(251, 191, 36)); // #fbbf24 amber
        }
        else if (state && hStatic == state->hStatusLabel)
        {
            SetTextColor(hdc, RGB(239, 68, 68)); // #ef4444 red
        }
        else
        {
            SetTextColor(hdc, RGB(249, 250, 251)); // #f9fafb white
        }
        return (LRESULT)(state ? state->hBgBrush : (HBRUSH)GetStockObject(BLACK_BRUSH));
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, state ? state->hBgBrush : (HBRUSH)GetStockObject(BLACK_BRUSH));
        return 1;
    }

    case WM_TIMER:
    {
        if (wParam == 1 && state)
        {
            if (state->isCompleted)
            {
                KillTimer(hwnd, 1);
                return 0;
            }
            state->secondsLeft--;
            std::wstring timerText = L"Time Remaining: " + std::to_wstring(state->secondsLeft) + L"s";
            if (state->hTimerLabel)
            {
                SetWindowTextW(state->hTimerLabel, timerText.c_str());
            }

            if (state->secondsLeft <= 0)
            {
                state->isCompleted = true;
                KillTimer(hwnd, 1);
                state->outcome = CaptchaOutcome::TIMEOUT;
                HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(state->challengeId);
                DestroyWindow(hwnd);
            }
        }
        return 0;
    }

    case WM_COMMAND:
    {
        int ctrlId = LOWORD(wParam);
        if (HIWORD(wParam) == BN_CLICKED && state)
        {
            if (state->isCompleted || state->outcome == CaptchaOutcome::TIMEOUT)
            {
                // Disallow late submissions after challenge has timed out or finalized
                return 0;
            }
            if (ctrlId >= 201 && ctrlId <= 204)
            {
                int clickedIndex = ctrlId - 201;
                if (clickedIndex >= 0 && clickedIndex < static_cast<int>(state->options.size()))
                {
                    CaptchaOutcome subRes = HIDBehaviorMonitor::Instance().SubmitChallengeResponse(
                        state->challengeId, state->options[clickedIndex], state->targetPin);

                    if (subRes == CaptchaOutcome::PASS)
                    {
                        state->isCompleted = true;
                        KillTimer(hwnd, 1);
                        state->outcome = CaptchaOutcome::PASS;
                        DestroyWindow(hwnd);
                    }
                    else if (subRes == CaptchaOutcome::TIMEOUT)
                    {
                        state->isCompleted = true;
                        KillTimer(hwnd, 1);
                        state->outcome = CaptchaOutcome::TIMEOUT;
                        DestroyWindow(hwnd);
                    }
                    else
                    {
                        state->attemptsLeft--;
                        if (state->attemptsLeft <= 0)
                        {
                            state->isCompleted = true;
                            KillTimer(hwnd, 1);
                            state->outcome = CaptchaOutcome::FAIL;
                            DestroyWindow(hwnd);
                        }
                        else
                        {
                            std::wstring statusText = L"Incorrect code! Attempts remaining: " + std::to_wstring(state->attemptsLeft);
                            if (state->hStatusLabel)
                            {
                                SetWindowTextW(state->hStatusLabel, statusText.c_str());
                            }
                            MessageBeep(MB_ICONWARNING);
                        }
                    }
                }
            }
            else if (ctrlId == 205 || ctrlId == IDCANCEL)
            {
                if (!state->isCompleted)
                {
                    state->isCompleted = true;
                    KillTimer(hwnd, 1);
                    state->outcome = CaptchaOutcome::CANCELLED;
                    HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(state->challengeId);
                }
                DestroyWindow(hwnd);
            }
        }
        return 0;
    }

    // STRICT DEFENSE AGAINST BADUSB KEYSTROKE INJECTION:
    // Any keyboard messages sent to the window are intentionally discarded.
    // The newly connected BadUSB cannot click buttons by injecting Enter, Space, or hotkeys.
    case WM_KEYDOWN:
    case WM_KEYUP:
    case WM_CHAR:
    case WM_SYSKEYDOWN:
    case WM_SYSKEYUP:
        return 0;

    case WM_CLOSE:
        if (state && !state->isCompleted)
        {
            state->isCompleted = true;
            state->outcome = CaptchaOutcome::CANCELLED;
            HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(state->challengeId);
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        // Modal window closed. NEVER call PostQuitMessage(0); keep client message loop alive!
        return 0;
    }

    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

CaptchaOutcome HIDBehaviorMonitor::PromptCaptchaChallengeWithDetails(const USBDevice& device)
{
    const PolicyConfig& cfg = PolicyConfig::Instance();

    // --- Simulation bypass for automated tests ---
    if (m_simulatedCaptchaEnabled)
    {
        std::wcout
            << L"[HID-CAPTCHA] Simulated outcome: "
            << (m_simulatedCaptchaOutcome == CaptchaOutcome::PASS ? L"PASS" :
               (m_simulatedCaptchaOutcome == CaptchaOutcome::TIMEOUT ? L"TIMEOUT" : L"FAIL"))
            << L"\n";
        return m_simulatedCaptchaOutcome;
    }

    // Generate randomized 4-digit PIN (1000 - 9999)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1000, 9999);

    int correctPinNum = dist(gen);
    std::wstring targetPin = std::to_wstring(correctPinNum);

    std::vector<std::wstring> options;
    options.push_back(targetPin);

    while (options.size() < 4)
    {
        int decoyNum = dist(gen);
        std::wstring decoyPin = std::to_wstring(decoyNum);
        if (std::find(options.begin(), options.end(), decoyPin) == options.end())
        {
            options.push_back(decoyPin);
        }
    }

    // Shuffle options so correct PIN is at a randomized button position
    std::shuffle(options.begin(), options.end(), gen);

    int correctIdx = 0;
    for (size_t i = 0; i < options.size(); ++i)
    {
        if (options[i] == targetPin)
        {
            correctIdx = static_cast<int>(i);
            break;
        }
    }

    InteractiveCaptchaState state;
    state.challengeId = IssueNewChallenge(device, L"legacy-pin-session", cfg.captchaTimeoutSeconds, cfg.captchaMaxAttempts);
    state.targetPin = targetPin;
    state.options = options;
    state.correctIndex = correctIdx;
    state.attemptsLeft = (cfg.captchaMaxAttempts > 0) ? cfg.captchaMaxAttempts : 3;
    state.secondsLeft = (cfg.captchaTimeoutSeconds > 0) ? cfg.captchaTimeoutSeconds : 30;
    state.outcome = CaptchaOutcome::FAIL;
    state.isCompleted = false;
    state.hBgBrush = CreateSolidBrush(RGB(17, 24, 39)); // dark theme

    // Register Window Class (if not already registered)
    LPCWSTR className = L"USBIPS_HID_CAPTCHA_WND";
    WNDCLASSEXW wc = { 0 };
    if (!GetClassInfoExW(GetModuleHandleW(nullptr), className, &wc))
    {
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.lpfnWndProc = CaptchaWindowProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = state.hBgBrush;
        wc.lpszClassName = className;
        RegisterClassExW(&wc);
    }

    int wndWidth = 560;
    int wndHeight = 460;
    int screenX = (GetSystemMetrics(SM_CXSCREEN) - wndWidth) / 2;
    int screenY = (GetSystemMetrics(SM_CYSCREEN) - wndHeight) / 2;

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        className,
        L"USBIPS — Zero-Trust Human Verification (Algorithm 2)",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        screenX, screenY, wndWidth, wndHeight,
        nullptr, nullptr, GetModuleHandleW(nullptr), &state
    );

    if (!hwnd)
    {
        std::wcerr << L"[HID-CAPTCHA ERROR] Could not create visual challenge window; default to BLOCK.\n";
        DeleteObject(state.hBgBrush);
        return CaptchaOutcome::FAIL;
    }

    // Create fonts
    HFONT hTitleFont = CreateFontW(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HFONT hBigFont = CreateFontW(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Consolas");
    HFONT hNormalFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    // Title label
    HWND hTitle = CreateWindowExW(0, L"STATIC", L"UNTRUSTED KEYBOARD DETECTED",
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 20, 520, 24, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(hTitle, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    // Device details
    std::wstring devText = L"Hardware: " + device.vendorId + L":" + device.productId +
        L" (" + (device.description.empty() ? L"USB Keyboard" : device.description) + L")";
    HWND hDev = CreateWindowExW(0, L"STATIC", devText.c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 50, 520, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(hDev, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    // Security warning notice
    LPCWSTR notice = L"SECURITY RESTRICTION: Keyboard inputs are quarantined to prevent BadUSB injection.\r\n"
                     L"Human verification MUST be completed using your trusted mouse pointer.";
    HWND hNotice = CreateWindowExW(0, L"STATIC", notice,
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 78, 520, 36, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(hNotice, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    // Big verification target PIN
    std::wstring targetText = L"Verification Target PIN: [ " + targetPin + L" ]";
    state.hTargetLabel = CreateWindowExW(0, L"STATIC", targetText.c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 125, 520, 34, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(state.hTargetLabel, WM_SETFONT, (WPARAM)hBigFont, TRUE);

    // Instruction label
    HWND hPrompt = CreateWindowExW(0, L"STATIC", L"Using your mouse pointer, click the matching verification PIN below:",
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 170, 520, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(hPrompt, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    // 4 Option Buttons (2x2 grid)
    int btnW = 180;
    int btnH = 42;
    int coords[4][2] = { {80, 205}, {300, 205}, {80, 260}, {300, 260} };
    for (int i = 0; i < 4; ++i)
    {
        std::wstring btnLabel = L"Option " + std::wstring(1, L'A' + i) + L":  " + options[i];
        state.hButtons[i] = CreateWindowExW(0, L"BUTTON", btnLabel.c_str(),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            coords[i][0], coords[i][1], btnW, btnH,
            hwnd, (HMENU)(INT_PTR)(201 + i), nullptr, nullptr);
        SendMessageW(state.hButtons[i], WM_SETFONT, (WPARAM)hTitleFont, TRUE);
    }

    // Status / attempts label
    std::wstring statusInit = L"Attempts Remaining: " + std::to_wstring(state.attemptsLeft);
    state.hStatusLabel = CreateWindowExW(0, L"STATIC", statusInit.c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 320, 520, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(state.hStatusLabel, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    // Timer countdown label
    std::wstring timerInit = L"Time Remaining: " + std::to_wstring(state.secondsLeft) + L"s";
    state.hTimerLabel = CreateWindowExW(0, L"STATIC", timerInit.c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 345, 520, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(state.hTimerLabel, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    // Deny / Cancel button
    state.hCancelBtn = CreateWindowExW(0, L"BUTTON", L"Deny & Block Device",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        180, 380, 200, 36,
        hwnd, (HMENU)(INT_PTR)205, nullptr, nullptr);
    SendMessageW(state.hCancelBtn, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    // Start countdown timer
    SetTimer(hwnd, 1, 1000, nullptr);

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    SetForegroundWindow(hwnd);

    std::wcout << L"\n[HID-CAPTCHA] ========================================\n"
               << L"[HID-CAPTCHA] Untrusted keyboard human verification initiated.\n"
               << L"[HID-CAPTCHA] Device      : " << device.vendorId << L":" << device.productId << L"\n"
               << L"[HID-CAPTCHA] Target PIN  : " << targetPin << L"\n"
               << L"[HID-CAPTCHA] Input Path  : TRUSTED MOUSE POINTER ONLY\n"
               << L"[HID-CAPTCHA] Timeout     : " << state.secondsLeft << L" seconds\n"
               << L"[HID-CAPTCHA] Max Attempts: " << state.attemptsLeft << L"\n"
               << L"[HID-CAPTCHA] ========================================\n";

    // Modal message loop: safely pumps messages until window closes
    MSG msg = { 0 };
    while (IsWindow(hwnd))
    {
        BOOL bRet = GetMessageW(&msg, nullptr, 0, 0);
        if (bRet == 0) // Legitimate WM_QUIT received from system shutdown or application exit
        {
            // Propagate legitimate shutdown signal to outer application message loop
            PostQuitMessage((int)msg.wParam);
            break;
        }
        else if (bRet == -1) // Error
        {
            break;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Cleanup resources
    DeleteObject(hTitleFont);
    DeleteObject(hBigFont);
    DeleteObject(hNormalFont);
    DeleteObject(state.hBgBrush);

    std::wcout << L"[HID-CAPTCHA] Outcome: "
               << (state.outcome == CaptchaOutcome::PASS ? L"PASS [OK]" :
                  (state.outcome == CaptchaOutcome::TIMEOUT ? L"TIMEOUT [BLOCK]" : L"FAIL [BLOCK]"))
               << L"\n";

    return state.outcome;
}


// ============================================================
// Specialized Keyboard Interactive Challenge
// ============================================================

struct KeyboardChallengeState
{
    std::wstring challengeId;
    std::wstring targetCode;
    USBDevice targetDevice;
    bool lastInputSourceIsTarget = false;
    int targetKeystrokeCount = 0;
    int nonTargetKeystrokeCount = 0;
    std::wstring enteredCode;
    int attemptsLeft = 3;
    int totalAttempts = 0;
    int secondsLeft = 30;
    CaptchaOutcome outcome = CaptchaOutcome::FAIL;
    bool isCompleted = false;
    HWND hEdit = NULL;
    HWND hTimerLabel = NULL;
    HWND hStatusLabel = NULL;
    HWND hTargetLabel = NULL;
    HBRUSH hBgBrush = NULL;
};

static LRESULT CALLBACK KeyboardCaptchaProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    KeyboardChallengeState* state = reinterpret_cast<KeyboardChallengeState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (uMsg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        state = reinterpret_cast<KeyboardChallengeState*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));

        // Register for Raw Input to inspect physical input device identity
        RAWINPUTDEVICE rid;
        rid.usUsagePage = 0x01; // Generic Desktop Controls
        rid.usUsage = 0x06;     // Keyboard
        rid.dwFlags = RIDEV_INPUTSINK;
        rid.hwndTarget = hwnd;
        BOOL regOk = RegisterRawInputDevices(&rid, 1, sizeof(RAWINPUTDEVICE));
        std::wcout << L"[RAWINPUT] Registered Keyboard Raw Input sink for HWND=" << hwnd
                   << L" Result=" << (regOk ? L"SUCCESS" : L"FAILED")
                   << L" (LastError=" << GetLastError() << L")\n";
        return 0;
    }
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        if (state && state->hBgBrush)
        {
            FillRect(hdc, &ps.rcPaint, state->hBgBrush);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_INPUT:
    {
        if (state)
        {
            UINT dwSize = 0;
            GetRawInputData((HRAWINPUT)lParam, RID_INPUT, nullptr, &dwSize, sizeof(RAWINPUTHEADER));
            if (dwSize > 0)
            {
                std::vector<BYTE> lpb(dwSize);
                if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, lpb.data(), &dwSize, sizeof(RAWINPUTHEADER)) == dwSize)
                {
                    RAWINPUT* raw = (RAWINPUT*)lpb.data();
                    if (raw->header.dwType == RIM_TYPEKEYBOARD)
                    {
                        if (raw->data.keyboard.Message == WM_KEYDOWN || raw->data.keyboard.Message == WM_SYSKEYDOWN)
                        {
                            USHORT vk = raw->data.keyboard.VKey;
                            bool isTarget = HIDBehaviorMonitor::Instance().IsInputFromTargetDevice(raw->header.hDevice, state->targetDevice);
                            state->lastInputSourceIsTarget = isTarget;

                            if (!isTarget)
                            {
                                state->nonTargetKeystrokeCount++;
                                if (state->hStatusLabel)
                                {
                                    SetWindowTextW(state->hStatusLabel, L"Input ignored: Keystroke from existing keyboard! Use NEW keyboard.");
                                }
                            }
                            else
                            {
                                state->targetKeystrokeCount++;
                                if (vk == VK_BACK)
                                {
                                    if (!state->enteredCode.empty())
                                    {
                                        state->enteredCode.pop_back();
                                        SetWindowTextW(state->hEdit, state->enteredCode.c_str());
                                        std::wstring status = L"Key accepted from target keyboard (" +
                                            std::to_wstring(state->enteredCode.length()) + L"/6)";
                                        if (state->hStatusLabel)
                                        {
                                            SetWindowTextW(state->hStatusLabel, status.c_str());
                                        }
                                    }
                                }
                                else if (vk == VK_RETURN)
                                {
                                    // Enter pressed on target keyboard triggers code verification
                                    PostMessageW(hwnd, WM_COMMAND, MAKEWPARAM(301, BN_CLICKED), 0);
                                }
                                else if (vk == VK_ESCAPE)
                                {
                                    // Escape pressed on target keyboard triggers cancel
                                    PostMessageW(hwnd, WM_COMMAND, MAKEWPARAM(302, BN_CLICKED), 0);
                                }
                                else
                                {
                                    wchar_t ch = 0;
                                    if (vk >= 'A' && vk <= 'Z')
                                    {
                                        ch = (wchar_t)vk;
                                    }
                                    else if (vk >= '0' && vk <= '9')
                                    {
                                        ch = (wchar_t)vk;
                                    }
                                    else if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9)
                                    {
                                        ch = L'0' + (vk - VK_NUMPAD0);
                                    }

                                    if (ch != 0 && state->enteredCode.length() < 6)
                                    {
                                        state->enteredCode.push_back(ch);
                                        SetWindowTextW(state->hEdit, state->enteredCode.c_str());

                                        std::wstring status = L"Key accepted from target keyboard (" +
                                            std::to_wstring(state->enteredCode.length()) + L"/6)";
                                        if (state->hStatusLabel)
                                        {
                                            SetWindowTextW(state->hStatusLabel, status.c_str());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        SetBkMode(hdc, TRANSPARENT);
        if (state && hCtrl == state->hEdit)
        {
            SetTextColor(hdc, RGB(248, 250, 252));
            SetBkColor(hdc, RGB(30, 41, 59));
            static HBRUSH hEditBrush = CreateSolidBrush(RGB(30, 41, 59));
            return (LRESULT)hEditBrush;
        }
        else if (state && hCtrl == state->hTargetLabel)
        {
            SetTextColor(hdc, RGB(56, 189, 248)); // #38bdf8 light cyan
        }
        else if (state && hCtrl == state->hTimerLabel)
        {
            SetTextColor(hdc, RGB(251, 191, 36)); // #fbbf24 amber
        }
        else if (state && hCtrl == state->hStatusLabel)
        {
            SetTextColor(hdc, RGB(239, 68, 68)); // #ef4444 red
        }
        else
        {
            SetTextColor(hdc, RGB(249, 250, 251)); // white
        }
        return (LRESULT)(state ? state->hBgBrush : (HBRUSH)GetStockObject(BLACK_BRUSH));
    }
    case WM_CTLCOLOREDIT:
    {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, RGB(248, 250, 252));
        SetBkColor(hdc, RGB(30, 41, 59));
        return (LRESULT)CreateSolidBrush(RGB(30, 41, 59));
    }
    case WM_ERASEBKGND:
    {
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, state ? state->hBgBrush : (HBRUSH)GetStockObject(BLACK_BRUSH));
        return 1;
    }
    case WM_TIMER:
    {
        if (wParam == 1 && state)
        {
            if (state->isCompleted)
            {
                KillTimer(hwnd, 1);
                return 0;
            }
            state->secondsLeft--;
            std::wstring timerText = L"Time Remaining: " + std::to_wstring(state->secondsLeft) + L"s";
            if (state->hTimerLabel)
            {
                SetWindowTextW(state->hTimerLabel, timerText.c_str());
            }
            if (state->secondsLeft <= 0)
            {
                state->isCompleted = true;
                KillTimer(hwnd, 1);
                state->outcome = CaptchaOutcome::TIMEOUT;
                HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(state->challengeId);
                DestroyWindow(hwnd);
            }
        }
        return 0;
    }
    case WM_COMMAND:
    {
        int ctrlId = LOWORD(wParam);
        if ((ctrlId == 301 || ctrlId == IDOK) && state)
        {
            if (state->isCompleted || state->outcome == CaptchaOutcome::TIMEOUT)
            {
                // Disallow late submissions after timeout
                return 0;
            }

            // Attribution check: reject if input was from existing keyboard or no input from target
            if (HIDBehaviorMonitor::Instance().IsSimulatedDeviceAttributionEnabled())
            {
                if (!HIDBehaviorMonitor::Instance().GetSimulatedIsTargetDevice())
                {
                    if (state->hStatusLabel)
                    {
                        SetWindowTextW(state->hStatusLabel, L"Input ignored: Keystroke from existing keyboard! Use NEW keyboard.");
                    }
                    state->enteredCode.clear();
                    SetWindowTextW(state->hEdit, L"");
                    MessageBeep(MB_ICONWARNING);
                    return 0;
                }
            }
            else
            {
                if (state->targetKeystrokeCount == 0 || state->enteredCode.empty())
                {
                    if (state->hStatusLabel)
                    {
                        SetWindowTextW(state->hStatusLabel, state->nonTargetKeystrokeCount > 0
                            ? L"Input ignored: Keystroke from existing keyboard! Use NEW keyboard."
                            : L"Please type the verification code using the NEW keyboard.");
                    }
                    MessageBeep(MB_ICONWARNING);
                    return 0;
                }
            }

            state->totalAttempts++;
            std::wstring entered = state->enteredCode;
            if (entered.empty())
            {
                WCHAR buf[64] = { 0 };
                GetWindowTextW(state->hEdit, buf, 63);
                entered = buf;
            }
            while (!entered.empty() && iswspace(entered.front())) entered.erase(entered.begin());
            while (!entered.empty() && iswspace(entered.back())) entered.pop_back();

            CaptchaOutcome subRes = HIDBehaviorMonitor::Instance().SubmitChallengeResponse(
                state->challengeId, entered, state->targetCode);

            if (subRes == CaptchaOutcome::PASS)
            {
                state->isCompleted = true;
                KillTimer(hwnd, 1);
                state->outcome = CaptchaOutcome::PASS;
                DestroyWindow(hwnd);
            }
            else if (subRes == CaptchaOutcome::TIMEOUT)
            {
                state->isCompleted = true;
                KillTimer(hwnd, 1);
                state->outcome = CaptchaOutcome::TIMEOUT;
                DestroyWindow(hwnd);
            }
            else
            {
                state->attemptsLeft--;
                if (state->attemptsLeft <= 0)
                {
                    state->isCompleted = true;
                    KillTimer(hwnd, 1);
                    state->outcome = CaptchaOutcome::FAIL;
                    DestroyWindow(hwnd);
                }
                else
                {
                    std::wstring status = L"Incorrect code! Attempts remaining: " + std::to_wstring(state->attemptsLeft);
                    SetWindowTextW(state->hStatusLabel, status.c_str());
                    state->enteredCode.clear();
                    SetWindowTextW(state->hEdit, L"");
                    SetFocus(state->hEdit);
                    MessageBeep(MB_ICONWARNING);
                }
            }
        }
        else if (ctrlId == 302 || ctrlId == IDCANCEL)
        {
            if (state && !state->isCompleted)
            {
                state->isCompleted = true;
                KillTimer(hwnd, 1);
                state->outcome = CaptchaOutcome::CANCELLED;
                HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(state->challengeId);
            }
            DestroyWindow(hwnd);
        }
        return 0;
    }
    case WM_CLOSE:
        if (state && !state->isCompleted)
        {
            state->isCompleted = true;
            state->outcome = CaptchaOutcome::CANCELLED;
            HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(state->challengeId);
        }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        // Modal window closed. NEVER call PostQuitMessage(0); keep client message loop alive!
        return 0;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

CaptchaOutcome HIDBehaviorMonitor::PromptKeyboardCaptchaChallenge(const USBDevice& device, HIDVerificationResult& outResult)
{
    const PolicyConfig& cfg = PolicyConfig::Instance();

    // Generate random 6-character alphanumeric challenge (unambiguous characters)
    static const wchar_t charset[] = L"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, sizeof(charset) / sizeof(wchar_t) - 2);

    std::wstring targetCode;
    for (int i = 0; i < 6; ++i)
    {
        targetCode.push_back(charset[dist(gen)]);
    }

    KeyboardChallengeState state;
    if (outResult.challengeId.empty())
    {
        outResult.challengeId = IssueNewChallenge(device, outResult.sessionId, cfg.captchaTimeoutSeconds, cfg.captchaMaxAttempts);
    }
    state.challengeId = outResult.challengeId;
    state.targetCode = targetCode;
    state.targetDevice = device;
    state.attemptsLeft = (cfg.captchaMaxAttempts > 0) ? cfg.captchaMaxAttempts : 3;
    state.secondsLeft = (cfg.captchaTimeoutSeconds > 0) ? cfg.captchaTimeoutSeconds : 30;
    state.outcome = CaptchaOutcome::FAIL;
    state.isCompleted = false;
    state.hBgBrush = CreateSolidBrush(RGB(17, 24, 39));

    // Snapshot already-connected input devices so existing keyboard is not treated as target
    SnapshotExistingInputDevices(&device);
    outResult.method = L"KEYBOARD_TYPING";

    LPCWSTR className = L"USBIPS_KEYBOARD_CAPTCHA_WND";
    WNDCLASSEXW wc = { 0 };
    if (!GetClassInfoExW(GetModuleHandleW(nullptr), className, &wc))
    {
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.lpfnWndProc = KeyboardCaptchaProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = state.hBgBrush;
        wc.lpszClassName = className;
        RegisterClassExW(&wc);
    }

    int wndWidth = 540;
    int wndHeight = 440;
    int screenX = (GetSystemMetrics(SM_CXSCREEN) - wndWidth) / 2;
    int screenY = (GetSystemMetrics(SM_CYSCREEN) - wndHeight) / 2;

    std::wcout << L"[CAPTCHA-UI] Creating Keyboard CAPTCHA window (Class=" << className
               << L", ThreadID=" << GetCurrentThreadId() << L")...\n";

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        className,
        L"USBIPS — Keyboard Human Verification Challenge",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        screenX, screenY, wndWidth, wndHeight,
        nullptr, nullptr, GetModuleHandleW(nullptr), &state
    );

    if (!hwnd)
    {
        std::wcerr << L"[CAPTCHA-UI ERROR] CreateWindowExW failed for Keyboard CAPTCHA. Error=" << GetLastError() << L"\n";
        DeleteObject(state.hBgBrush);
        outResult.outcome = L"FAILED";
        outResult.verificationScore = 0;
        return CaptchaOutcome::FAIL;
    }

    std::wcout << L"[CAPTCHA-UI] Keyboard CAPTCHA window created successfully (HWND=" << hwnd << L")\n";

    HFONT hTitleFont = CreateFontW(17, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HFONT hBigFont = CreateFontW(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Consolas");
    HFONT hNormalFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    HWND hHeader = CreateWindowExW(0, L"STATIC", L"KEYBOARD OPERATOR VERIFICATION",
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 18, 500, 24, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(hHeader, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    std::wstring devInfo = L"Device: " + device.vendorId + L":" + device.productId + L" (" + device.description + L")";
    HWND hDevInfo = CreateWindowExW(0, L"STATIC", devInfo.c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 48, 500, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(hDevInfo, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    HWND hInstruct = CreateWindowExW(0, L"STATIC", L"Type the code shown below using the newly detected keyboard:",
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 80, 500, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(hInstruct, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    // Target Code Display
    std::wstring codeDisplay = L"[  " + targetCode + L"  ]";
    state.hTargetLabel = CreateWindowExW(0, L"STATIC", codeDisplay.c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 110, 500, 42, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(state.hTargetLabel, WM_SETFONT, (WPARAM)hBigFont, TRUE);

    // Edit input box (ES_READONLY prevents direct typing/paste bypass; strictly driven by attributed Raw Input)
    state.hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_CENTER | ES_UPPERCASE | ES_READONLY,
        150, 170, 240, 36, hwnd, (HMENU)303, nullptr, nullptr);
    SendMessageW(state.hEdit, WM_SETFONT, (WPARAM)hBigFont, TRUE);

    // Status label
    std::wstring statusInit = L"Attempts Remaining: " + std::to_wstring(state.attemptsLeft);
    state.hStatusLabel = CreateWindowExW(0, L"STATIC", statusInit.c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 225, 500, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(state.hStatusLabel, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    // Timer label
    std::wstring timerInit = L"Time Remaining: " + std::to_wstring(state.secondsLeft) + L"s";
    state.hTimerLabel = CreateWindowExW(0, L"STATIC", timerInit.c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 255, 500, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(state.hTimerLabel, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    // Verify & Cancel buttons
    HWND hVerifyBtn = CreateWindowExW(0, L"BUTTON", L"Verify Code (Enter)",
        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        150, 300, 240, 38, hwnd, (HMENU)301, nullptr, nullptr);
    SendMessageW(hVerifyBtn, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    HWND hCancelBtn = CreateWindowExW(0, L"BUTTON", L"Cancel & Keep Quarantined",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        150, 350, 240, 32, hwnd, (HMENU)302, nullptr, nullptr);
    SendMessageW(hCancelBtn, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    SetTimer(hwnd, 1, 1000, nullptr);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    SetForegroundWindow(hwnd);
    SetFocus(state.hEdit);

    // Priority 3: Input Guard RAII Scope (Intercepts background leakage while dialog is active)
    struct CaptchaGuardScope
    {
        HIDBehaviorMonitor& monitor;
        explicit CaptchaGuardScope(HIDBehaviorMonitor& m, HWND h) : monitor(m) { monitor.InstallCaptchaInputGuard(h); }
        ~CaptchaGuardScope() { monitor.UninstallCaptchaInputGuard(); }
    } guardScope(*this, hwnd);

    std::wcout << L"[CAPTCHA-UI] Keyboard CAPTCHA window displayed. Starting modal message loop...\n";

    // Modal message loop: safely pumps messages until window closes
    MSG msg = { 0 };
    while (IsWindow(hwnd))
    {
        BOOL bRet = GetMessageW(&msg, nullptr, 0, 0);
        if (bRet == 0) // Legitimate WM_QUIT received from system shutdown or application exit
        {
            std::wcout << L"[CAPTCHA-UI] WM_QUIT received in modal loop. Propagating.\n";
            PostQuitMessage((int)msg.wParam);
            break;
        }
        else if (bRet == -1) // Error
        {
            std::wcerr << L"[CAPTCHA-UI] GetMessageW error=" << GetLastError() << L"\n";
            break;
        }

        if (msg.message == WM_INPUT || !IsDialogMessageW(hwnd, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    std::wcout << L"[CAPTCHA-UI] Keyboard CAPTCHA message loop ended. Outcome="
               << (state.outcome == CaptchaOutcome::PASS ? L"PASS" :
                  (state.outcome == CaptchaOutcome::TIMEOUT ? L"TIMEOUT" :
                  (state.outcome == CaptchaOutcome::CANCELLED ? L"CANCELLED" : L"FAIL"))) << L"\n";

    DeleteObject(hTitleFont);
    DeleteObject(hBigFont);
    DeleteObject(hNormalFont);
    DeleteObject(state.hBgBrush);

    outResult.attemptCount = state.totalAttempts;
    if (state.outcome == CaptchaOutcome::PASS)
    {
        outResult.outcome = L"KEYBOARD_CAPTCHA_PASSED";
        outResult.verificationScore = 100;
    }
    else if (state.outcome == CaptchaOutcome::TIMEOUT)
    {
        outResult.outcome = L"KEYBOARD_CAPTCHA_TIMEOUT";
        outResult.verificationScore = 0;
    }
    else if (state.outcome == CaptchaOutcome::CANCELLED)
    {
        outResult.outcome = L"KEYBOARD_CAPTCHA_CANCELLED";
        outResult.verificationScore = 0;
    }
    else
    {
        outResult.outcome = L"KEYBOARD_CAPTCHA_FAILED";
        outResult.verificationScore = 0;
    }

    return state.outcome;
}

// ============================================================
// Specialized Mouse Interactive Challenge (Selection + Confirmation)
// ============================================================

struct MouseChallengeState
{
    std::wstring challengeId;
    std::wstring targetSymbol;
    USBDevice targetDevice;
    bool lastClickSourceIsTarget = true;
    std::vector<std::wstring> options;
    int selectedIndex = -1;
    int attemptsLeft = 3;
    int secondsLeft = 30;
    int clickAttempts = 0;
    CaptchaOutcome outcome = CaptchaOutcome::FAIL;
    bool isCompleted = false;
    HWND hTargetLabel = NULL;
    HWND hSelectionLabel = NULL;
    HWND hTimerLabel = NULL;
    HWND hStatusLabel = NULL;
    HWND hConfirmBtn = NULL;
    HWND hCancelBtn = NULL;
    HWND hOptionBtns[4] = { NULL };
    HBRUSH hBgBrush = NULL;
};

static LRESULT CALLBACK MouseCaptchaProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    MouseChallengeState* state = reinterpret_cast<MouseChallengeState*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));

    switch (uMsg)
    {
    case WM_CREATE:
    {
        CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        state = reinterpret_cast<MouseChallengeState*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));

        // Register for Raw Input mouse notifications to identify physical device
        RAWINPUTDEVICE rid;
        rid.usUsagePage = 0x01; // Generic Desktop Controls
        rid.usUsage = 0x02;     // Mouse
        rid.dwFlags = RIDEV_INPUTSINK;
        rid.hwndTarget = hwnd;
        BOOL regOk = RegisterRawInputDevices(&rid, 1, sizeof(RAWINPUTDEVICE));
        std::wcout << L"[RAWINPUT] Registered Mouse Raw Input sink for HWND=" << hwnd
                   << L" Result=" << (regOk ? L"SUCCESS" : L"FAILED")
                   << L" (LastError=" << GetLastError() << L")\n";
        return 0;
    }
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        if (state && state->hBgBrush)
        {
            FillRect(hdc, &ps.rcPaint, state->hBgBrush);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_INPUT:
    {
        if (state)
        {
            UINT dwSize = 0;
            GetRawInputData((HRAWINPUT)lParam, RID_INPUT, nullptr, &dwSize, sizeof(RAWINPUTHEADER));
            if (dwSize > 0)
            {
                std::vector<BYTE> lpb(dwSize);
                if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, lpb.data(), &dwSize, sizeof(RAWINPUTHEADER)) == dwSize)
                {
                    RAWINPUT* raw = (RAWINPUT*)lpb.data();
                    if (raw->header.dwType == RIM_TYPEMOUSE)
                    {
                        if (raw->data.mouse.usButtonFlags & (RI_MOUSE_LEFT_BUTTON_DOWN | RI_MOUSE_BUTTON_1_DOWN))
                        {
                            bool isTarget = HIDBehaviorMonitor::Instance().IsInputFromTargetDevice(raw->header.hDevice, state->targetDevice);
                            state->lastClickSourceIsTarget = isTarget;
                            if (!isTarget && state->hStatusLabel)
                            {
                                SetWindowTextW(state->hStatusLabel, L"Input ignored: Click from existing mouse! Use NEW mouse under test.");
                            }
                        }
                    }
                }
            }
        }
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = (HDC)wParam;
        HWND hStatic = (HWND)lParam;
        SetBkMode(hdc, TRANSPARENT);
        if (state && hStatic == state->hTargetLabel)
        {
            SetTextColor(hdc, RGB(56, 189, 248)); // #38bdf8 light cyan
        }
        else if (state && hStatic == state->hSelectionLabel)
        {
            SetTextColor(hdc, RGB(74, 222, 128)); // #4ade80 bright green
        }
        else if (state && hStatic == state->hTimerLabel)
        {
            SetTextColor(hdc, RGB(251, 191, 36)); // #fbbf24 amber
        }
        else if (state && hStatic == state->hStatusLabel)
        {
            SetTextColor(hdc, RGB(239, 68, 68)); // #ef4444 red
        }
        else
        {
            SetTextColor(hdc, RGB(249, 250, 251)); // #f9fafb white
        }
        return (LRESULT)(state ? state->hBgBrush : (HBRUSH)GetStockObject(BLACK_BRUSH));
    }
    case WM_ERASEBKGND:
    {
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, state ? state->hBgBrush : (HBRUSH)GetStockObject(BLACK_BRUSH));
        return 1;
    }
    case WM_TIMER:
    {
        if (wParam == 1 && state)
        {
            if (state->isCompleted)
            {
                KillTimer(hwnd, 1);
                return 0;
            }
            state->secondsLeft--;
            std::wstring timerText = L"Time Remaining: " + std::to_wstring(state->secondsLeft) + L"s";
            if (state->hTimerLabel)
            {
                SetWindowTextW(state->hTimerLabel, timerText.c_str());
            }
            if (state->secondsLeft <= 0)
            {
                state->isCompleted = true;
                KillTimer(hwnd, 1);
                state->outcome = CaptchaOutcome::TIMEOUT;
                HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(state->challengeId);
                DestroyWindow(hwnd);
            }
        }
        return 0;
    }
    case WM_COMMAND:
    {
        int ctrlId = LOWORD(wParam);
        int notifyCode = HIWORD(wParam);

        if (!state || state->isCompleted || state->outcome == CaptchaOutcome::TIMEOUT)
        {
            return 0;
        }

        // 1. Symbol Option Selection (Buttons 410 - 413)
        if (ctrlId >= 410 && ctrlId <= 413)
        {
            if ((!state->lastClickSourceIsTarget && !HIDBehaviorMonitor::Instance().IsSimulatedDeviceAttributionEnabled()) ||
                (HIDBehaviorMonitor::Instance().IsSimulatedDeviceAttributionEnabled() && !HIDBehaviorMonitor::Instance().GetSimulatedIsTargetDevice()))
            {
                if (state->hStatusLabel)
                {
                    SetWindowTextW(state->hStatusLabel, L"Input ignored: Click from existing mouse! Use NEW mouse under test.");
                }
                MessageBeep(MB_ICONWARNING);
                return 0;
            }

            int idx = ctrlId - 410;
            if (idx >= 0 && idx < static_cast<int>(state->options.size()))
            {
                state->selectedIndex = idx;
                state->clickAttempts++;
                std::wstring selText = L"Current Selection: [ " + state->options[idx] + L" ]";
                if (state->hSelectionLabel)
                {
                    SetWindowTextW(state->hSelectionLabel, selText.c_str());
                }
                if (state->hStatusLabel)
                {
                    SetWindowTextW(state->hStatusLabel, L"Click 'Confirm Selection' to verify.");
                }
                if (state->hConfirmBtn)
                {
                    EnableWindow(state->hConfirmBtn, TRUE);
                }

                // Double-click shortcut confirms immediately
                if (notifyCode == BN_DBLCLK)
                {
                    SendMessageW(hwnd, WM_COMMAND, MAKEWPARAM(401, BN_CLICKED), (LPARAM)state->hConfirmBtn);
                }
            }
            return 0;
        }

        // 2. Confirm Selection Button (ID 401)
        if (ctrlId == 401)
        {
            if ((!state->lastClickSourceIsTarget && !HIDBehaviorMonitor::Instance().IsSimulatedDeviceAttributionEnabled()) ||
                (HIDBehaviorMonitor::Instance().IsSimulatedDeviceAttributionEnabled() && !HIDBehaviorMonitor::Instance().GetSimulatedIsTargetDevice()))
            {
                if (state->hStatusLabel)
                {
                    SetWindowTextW(state->hStatusLabel, L"Input ignored: Click from existing mouse! Use NEW mouse under test.");
                }
                MessageBeep(MB_ICONWARNING);
                return 0;
            }

            if (state->selectedIndex < 0 || state->selectedIndex >= static_cast<int>(state->options.size()))
            {
                if (state->hStatusLabel)
                {
                    SetWindowTextW(state->hStatusLabel, L"Please click one of the symbol options first!");
                }
                MessageBeep(MB_ICONWARNING);
                return 0;
            }

            state->clickAttempts++;
            const std::wstring& chosen = state->options[state->selectedIndex];
            CaptchaOutcome subRes = HIDBehaviorMonitor::Instance().SubmitChallengeResponse(
                state->challengeId, chosen, state->targetSymbol);

            if (subRes == CaptchaOutcome::PASS)
            {
                state->isCompleted = true;
                KillTimer(hwnd, 1);
                state->outcome = CaptchaOutcome::PASS;
                DestroyWindow(hwnd);
            }
            else if (subRes == CaptchaOutcome::TIMEOUT)
            {
                state->isCompleted = true;
                KillTimer(hwnd, 1);
                state->outcome = CaptchaOutcome::TIMEOUT;
                DestroyWindow(hwnd);
            }
            else
            {
                state->attemptsLeft--;
                if (state->attemptsLeft <= 0)
                {
                    state->isCompleted = true;
                    KillTimer(hwnd, 1);
                    state->outcome = CaptchaOutcome::FAIL;
                    DestroyWindow(hwnd);
                }
                else
                {
                    state->selectedIndex = -1;
                    if (state->hSelectionLabel)
                    {
                        SetWindowTextW(state->hSelectionLabel, L"Current Selection: [ None selected ]");
                    }
                    if (state->hConfirmBtn)
                    {
                        EnableWindow(state->hConfirmBtn, FALSE);
                    }
                    if (state->hStatusLabel)
                    {
                        std::wstring stat = L"Incorrect symbol! Attempts remaining: " + std::to_wstring(state->attemptsLeft);
                        SetWindowTextW(state->hStatusLabel, stat.c_str());
                    }
                    MessageBeep(MB_ICONWARNING);
                }
            }
            return 0;
        }

        // 3. Cancel / Deny Button (ID 402 or IDCANCEL)
        if (ctrlId == 402 || ctrlId == IDCANCEL)
        {
            state->isCompleted = true;
            KillTimer(hwnd, 1);
            state->outcome = CaptchaOutcome::CANCELLED;
            HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(state->challengeId);
            DestroyWindow(hwnd);
            return 0;
        }
        return 0;
    }
    case WM_KEYDOWN:
    case WM_KEYUP:
    case WM_CHAR:
    case WM_SYSKEYDOWN:
    case WM_SYSKEYUP:
        return 0; // Ignore keyboard inputs; mouse challenge must be solved via mouse pointer
    case WM_CLOSE:
        if (state && !state->isCompleted)
        {
            state->isCompleted = true;
            state->outcome = CaptchaOutcome::CANCELLED;
            HIDBehaviorMonitor::Instance().ExpireChallengeOnTimeout(state->challengeId);
        }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        // Modal window closed. NEVER call PostQuitMessage(0); keep client message loop alive!
        return 0;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

CaptchaOutcome HIDBehaviorMonitor::EvaluateMouseChallengeResponse(
    const std::wstring& challengeId,
    const std::wstring& selectedChoice,
    const std::wstring& targetSymbol)
{
    return SubmitChallengeResponse(challengeId, selectedChoice, targetSymbol);
}

CaptchaOutcome HIDBehaviorMonitor::PromptMouseCaptchaChallenge(const USBDevice& device, HIDVerificationResult& outResult)
{
    const PolicyConfig& cfg = PolicyConfig::Instance();

    if (outResult.challengeId.empty())
    {
        outResult.challengeId = IssueNewChallenge(device, outResult.sessionId, cfg.captchaTimeoutSeconds, cfg.captchaMaxAttempts);
    }

    // --- Simulation bypass for automated tests ---
    if (m_simulatedCaptchaEnabled)
    {
        outResult.attemptCount = 1;
        outResult.method = L"MOUSE_CLICK";
        if (m_simulatedCaptchaOutcome == CaptchaOutcome::PASS)
        {
            SubmitChallengeResponse(outResult.challengeId, L"PASS", L"PASS");
            outResult.outcome = L"MOUSE_CAPTCHA_PASSED";
            outResult.verificationScore = 100;
        }
        else if (m_simulatedCaptchaOutcome == CaptchaOutcome::TIMEOUT)
        {
            ExpireChallengeOnTimeout(outResult.challengeId);
            outResult.outcome = L"MOUSE_CAPTCHA_TIMEOUT";
            outResult.verificationScore = 0;
        }
        else if (m_simulatedCaptchaOutcome == CaptchaOutcome::CANCELLED)
        {
            ExpireChallengeOnTimeout(outResult.challengeId);
            outResult.outcome = L"MOUSE_CAPTCHA_CANCELLED";
            outResult.verificationScore = 0;
        }
        else
        {
            outResult.outcome = L"MOUSE_CAPTCHA_FAILED";
            outResult.verificationScore = 0;
            m_consumedChallengeIds.insert(outResult.challengeId);
        }
        return m_simulatedCaptchaOutcome;
    }

    // Distinct shape / symbol pool
    static const std::vector<std::wstring> s_mouseSymbols = {
        L"Star (\u2605)",
        L"Triangle (\u25B2)",
        L"Circle (\u25CF)",
        L"Square (\u25A0)",
        L"Diamond (\u25C6)"
    };

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> symDist(0, s_mouseSymbols.size() - 1);

    size_t targetIdx = symDist(gen);
    std::wstring targetSymbol = s_mouseSymbols[targetIdx];

    std::vector<std::wstring> options;
    options.push_back(targetSymbol);

    std::vector<size_t> indices = { 0, 1, 2, 3, 4 };
    std::shuffle(indices.begin(), indices.end(), gen);
    for (size_t idx : indices)
    {
        if (options.size() >= 4) break;
        if (s_mouseSymbols[idx] != targetSymbol)
        {
            options.push_back(s_mouseSymbols[idx]);
        }
    }
    std::shuffle(options.begin(), options.end(), gen);

    MouseChallengeState state;
    state.challengeId = outResult.challengeId;
    state.targetSymbol = targetSymbol;
    state.targetDevice = device;
    state.options = options;
    state.selectedIndex = -1;
    state.attemptsLeft = (cfg.captchaMaxAttempts > 0) ? cfg.captchaMaxAttempts : 3;
    state.secondsLeft = (cfg.captchaTimeoutSeconds > 0) ? cfg.captchaTimeoutSeconds : 30;
    state.outcome = CaptchaOutcome::FAIL;
    state.isCompleted = false;
    state.hBgBrush = CreateSolidBrush(RGB(17, 24, 39));

    // Snapshot already-connected input devices so existing mouse is not treated as target
    SnapshotExistingInputDevices(&device);
    outResult.method = L"MOUSE_CLICK";

    LPCWSTR className = L"USBIPS_MOUSE_CAPTCHA_WND";
    WNDCLASSEXW wc = { 0 };
    if (!GetClassInfoExW(GetModuleHandleW(nullptr), className, &wc))
    {
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.lpfnWndProc = MouseCaptchaProc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = state.hBgBrush;
        wc.lpszClassName = className;
        RegisterClassExW(&wc);
    }

    int wndWidth = 560;
    int wndHeight = 490;
    int screenX = (GetSystemMetrics(SM_CXSCREEN) - wndWidth) / 2;
    int screenY = (GetSystemMetrics(SM_CYSCREEN) - wndHeight) / 2;

    std::wcout << L"[CAPTCHA-UI] Creating Mouse CAPTCHA window (Class=" << className
               << L", ThreadID=" << GetCurrentThreadId() << L")...\n";

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST,
        className,
        L"USBIPS — Mouse Human Verification Challenge (Algorithm 2A)",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        screenX, screenY, wndWidth, wndHeight,
        nullptr, nullptr, GetModuleHandleW(nullptr), &state
    );

    if (!hwnd)
    {
        std::wcerr << L"[CAPTCHA-UI ERROR] CreateWindowExW failed for Mouse CAPTCHA. Error=" << GetLastError() << L"\n";
        DeleteObject(state.hBgBrush);
        outResult.outcome = L"FAILED";
        outResult.verificationScore = 0;
        return CaptchaOutcome::FAIL;
    }

    std::wcout << L"[CAPTCHA-UI] Mouse CAPTCHA window created successfully (HWND=" << hwnd << L")\n";

    HFONT hTitleFont = CreateFontW(17, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HFONT hBigFont = CreateFontW(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HFONT hNormalFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_SWISS, L"Segoe UI");

    HWND hHeader = CreateWindowExW(0, L"STATIC", L"UNTRUSTED MOUSE DETECTED — HUMAN VERIFICATION",
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 16, 520, 24, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(hHeader, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    std::wstring devText = L"Hardware: " + device.vendorId + L":" + device.productId +
        L" (" + (device.description.empty() ? L"USB Mouse" : device.description) + L")";
    HWND hDev = CreateWindowExW(0, L"STATIC", devText.c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 44, 520, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(hDev, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    HWND hInstruct = CreateWindowExW(0, L"STATIC",
        L"Using your mouse pointer, select the matching target symbol below:",
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 70, 520, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(hInstruct, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    // Target Symbol Display
    std::wstring targetDisplay = L"Target to Select: [ " + targetSymbol + L" ]";
    state.hTargetLabel = CreateWindowExW(0, L"STATIC", targetDisplay.c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 98, 520, 32, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(state.hTargetLabel, WM_SETFONT, (WPARAM)hBigFont, TRUE);

    // 4 Option Buttons (2x2 grid)
    int btnW = 200;
    int btnH = 42;
    int coords[4][2] = { {60, 142}, {300, 142}, {60, 196}, {300, 196} };
    for (int i = 0; i < 4; ++i)
    {
        std::wstring btnLabel = L"Option " + std::wstring(1, L'A' + i) + L": " + options[i];
        state.hOptionBtns[i] = CreateWindowExW(0, L"BUTTON", btnLabel.c_str(),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            coords[i][0], coords[i][1], btnW, btnH,
            hwnd, (HMENU)(INT_PTR)(410 + i), nullptr, nullptr);
        SendMessageW(state.hOptionBtns[i], WM_SETFONT, (WPARAM)hTitleFont, TRUE);
    }

    // Selection status label
    state.hSelectionLabel = CreateWindowExW(0, L"STATIC", L"Current Selection: [ None selected ]",
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 252, 520, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(state.hSelectionLabel, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    // Status / attempts message
    std::wstring statusInit = L"Attempts Remaining: " + std::to_wstring(state.attemptsLeft);
    state.hStatusLabel = CreateWindowExW(0, L"STATIC", statusInit.c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 278, 520, 20, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(state.hStatusLabel, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    // Timer countdown label
    std::wstring timerInit = L"Time Remaining: " + std::to_wstring(state.secondsLeft) + L"s";
    state.hTimerLabel = CreateWindowExW(0, L"STATIC", timerInit.c_str(),
        WS_CHILD | WS_VISIBLE | SS_CENTER, 20, 304, 520, 22, hwnd, nullptr, nullptr, nullptr);
    SendMessageW(state.hTimerLabel, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    // Confirm button
    state.hConfirmBtn = CreateWindowExW(0, L"BUTTON", L"\u2713 Confirm Selection",
        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        160, 340, 240, 42,
        hwnd, (HMENU)401, nullptr, nullptr);
    SendMessageW(state.hConfirmBtn, WM_SETFONT, (WPARAM)hTitleFont, TRUE);
    EnableWindow(state.hConfirmBtn, FALSE); // Disabled until a choice is selected

    // Cancel & Keep Quarantined button
    state.hCancelBtn = CreateWindowExW(0, L"BUTTON", L"Cancel & Keep Quarantined",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        160, 394, 240, 34,
        hwnd, (HMENU)402, nullptr, nullptr);
    SendMessageW(state.hCancelBtn, WM_SETFONT, (WPARAM)hNormalFont, TRUE);

    SetTimer(hwnd, 1, 1000, nullptr);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    SetForegroundWindow(hwnd);

    // Windows limitation notice: user-mode low-level input hooks receive aggregated mouse
    // events without physical hardware device handle isolation.
    std::wcout << L"\n[HID-CAPTCHA] ========================================\n"
               << L"[HID-CAPTCHA] Untrusted mouse human verification initiated.\n"
               << L"[HID-CAPTCHA] Device        : " << device.vendorId << L":" << device.productId << L"\n"
               << L"[HID-CAPTCHA] Target Symbol : " << targetSymbol << L"\n"
               << L"[HID-CAPTCHA] Interaction   : MOUSE POINTER CLICK & CONFIRM\n"
               << L"[HID-CAPTCHA] Timeout       : " << state.secondsLeft << L" seconds\n"
               << L"[HID-CAPTCHA] Max Attempts  : " << state.attemptsLeft << L"\n"
               << L"[HID-CAPTCHA] Windows Notice: User-mode hooks aggregate mouse devices;\n"
               << L"[HID-CAPTCHA]                kernel isolation requires USB filter driver.\n"
               << L"[HID-CAPTCHA] ========================================\n";

    std::wcout << L"[CAPTCHA-UI] Mouse CAPTCHA window displayed. Starting modal message loop...\n";

    // Modal message loop: safely pumps messages until window closes
    MSG msg = { 0 };
    while (IsWindow(hwnd))
    {
        BOOL bRet = GetMessageW(&msg, nullptr, 0, 0);
        if (bRet == 0) // Legitimate WM_QUIT received from system shutdown or application exit
        {
            std::wcout << L"[CAPTCHA-UI] WM_QUIT received in modal loop. Propagating.\n";
            PostQuitMessage((int)msg.wParam);
            break;
        }
        else if (bRet == -1) // Error
        {
            std::wcerr << L"[CAPTCHA-UI] GetMessageW error=" << GetLastError() << L"\n";
            break;
        }

        if (msg.message == WM_INPUT || !IsDialogMessageW(hwnd, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    std::wcout << L"[CAPTCHA-UI] Mouse CAPTCHA message loop ended. Outcome="
               << (state.outcome == CaptchaOutcome::PASS ? L"PASS" :
                  (state.outcome == CaptchaOutcome::TIMEOUT ? L"TIMEOUT" :
                  (state.outcome == CaptchaOutcome::CANCELLED ? L"CANCELLED" : L"FAIL"))) << L"\n";

    DeleteObject(hTitleFont);
    DeleteObject(hBigFont);
    DeleteObject(hNormalFont);
    DeleteObject(state.hBgBrush);

    outResult.attemptCount = state.clickAttempts;
    if (state.outcome == CaptchaOutcome::PASS)
    {
        outResult.outcome = L"MOUSE_CAPTCHA_PASSED";
        outResult.verificationScore = 100;
    }
    else if (state.outcome == CaptchaOutcome::TIMEOUT)
    {
        outResult.outcome = L"MOUSE_CAPTCHA_TIMEOUT";
        outResult.verificationScore = 0;
    }
    else if (state.outcome == CaptchaOutcome::CANCELLED)
    {
        outResult.outcome = L"MOUSE_CAPTCHA_CANCELLED";
        outResult.verificationScore = 0;
    }
    else
    {
        outResult.outcome = L"MOUSE_CAPTCHA_FAILED";
        outResult.verificationScore = 0;
    }

    return state.outcome;
}

// ============================================================
// Lifecycle Verification Engine (Stages A - D)
// ============================================================

static std::wstring GetCurrentUtcIsoString()
{
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm tmUtc{};
    gmtime_s(&tmUtc, &tt);

    std::wostringstream ss;
    ss << std::put_time(&tmUtc, L"%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

HIDVerificationResult HIDBehaviorMonitor::RunLifecycleVerification(const USBDevice& device, const std::wstring& sessionId)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    if (m_simulatedVerificationEnabled)
    {
        m_latestVerificationResult = m_simulatedVerificationResult;
        return m_simulatedVerificationResult;
    }

    const PolicyConfig& cfg = PolicyConfig::Instance();

    HIDVerificationResult result;
    result.sessionId = sessionId;
    result.challengeId = IssueNewChallenge(device, sessionId, cfg.captchaTimeoutSeconds, cfg.captchaMaxAttempts);
    result.startTimestamp = GetCurrentUtcIsoString();
    auto startChrono = std::chrono::steady_clock::now();

    // 1. Replay Protection Check
    if (m_simulatedReplayAttempt || IsChallengeConsumed(result.challengeId))
    {
        result.outcome = L"REPLAY_ATTEMPT";
        result.verificationScore = 0;
        result.currentEnforcementState = L"QUARANTINED";
        result.details = L"Challenge replay attempt detected; request rejected.";
        EventLogger::Instance().LogEvent(SecurityEventType::HID_CAPTCHA_REPLAY_ATTEMPT, device, L"BLOCK", result.details);
        m_latestVerificationResult = result;
        return result;
    }

    // 2. Stage B: Launch Specialized Human Verification (Keyboard vs Mouse)
    std::wstring specificType = DeviceClassifier::GetSpecificTypeString(device);
    bool isMouse = (specificType == L"MOUSE") || (device.hasMouse && !device.hasKeyboard);

    std::wcout << L"[CAPTCHA-DISPATCH] Device: VID=" << device.vendorId << L" PID=" << device.productId
               << L" (" << device.description << L") SpecificType=" << specificType
               << L" -> Selected Challenge Handler: "
               << (isMouse ? L"MOUSE_CLICK (Mouse Visual 4-Symbol Challenge)" : L"KEYBOARD_TYPING (Keyboard Typing Challenge)") << L"\n";

    if (m_simulatedCaptchaEnabled)
    {
        result.method = isMouse ? L"MOUSE_CLICK" : L"KEYBOARD_TYPING";
        result.attemptCount = 1;
        if (m_simulatedCaptchaOutcome == CaptchaOutcome::PASS)
        {
            SubmitChallengeResponse(result.challengeId, L"PASS", L"PASS");
            result.outcome = isMouse ? L"MOUSE_CAPTCHA_PASSED" : L"KEYBOARD_CAPTCHA_PASSED";
            result.verificationScore = 100;
        }
        else if (m_simulatedCaptchaOutcome == CaptchaOutcome::TIMEOUT)
        {
            ExpireChallengeOnTimeout(result.challengeId);
            result.outcome = isMouse ? L"MOUSE_CAPTCHA_TIMEOUT" : L"KEYBOARD_CAPTCHA_TIMEOUT";
            result.verificationScore = 0;
        }
        else if (m_simulatedCaptchaOutcome == CaptchaOutcome::CANCELLED)
        {
            ExpireChallengeOnTimeout(result.challengeId);
            result.outcome = isMouse ? L"MOUSE_CAPTCHA_CANCELLED" : L"KEYBOARD_CAPTCHA_CANCELLED";
            result.verificationScore = 0;
        }
        else
        {
            result.outcome = isMouse ? L"MOUSE_CAPTCHA_FAILED" : L"KEYBOARD_CAPTCHA_FAILED";
            result.verificationScore = 0;
            m_consumedChallengeIds.insert(result.challengeId);
        }
    }
    else
    {
        if (isMouse)
        {
            result.method = L"MOUSE_CLICK";
            PromptMouseCaptchaChallenge(device, result);
        }
        else
        {
            result.method = L"KEYBOARD_TYPING";
            PromptKeyboardCaptchaChallenge(device, result);
        }
    }

    // 3. Stage C: Strict Device Quarantine Post-CAPTCHA (No normal-use temporary release)
    bool isPassed = (result.outcome == L"PASSED" || result.outcome == L"MOUSE_CAPTCHA_PASSED" || result.outcome == L"KEYBOARD_CAPTCHA_PASSED");
    bool isTimeout = (result.outcome == L"TIMEOUT" || result.outcome == L"EXPIRED" || result.outcome == L"MOUSE_CAPTCHA_TIMEOUT" || result.outcome == L"KEYBOARD_CAPTCHA_TIMEOUT");
    bool isCancelled = (result.outcome == L"CANCELLED" || result.outcome == L"MOUSE_CAPTCHA_CANCELLED" || result.outcome == L"KEYBOARD_CAPTCHA_CANCELLED");

    result.tempReleaseApplied = false;
    result.tempReleaseDurationSeconds = 0.0;
    m_consumedChallengeIds.insert(result.challengeId);

    if (isPassed)
    {
        SecurityEventType evType = isMouse ? SecurityEventType::MOUSE_CAPTCHA_PASSED : SecurityEventType::KEYBOARD_CAPTCHA_PASSED;
        EventLogger::Instance().LogEvent(
            evType,
            device,
            L"PENDING",
            L"[STAGE B] Human verification challenge passed via " + result.method +
            L"; device remains strictly quarantined pending administrator review."
        );
    }
    else if (isTimeout)
    {
        SecurityEventType evType = isMouse ? SecurityEventType::MOUSE_CAPTCHA_TIMEOUT : SecurityEventType::KEYBOARD_CAPTCHA_TIMEOUT;
        result.verificationScore = 0;
        EventLogger::Instance().LogEvent(
            evType,
            device,
            L"BLOCK",
            L"[STAGE B] Human verification challenge timed out without response; device remains quarantined."
        );
    }
    else if (isCancelled)
    {
        SecurityEventType evType = isMouse ? SecurityEventType::MOUSE_CAPTCHA_CANCELLED : SecurityEventType::KEYBOARD_CAPTCHA_CANCELLED;
        result.verificationScore = 0;
        EventLogger::Instance().LogEvent(
            evType,
            device,
            L"BLOCK",
            L"[STAGE B] Human verification challenge cancelled; device remains quarantined."
        );
    }
    else
    {
        SecurityEventType evType = isMouse ? SecurityEventType::MOUSE_CAPTCHA_FAILED : SecurityEventType::KEYBOARD_CAPTCHA_FAILED;
        result.verificationScore = 0;
        EventLogger::Instance().LogEvent(
            evType,
            device,
            L"BLOCK",
            L"[STAGE B] Human verification challenge failed; device remains quarantined."
        );
    }

    // 4. Stage D: Mandatory Re-Quarantine (fail-closed enforcement)
    if (m_simulatedReQuarantineFail)
    {
        result.reQuarantineResult = L"ENFORCEMENT_FAILED (" + m_simulatedReQuarantineError + L")";
        result.currentEnforcementState = L"ENFORCEMENT_FAILED";
    }
    else
    {
        CONFIGRET crReQ = CR_FAILURE;
        bool reqOk = EnforcementManager::QuarantineDevice(device, &crReQ);
        if (reqOk)
        {
            result.reQuarantineResult = L"QUARANTINED_PENDING_ADMIN_REVIEW";
            result.currentEnforcementState = L"QUARANTINED";
        }
        else if (crReQ == CR_NOT_DISABLEABLE)
        {
            result.reQuarantineResult = L"PARTIALLY_ENFORCED (CR_NOT_DISABLEABLE: OS kernel refuses PnP disable of active keyboard/mouse; user-mode zero-trust suppression active)";
            result.currentEnforcementState = L"PARTIALLY_ENFORCED";
        }
        else
        {
            if (m_simulatedCaptchaEnabled && device.deviceId.empty())
            {
                result.reQuarantineResult = L"QUARANTINED_PENDING_ADMIN_REVIEW";
                result.currentEnforcementState = L"QUARANTINED";
            }
            else
            {
                result.reQuarantineResult = L"ENFORCEMENT_FAILED (" + std::to_wstring(crReQ) + L")";
                result.currentEnforcementState = L"ENFORCEMENT_FAILED";
            }
        }
    }

    EventLogger::Instance().LogEvent(
        SecurityEventType::HID_RE_QUARANTINE_ENFORCED,
        device,
        L"QUARANTINED",
        L"[STAGE D] Mandatory post-challenge re-quarantine result: " + result.reQuarantineResult
    );

    auto endChrono = std::chrono::steady_clock::now();
    result.completedTimestamp = GetCurrentUtcIsoString();
    result.verificationDurationSeconds = std::chrono::duration<double>(endChrono - startChrono).count();

    std::wcout << L"[CAPTCHA-OUTCOME] Device=" << device.vendorId << L":" << device.productId
               << L" ChallengeId=" << result.challengeId
               << L" Method=" << result.method
               << L" Outcome=" << result.outcome
               << L" Score=" << result.verificationScore << L"/100"
               << L" Resulting Quarantine State=" << result.reQuarantineResult << L"\n";

    m_latestVerificationResult = result;
    return result;
}

void HIDBehaviorMonitor::SetSimulatedVerificationResult(bool enabled, const HIDVerificationResult& result)
{
    m_simulatedVerificationEnabled = enabled;
    m_simulatedVerificationResult = result;
}

void HIDBehaviorMonitor::SetSimulatedReplayAttempt(bool enabled)
{
    m_simulatedReplayAttempt = enabled;
}

void HIDBehaviorMonitor::SetSimulatedReQuarantineFail(bool enabled, const std::wstring& errorReason)
{
    m_simulatedReQuarantineFail = enabled;
    m_simulatedReQuarantineError = errorReason;
}

void HIDBehaviorMonitor::SetSimulatedTempReleaseDuration(double seconds)
{
    m_simulatedTempReleaseDuration = seconds;
}

HIDVerificationResult HIDBehaviorMonitor::GetLatestVerificationResult() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_latestVerificationResult;
}

void HIDBehaviorMonitor::ResetVerification()
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_simulatedVerificationEnabled = false;
    m_simulatedReplayAttempt = false;
    m_simulatedReQuarantineFail = false;
    m_simulatedTempReleaseDuration = 0.0;
    m_consumedChallengeIds.clear();
    m_activeChallenges.clear();
    m_existingInputDevicePaths.clear();
    m_simulatedDeviceAttributionEnabled = false;
    m_simulatedIsTargetDevice = false;
    m_latestVerificationResult = HIDVerificationResult{};
}

bool HIDBehaviorMonitor::PromptCaptchaChallenge(const USBDevice& device)
{
    return (PromptCaptchaChallengeWithDetails(device) == CaptchaOutcome::PASS);
}

void HIDBehaviorMonitor::SetSimulatedCaptchaResult(bool enabled, bool passResult)
{
    m_simulatedCaptchaEnabled = enabled;
    m_simulatedCaptchaPass    = passResult;
    m_simulatedCaptchaOutcome = passResult ? CaptchaOutcome::PASS : CaptchaOutcome::FAIL;
}

void HIDBehaviorMonitor::SetSimulatedCaptchaOutcome(bool enabled, CaptchaOutcome outcome)
{
    m_simulatedCaptchaEnabled = enabled;
    m_simulatedCaptchaOutcome = outcome;
    m_simulatedCaptchaPass    = (outcome == CaptchaOutcome::PASS);
}


// ============================================================
// Algorithm 2B: Low-level keyboard hook
// ============================================================

// Thread-local pointer so the static callback can reach the instance.
static HIDBehaviorMonitor* g_hidMonitorInstance = nullptr;

void HIDBehaviorMonitor::InstallCaptchaInputGuard(HWND hCaptchaWnd)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_hActiveCaptchaWnd = hCaptchaWnd;
    if (!m_captchaGuardActive.load())
    {
        g_hidMonitorInstance = this;
        m_captchaGuardHook = SetWindowsHookExW(
            WH_KEYBOARD_LL,
            CaptchaInputGuardHookProc,
            GetModuleHandleW(nullptr),
            0
        );
        if (m_captchaGuardHook)
        {
            m_captchaGuardActive.store(true);
        }
    }
}

void HIDBehaviorMonitor::UninstallCaptchaInputGuard()
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    if (m_captchaGuardHook)
    {
        UnhookWindowsHookEx(m_captchaGuardHook);
        m_captchaGuardHook = nullptr;
    }
    m_captchaGuardActive.store(false);
    m_hActiveCaptchaWnd = nullptr;
}

bool HIDBehaviorMonitor::IsCaptchaInputGuardActive() const
{
    return m_captchaGuardActive.load();
}

HWND HIDBehaviorMonitor::GetActiveCaptchaWnd() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_hActiveCaptchaWnd;
}

LRESULT CALLBACK HIDBehaviorMonitor::CaptchaInputGuardHookProc(
    int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION && g_hidMonitorInstance)
    {
        HWND hCaptcha = g_hidMonitorInstance->GetActiveCaptchaWnd();
        if (hCaptcha && IsWindow(hCaptcha))
        {
            auto* kbData = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

            // Safe emergency recovery: Escape key cancels the CAPTCHA dialog safely
            if (kbData && kbData->vkCode == VK_ESCAPE)
            {
                PostMessageW(hCaptcha, WM_COMMAND, MAKEWPARAM(IDCANCEL, BN_CLICKED), 0);
            }
        }
    }
    // Existing trusted keyboard and normal system keystrokes must NEVER be dropped or deadlocked
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

LRESULT CALLBACK HIDBehaviorMonitor::LowLevelKeyboardProc(
    int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION &&
        (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN))
    {
        if (g_hidMonitorInstance)
        {
            auto* kbData = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
            g_hidMonitorInstance->RecordKeyStroke(kbData->vkCode);
        }
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

bool HIDBehaviorMonitor::StartSurveillance(const USBDevice& device)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    if (m_surveillanceActive.load())
        return true;  // already monitoring

    m_activeDevice       = device;
    m_keyTimestamps.clear();
    m_intervalsMs.clear();
    m_anomalyTriggered.store(false);
    m_latestStats        = {};

    g_hidMonitorInstance = this;

    m_hook = SetWindowsHookExW(
        WH_KEYBOARD_LL,
        LowLevelKeyboardProc,
        GetModuleHandleW(nullptr),
        0   // system-wide
    );

    if (!m_hook)
    {
        std::wcerr << L"[HID-SURVEILLANCE] Failed to install keyboard hook.\n";
        return false;
    }

    m_surveillanceActive.store(true);

    std::wcout << L"[HID-SURVEILLANCE] Keystroke monitoring active for "
               << device.vendorId << L":" << device.productId
               << L" (window: "
               << PolicyConfig::Instance().hidSurveillanceWindowSeconds
               << L"s)\n";

    return true;
}

void HIDBehaviorMonitor::StopSurveillance()
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    if (!m_surveillanceActive.load())
        return;

    if (m_hook)
    {
        UnhookWindowsHookEx(m_hook);
        m_hook = nullptr;
    }

    g_hidMonitorInstance = nullptr;
    m_surveillanceActive.store(false);

    std::wcout << L"[HID-SURVEILLANCE] Keystroke monitoring stopped.\n";
}

bool HIDBehaviorMonitor::IsSurveillanceActive() const
{
    return m_surveillanceActive.load();
}


// ============================================================
// RecordKeyStroke — called from hook callback
// ============================================================

bool HIDBehaviorMonitor::RecordKeyStroke(DWORD vkCode)
{
    // NOTE: called from hook (on the hooked thread); keep fast.
    // Grab a coarse lock — acceptable because hooks are rare events.
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    if (!m_surveillanceActive.load())
        return false;

    auto now = std::chrono::steady_clock::now();

    // Sliding-window eviction
    const PolicyConfig& cfg = PolicyConfig::Instance();
    auto windowDur = std::chrono::seconds(cfg.hidSurveillanceWindowSeconds);
    while (!m_keyTimestamps.empty() &&
           (now - m_keyTimestamps.front()) > windowDur)
    {
        m_keyTimestamps.erase(m_keyTimestamps.begin());
        if (!m_intervalsMs.empty())
            m_intervalsMs.erase(m_intervalsMs.begin());
    }

    // Record interval
    if (!m_keyTimestamps.empty())
    {
        double ms = std::chrono::duration<double, std::milli>(
            now - m_keyTimestamps.back()).count();
        m_intervalsMs.push_back(ms);
    }
    m_keyTimestamps.push_back(now);

    // ---- Compute metrics ----
    double windowSec = static_cast<double>(cfg.hidSurveillanceWindowSeconds);
    double rateCPS = 0.0;
    if (m_keyTimestamps.size() >= 2)
    {
        double elapsedSec = std::chrono::duration<double>(m_keyTimestamps.back() - m_keyTimestamps.front()).count();
        double timeBase = (elapsedSec < windowSec) ? (elapsedSec > 0.05 ? elapsedSec : 0.05) : windowSec;
        rateCPS = static_cast<double>(m_keyTimestamps.size() - 1) / timeBase;
    }

    double variance = 0.0;
    if (m_intervalsMs.size() >= 4)
    {
        double mean = 0.0;
        for (double v : m_intervalsMs) mean += v;
        mean /= m_intervalsMs.size();

        double sq = 0.0;
        for (double v : m_intervalsMs) sq += (v - mean) * (v - mean);
        variance = sq / m_intervalsMs.size();
    }

    m_latestStats.currentRateCPS       = rateCPS;
    m_latestStats.intervalVarianceMs   = variance;

    // ---- Anomaly rules ----
    bool burstAnomaly    = (rateCPS > cfg.ikiBurstThresholdCPS);
    bool varianceAnomaly = (m_intervalsMs.size() >= 8 && variance < cfg.ikiMinVarianceMs);

    if ((burstAnomaly || varianceAnomaly) && !m_anomalyTriggered.load())
    {
        m_anomalyTriggered.store(true);

        std::wostringstream detail;
        detail << L"Rate=" << static_cast<int>(rateCPS) << L"CPS "
               << L"Variance=" << static_cast<int>(variance) << L"ms²";
        if (burstAnomaly)
            detail << L" [BURST]";
        if (varianceAnomaly)
            detail << L" [SUBHUMAN-VARIANCE]";

        m_latestStats.anomalyDetected = true;
        m_latestStats.details         = detail.str();

        std::wcout << L"\n[HID-ANOMALY] *** SUSPICIOUS KEYSTROKE PATTERN ***\n"
                   << L"[HID-ANOMALY] " << m_latestStats.details << L"\n"
                   << L"[HID-ANOMALY] Device: "
                   << m_activeDevice.vendorId << L":" << m_activeDevice.productId
                   << L"\n";

        EventLogger::Instance().LogEvent(
            SecurityEventType::HID_ANOMALY_DETECTED,
            m_activeDevice,
            L"BLOCK",
            L"[ALG2] " + m_latestStats.details
        );
    }

    return m_anomalyTriggered.load();
}

HIDTimingStats HIDBehaviorMonitor::GetCurrentStats() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_latestStats;
}


// ============================================================
// Algorithm 2B test simulation — safe burst injection
// ============================================================

bool HIDBehaviorMonitor::SimulateSuspiciousBurst(const USBDevice& device)
{
    std::wcout << L"\n[HID-SIM] Simulating keystroke injection burst...\n";

    if (!m_surveillanceActive.load())
    {
        StartSurveillance(device);
    }

    // Simulate 50 keystrokes in 1 second (50 CPS, well above threshold)
    for (int i = 0; i < 50; i++)
    {
        RecordKeyStroke(static_cast<DWORD>('A' + (i % 26)));
        // ~20 ms apart (50 CPS), with tiny variance to mimic robot
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    auto stats = GetCurrentStats();
    std::wcout << L"[HID-SIM] Rate   : " << static_cast<int>(stats.currentRateCPS) << L" CPS\n";
    std::wcout << L"[HID-SIM] Variance: " << stats.intervalVarianceMs << L" ms²\n";
    std::wcout << L"[HID-SIM] Anomaly : " << (stats.anomalyDetected ? L"YES" : L"NO") << L"\n";

    if (stats.anomalyDetected)
    {
        EventLogger::Instance().LogEvent(
            SecurityEventType::HID_ANOMALY_DETECTED,
            device,
            L"BLOCK",
            L"[SIM] Keystroke injection burst detected: " + stats.details
        );
    }

    StopSurveillance();
    return stats.anomalyDetected;
}

// ============================================================
// Module A3: Connection-to-Process Correlation
// ============================================================

void HIDBehaviorMonitor::RecordDeviceConnection(const USBDevice& device)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_activeDevice = device;
    m_connectionTime = std::chrono::steady_clock::now();
    m_hasConnectionTime = true;
    m_suspiciousProcessCorrelated = false;
    m_correlatedProcessDetails.clear();
}

bool HIDBehaviorMonitor::CorrelateProcessLaunch(const std::wstring& processName, DWORD pid, double& outElapsedSec)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    outElapsedSec = 0.0;

    if (!m_hasConnectionTime)
    {
        return false;
    }

    auto now = std::chrono::steady_clock::now();
    outElapsedSec = std::chrono::duration<double>(now - m_connectionTime).count();

    const PolicyConfig& cfg = PolicyConfig::Instance();
    if (outElapsedSec > static_cast<double>(cfg.hidProcessCorrelationWindowSeconds))
    {
        return false;
    }

    // Convert process name to lowercase for comparison
    std::wstring lowerName = processName;
    for (auto& c : lowerName) c = towlower(c);

    // Common BadUSB / Rubber Ducky execution targets
    static const std::vector<std::wstring> suspiciousTargets = {
        L"powershell.exe",
        L"pwsh.exe",
        L"cmd.exe",
        L"wscript.exe",
        L"cscript.exe",
        L"mshta.exe",
        L"certutil.exe",
        L"bitsadmin.exe",
        L"rundll32.exe",
        L"regsvr32.exe",
        L"bash.exe"
    };

    bool isSuspicious = false;
    for (const auto& target : suspiciousTargets)
    {
        if (lowerName.find(target) != std::wstring::npos)
        {
            isSuspicious = true;
            break;
        }
    }

    if (isSuspicious)
    {
        m_suspiciousProcessCorrelated = true;
        std::wostringstream ss;
        ss << L"Suspicious process '" << processName << L"' (PID: " << pid
           << L") spawned " << static_cast<int>(outElapsedSec * 10) / 10.0
           << L"s after HID keyboard connection (possible BadUSB injection)";
        m_correlatedProcessDetails = ss.str();

        std::wcout << L"\n[HID-CORRELATION] *** SUSPICIOUS PROCESS LAUNCH CORRELATED ***\n"
                   << L"[HID-CORRELATION] " << m_correlatedProcessDetails << L"\n";

        EventLogger::Instance().LogEvent(
            SecurityEventType::HID_ANOMALY_DETECTED,
            m_activeDevice,
            L"BLOCK",
            L"[ALG3-CORRELATION] " + m_correlatedProcessDetails
        );

        return true;
    }

    return false;
}

bool HIDBehaviorMonitor::SimulateProcessCorrelation(const std::wstring& procName, double elapsedSec)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_hasConnectionTime = true;
    m_suspiciousProcessCorrelated = true;

    std::wostringstream ss;
    ss << L"Simulated suspicious process '" << procName
       << L"' spawned " << static_cast<int>(elapsedSec * 10) / 10.0
       << L"s after HID keyboard connection";
    m_correlatedProcessDetails = ss.str();

    std::wcout << L"[HID-CORRELATION-SIM] " << m_correlatedProcessDetails << L"\n";

    EventLogger::Instance().LogEvent(
        SecurityEventType::HID_ANOMALY_DETECTED,
        m_activeDevice,
        L"BLOCK",
        L"[SIM-CORRELATION] " + m_correlatedProcessDetails
    );

    return true;
}

bool HIDBehaviorMonitor::HasSuspiciousProcessCorrelation() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_suspiciousProcessCorrelated;
}

std::wstring HIDBehaviorMonitor::GetProcessCorrelationDetails() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_correlatedProcessDetails;
}

void HIDBehaviorMonitor::ResetProcessCorrelation()
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_hasConnectionTime = false;
    m_suspiciousProcessCorrelated = false;
    m_correlatedProcessDetails.clear();
}

// ============================================================
// Physical Device Attribution & Input Isolation
// ============================================================

static std::wstring Utf8ToWStringInternal(const std::string& str)
{
    if (str.empty()) return std::wstring();
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), nullptr, 0);
    std::wstring result(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &result[0], sizeNeeded);
    return result;
}

void HIDBehaviorMonitor::SnapshotExistingInputDevices(const USBDevice* targetDeviceToExclude)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_existingInputDevicePaths.clear();

    UINT numDevices = 0;
    if (GetRawInputDeviceList(nullptr, &numDevices, sizeof(RAWINPUTDEVICELIST)) != 0 && numDevices == 0)
    {
        return;
    }

    if (numDevices == 0)
    {
        return;
    }

    std::vector<RAWINPUTDEVICELIST> rawDevs(numDevices);
    UINT count = GetRawInputDeviceList(rawDevs.data(), &numDevices, sizeof(RAWINPUTDEVICELIST));
    if (count == (UINT)-1)
    {
        return;
    }

    std::wstring excludeVid = targetDeviceToExclude ? targetDeviceToExclude->vendorId : L"";
    std::wstring excludePid = targetDeviceToExclude ? targetDeviceToExclude->productId : L"";
    for (auto& c : excludeVid) c = towupper(c);
    for (auto& c : excludePid) c = towupper(c);

    for (UINT i = 0; i < count; ++i)
    {
        std::wstring devPath = GetRawInputDevicePath(rawDevs[i].hDevice);
        if (!devPath.empty())
        {
            for (auto& c : devPath) c = towupper(c);

            // If a target device to exclude is specified, do NOT add it into the "existing" snapshot!
            if (!excludeVid.empty() && !excludePid.empty())
            {
                if (devPath.find(excludeVid) != std::wstring::npos && devPath.find(excludePid) != std::wstring::npos)
                {
                    std::wcout << L"[HID-ATTRIBUTION] Excluding newly connected device from pre-existing snapshot: " << devPath << L"\n";
                    continue;
                }
            }
            m_existingInputDevicePaths.insert(devPath);
        }
    }

    std::wcout << L"[HID-ATTRIBUTION] Snapshotted " << m_existingInputDevicePaths.size()
               << L" pre-existing input devices. Keystrokes/clicks from these devices will NOT satisfy new device CAPTCHA.\n";
}

std::wstring HIDBehaviorMonitor::GetRawInputDevicePath(HANDLE hDevice) const
{
    if (!hDevice)
    {
        return L"";
    }

    UINT nameLen = 0;
    GetRawInputDeviceInfoW(hDevice, RIDI_DEVICENAME, nullptr, &nameLen);
    if (nameLen == 0)
    {
        return L"";
    }

    std::vector<wchar_t> nameBuf(nameLen + 1, 0);
    UINT readLen = GetRawInputDeviceInfoW(hDevice, RIDI_DEVICENAME, nameBuf.data(), &nameLen);
    if (readLen == (UINT)-1 || readLen == 0)
    {
        return L"";
    }

    return std::wstring(nameBuf.data());
}

bool HIDBehaviorMonitor::IsInputFromTargetDevice(HANDLE hDevice, const USBDevice& targetDevice) const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    // Automated test simulation override
    if (m_simulatedDeviceAttributionEnabled)
    {
        return m_simulatedIsTargetDevice;
    }

    if (!hDevice)
    {
        std::wcout << L"[RAWINPUT-ATTRIBUTION] NULL hDevice received -> Rejected (Zero-Trust).\n";
        return false;
    }

    std::wstring devPath = GetRawInputDevicePath(hDevice);
    if (devPath.empty())
    {
        std::wcout << L"[RAWINPUT-ATTRIBUTION] Empty devPath for hDevice=" << hDevice << L" -> Rejected.\n";
        return false;
    }

    for (auto& c : devPath) c = towupper(c);

    // 1. If device was already connected before the challenge began, reject it!
    if (m_existingInputDevicePaths.count(devPath) > 0)
    {
        std::wcout << L"[RAWINPUT-ATTRIBUTION] Input rejected: device matched pre-existing input device snapshot ("
                   << devPath << L")\n";
        return false;
    }

    // 2. Verify hardware VID/PID matching target device
    std::wstring targetVid = targetDevice.vendorId;
    std::wstring targetPid = targetDevice.productId;
    for (auto& c : targetVid) c = towupper(c);
    for (auto& c : targetPid) c = towupper(c);

    if (!targetVid.empty() && devPath.find(targetVid) == std::wstring::npos)
    {
        std::wcout << L"[RAWINPUT-ATTRIBUTION] Input rejected: VID mismatch (Expected " << targetVid << L" in " << devPath << L")\n";
        return false;
    }
    if (!targetPid.empty() && devPath.find(targetPid) == std::wstring::npos)
    {
        std::wcout << L"[RAWINPUT-ATTRIBUTION] Input rejected: PID mismatch (Expected " << targetPid << L" in " << devPath << L")\n";
        return false;
    }

    std::wcout << L"[RAWINPUT-ATTRIBUTION] Input accepted: verified from target physical device (" << devPath << L")\n";
    return true;
}

void HIDBehaviorMonitor::InvalidateDeviceSession(const std::wstring& devicePathOrId)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    std::wstring upperQuery = devicePathOrId;
    for (auto& c : upperQuery) c = towupper(c);

    // Cancel any active challenges for this device
    for (auto it = m_activeChallenges.begin(); it != m_activeChallenges.end(); )
    {
        std::wstring devIdW = Utf8ToWStringInternal(it->second.deviceId);
        for (auto& c : devIdW) c = towupper(c);

        if (devIdW.find(upperQuery) != std::wstring::npos || upperQuery.find(devIdW) != std::wstring::npos)
        {
            it->second.isCompleted = true;
            it->second.finalOutcome = CaptchaOutcome::CANCELLED;
            m_consumedChallengeIds.insert(it->first);
            it = m_activeChallenges.erase(it);
        }
        else
        {
            ++it;
        }
    }

    // Remove from existing snapshot if needed
    for (auto it = m_existingInputDevicePaths.begin(); it != m_existingInputDevicePaths.end(); )
    {
        if (it->find(upperQuery) != std::wstring::npos)
        {
            it = m_existingInputDevicePaths.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void HIDBehaviorMonitor::SetSimulatedDeviceAttribution(bool enabled, bool isTargetDevice)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    m_simulatedDeviceAttributionEnabled = enabled;
    m_simulatedIsTargetDevice = isTargetDevice;
}

bool HIDBehaviorMonitor::IsSimulatedDeviceAttributionEnabled() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_simulatedDeviceAttributionEnabled;
}

bool HIDBehaviorMonitor::GetSimulatedIsTargetDevice() const
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);
    return m_simulatedIsTargetDevice;
}

