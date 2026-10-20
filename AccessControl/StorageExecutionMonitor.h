#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <chrono>

#include "../Models/USBDevice.h"

class AllowlistManager;

struct StorageExecutionViolation
{
    DWORD processId = 0;
    std::wstring processName;
    std::wstring processPath;
    std::wstring removableDrive;
    bool wasTerminated = false;
    std::wstring reason;
    USBDevice responsibleDevice;
};

struct StorageExecutableInspectionResult
{
    enum class Status
    {
        CLEAN,
        PROHIBITED_FOUND,
        NOT_MOUNTED,
        FAILED
    } status = Status::NOT_MOUNTED;

    std::wstring scannedDrive;
    std::wstring primaryProhibitedFile;
    std::vector<std::wstring> allProhibitedFiles;
    std::wstring policyRule;
    std::wstring failureReason;
};

class StorageExecutionMonitor
{
public:
    static StorageExecutionMonitor& Instance()
    {
        static StorageExecutionMonitor instance;
        return instance;
    }

    // Continuous background surveillance
    void StartSurveillance(AllowlistManager* allowlist);
    void StopSurveillance();
    bool IsSurveillanceActive() const;
    void SetAllowlistManager(AllowlistManager* allowlist);

    // Exact volume-to-device attribution
    bool GetUsbDeviceForDrive(const std::wstring& driveLetter, USBDevice& outDevice) const;

    // Enumerates drive letters corresponding specifically to a given USBDevice
    std::vector<std::wstring> GetDriveLettersForDevice(const USBDevice& device) const;

    // Enumerates files on a mapped volume and detects prohibited executable extensions (.exe, .com)
    StorageExecutableInspectionResult InspectVolumeForProhibitedExecutables(const std::wstring& driveLetter) const;

    // Test simulation mappings for deterministic mock tests
    void RegisterDeviceDriveMapping(const std::wstring& deviceId, const std::wstring& driveLetter);
    void ClearDeviceDriveMappings();

    // Mock volume directory mapping for filesystem inspection testing
    void RegisterMockVolumePath(const std::wstring& driveLetter, const std::wstring& realFolderPath);
    void ClearMockVolumePaths();

    // Simulation hooks for unit tests
    void SetSimulatedInspectionResult(
        bool enabled,
        StorageExecutableInspectionResult::Status status = StorageExecutableInspectionResult::Status::CLEAN,
        const std::wstring& primaryFile = L"",
        const std::wstring& policyRule = L"",
        const std::wstring& failureReason = L""
    );
    bool IsSimulationActive() const { return m_simulationEnabled; }

    // Enumerates active drive letters that are removable media (USB storage)
    std::vector<std::wstring> GetRemovableDriveLetters() const;

    // Checks whether a given filesystem path resides on removable media
    bool IsPathOnRemovableStorage(const std::wstring& filePath, std::wstring& outDrive) const;

    // Scans active running processes to detect executables running from removable media
    std::vector<StorageExecutionViolation> ScanRunningProcesses(bool terminateViolations = false);

    // Evaluates a single candidate process execution
    bool CheckExecution(DWORD pid, const std::wstring& processPath, StorageExecutionViolation& outViolation, bool terminate = false);

    // Execute policy containment: terminate process, quarantine device, purge allowlist, submit incident
    void EnforceViolation(const StorageExecutionViolation& viol);

    // Diagnostic simulation for automated tests
    void TriggerSimulatedExecution(const std::wstring& driveLetter, const std::wstring& exePath, DWORD pid);

    // OS-level proactive execution prevention policy (HKLM RemovableStorageDevices Deny_Execute)
    bool SetRemovableStorageExecutionPolicy(bool denyExecute);
    bool IsRemovableStorageExecutionDenied() const;

    // Algorithm 5 / Scenario 1 verification self-test
    bool VerifySelfTest();

private:
    StorageExecutionMonitor();
    ~StorageExecutionMonitor();
    StorageExecutionMonitor(const StorageExecutionMonitor&) = delete;
    StorageExecutionMonitor& operator=(const StorageExecutionMonitor&) = delete;

    void SurveillanceLoop();

    std::thread m_thread;
    std::atomic<bool> m_running{ false };
    mutable std::mutex m_mutex;
    AllowlistManager* m_allowlist = nullptr;

    // Deduplication map: deviceId+exePath -> last timestamp
    std::map<std::wstring, std::chrono::steady_clock::time_point> m_recentViolations;

    // Simulation / mock mapping: deviceId -> driveLetter
    std::map<std::wstring, std::wstring> m_mockDriveMappings;

    // Mock volume paths: driveLetter -> real folder path
    std::map<std::wstring, std::wstring> m_mockVolumePaths;

    // Simulation hooks
    bool m_simulationEnabled = false;
    StorageExecutableInspectionResult::Status m_simulatedStatus = StorageExecutableInspectionResult::Status::CLEAN;
    std::wstring m_simulatedPrimaryFile;
    std::wstring m_simulatedPolicyRule;
    std::wstring m_simulatedFailureReason;
};
