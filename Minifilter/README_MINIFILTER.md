# USBIPS File System Minifilter Driver: Architecture, Signing, & Deployment Guide

**Target Module**: Scenario 3 — Real-Time Pre-Access File Read, Copy, & Modification Denial  
**Driver Binary**: `USBIPSFilter.sys`  
**Communication Port**: `\USBIPSFilterPort`  
**Filter Manager Altitude**: `370050` (Activity Monitor)

---

## Driver Lifecycle & Verification Status

| Component Stage | Status | Description |
|:---|:---:|:---|
| **1. Source Code Created** | **COMPLETED** | `USBIPSFilter.c`, `USBIPSFilter.h`, `USBIPSFilter.inf`, `USBIPSFilter.vcxproj` authored. PreCreate, PreRead, PreWrite, bidirectional communication port, and NT/DOS path matching implemented. |
| **2. Compiled with WDK** | **PENDING_WDK** | Requires Windows Driver Kit (WDK) toolchain and `fltKernel.h`. Not installed on primary host (SDK 10.0.26100.0 contains only user-mode headers). |
| **3. Loaded into OS** | **PENDING_VM** | Requires Windows Test-Signing (`bcdedit /set testsigning on`) and disposable test VM (Hyper-V / VirtualBox). Must NEVER be loaded unverified on host production workstation. |
| **4. Behavior Verified** | **STANDALONE_OK / MOCKED** | User-mode agent operates with honest fallback (`PENDING_KERNEL_DRIVER`); automated test suites run with mocked enforcement to guarantee hardware safety. |

---

## 1. Technical Rationale & User-Mode Boundaries

### Why User Mode Cannot Block File Reads
1. **Post-Facto Notification Limitation**:
   Win32 `ReadDirectoryChangesW` is an asynchronous notification mechanism. It receives notifications **after** I/O operations have already been committed to disk or memory.
2. **Invisibility of Reads**:
   `ReadDirectoryChangesW` observes file name changes, writes, and deletions. It does **not** receive notifications for ordinary file reads (`GENERIC_READ`, `FILE_READ_DATA`).
3. **No I/O Denial Vector**:
   User-mode applications have no capability to intercept an in-flight file system request or return `STATUS_ACCESS_DENIED` to a requesting application before file data is read into user memory.
4. **The Kernel Solution**:
   A Windows File System Minifilter Driver registered with `FltMgr.sys` operates in Ring 0 at the file system filter altitude. It intercepts `IRP_MJ_CREATE` and `IRP_MJ_READ` pre-operation callbacks, evaluates policies in real time, and immediately denies unauthorized access with `STATUS_ACCESS_DENIED` before any handle is granted or byte is transferred.

---

## 2. Kernel Minifilter Architecture

```
+----------------------------------------------------------------+
|                 User Space Applications                         |
|   (e.g., cmd.exe, explorer.exe, malicious.exe on USB volume)   |
+-------------------------------+--------------------------------+
                                |  1. CreateFileW / ReadFile
                                v
+----------------------------------------------------------------+
|                   Windows I/O Manager                          |
+-------------------------------+--------------------------------+
                                |  2. IRP_MJ_CREATE / IRP_MJ_READ
                                v
+----------------------------------------------------------------+
|                 Filter Manager (FltMgr.sys)                    |
+-------------------------------+--------------------------------+
                                |  3. PreCreate / PreRead Callback
                                v
+----------------------------------------------------------------+
|                 USBIPSFilter.sys (Altitude 370050)              |
|  - Is target path within an Admin-Protected Folder?            |
|  - Check Caller Process Origin & Associated USB Device         |
|  - If Unauthorized:                                            |
|      Return FLT_PREOP_COMPLETE with STATUS_ACCESS_DENIED       |
|      (Access BLOCKED at File-System Layer before execution)    |
+-------------------------------+--------------------------------+
                                |  4. Bidirectional Event Port
                                v  (\USBIPSFilterPort)
+----------------------------------------------------------------+
|                  USBIPSClient.exe (User-Mode Agent)            |
|  - Receives real-time kernel violation event                   |
|  - Maps implicated physical USB Storage Device                 |
|  - Initiates CM_Disable_DevNode hardware quarantine            |
|  - Evicts peripheral from local SQLite allowlist               |
|  - Transmits revocation incident to Central Management Server  |
+----------------------------------------------------------------+
```

---

## 3. Build & Development Prerequisites

To compile the native kernel driver `USBIPSFilter.sys`:
1. **Windows Driver Kit (WDK)**:
   - Install WDK 10/11 matching the installed Windows SDK (`10.0.26100.0`).
   - Visual Studio Extension: Ensure `Windows Driver Kit Visual Studio extension` is enabled.
2. **Visual Studio Workload**:
   - `Desktop development with C++`
   - Include `MSVC v143 - VS 2022 C++ ARM64/x64 build tools`
   - Include `Spectre-mitigated libraries (x64/x86)`
3. **Compilation Command**:
   ```cmd
   msbuild USBIPSFilter.vcxproj /p:Configuration=Debug /p:Platform=x64
   ```

---

## 4. Driver Signing Requirements

Windows 64-bit kernel enforcement prohibits loading unsigned or ad-hoc signed kernel binaries.

### Production Environment
* Requires an **Extended Validation (EV) Code Signing Certificate**.
* Driver package must be submitted to the **Microsoft Hardware Dev Center (WHQL)** for attestation signing by Microsoft Windows Hardware Quality Labs.

### Development & Lab Testing Environment
1. **Enable Test-Signing**:
   Open an elevated Command Prompt or PowerShell:
   ```cmd
   bcdedit /set testsigning on
   ```
   *(Note: Requires Secure Boot to be temporarily disabled in UEFI BIOS).*
2. **Create Test Certificate**:
   ```powershell
   New-SelfSignedCertificate -Type CodeSigning -CertStoreLocation Cert:\LocalMachine\My -Subject "CN=USBIPS Test Driver"
   ```
3. **Sign Driver Binary**:
   ```cmd
   signtool sign /v /s My /n "USBIPS Test Driver" /t http://timestamp.digicert.com x64\Debug\USBIPSFilter.sys
   ```

---

## 5. Installation, Lifecycle, & Verification Commands

### 1. Installation via INF
In an administrative console:
```cmd
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 .\USBIPSFilter.inf
```
Or create the service manually:
```cmd
sc create USBIPSFilter type= filesys binPath= "C:\Windows\System32\drivers\USBIPSFilter.sys" depend= FltMgr
```

### 2. Loading the Minifilter
```cmd
fltmc load USBIPSFilter
```

### 3. Verifying Filter Attachment
```cmd
fltmc instances
```
Expected output:
```text
Filter Name                     Num Instances    Altitude    Frame
------------------------------  -------------  ------------  -----
USBIPSFilter                                2        370050      0
```

### 4. Unloading the Minifilter
```cmd
fltmc unload USBIPSFilter
```

---

## 6. Safe Development & Isolation Plan

> [!CAUTION]
> Kernel-mode exceptions cause immediate Windows Bugchecks (`BSOD`). Driver development must follow strict isolation practices.

1. **Virtual Machine Isolation**:
   Always execute and test `USBIPSFilter.sys` inside a dedicated Hyper-V, VMware, or VirtualBox virtual machine running Windows 10/11. Never test unverified driver binaries directly on a production workstation.
2. **Kernel Debugging Setup**:
   Attach WinDbg over network (`KDNET`):
   ```cmd
   bcdedit /debug on
   bcdedit /dbgsettings net hostip:<Host-IP> port:50000 key:1.2.3.4
   ```
3. **Driver Verifier**:
   Enable Driver Verifier on `USBIPSFilter.sys` to detect memory leaks, IRQL violations, and pool corruption:
   ```cmd
   verifier /standard /driver USBIPSFilter.sys
   ```
