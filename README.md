# FYP-USBIPS

USB Intrusion Prevention System (USBIPS) is a Windows C++ console application that monitors USB device arrival and removal events. When a device is connected, the application extracts its identity, classifies it, checks the local allowlist, and uses Windows device management APIs to quarantine or release it.

> **Warning:** This program can disable USB devices immediately after they are connected. Test it on a non-critical Windows machine with a recovery method available. A device can remain disabled if the application is terminated or an enforcement/release operation fails.

## Features

- Monitors USB device interface notifications through a hidden Windows message-only window.
- Extracts vendor, product, serial number, manufacturer, and device description information.
- Classifies devices as HID, storage, network, or other.
- Quarantines newly detected devices before the allowlist decision.
- Stores approved device identities in a local SQLite database.
- Detects physical removal using Windows notifications and a polling fallback.

## Requirements

- Windows 10 or later.
- Visual Studio Community with the **Desktop development with C++** workload.
- An installed Windows 10 SDK or later.
- MSVC v145 build tools, which are selected by the project configuration. If Visual Studio offers a different installed toolset, change **Platform Toolset** in the project properties or install v145 through Visual Studio Installer.
- Administrator privileges at runtime. USB device enable/disable operations use Configuration Manager APIs and may fail without elevation.
- A physical USB device for end-to-end testing.

SQLite is compiled into the project from `ThirdParty/SQLite`, so no separate SQLite installation is required.

## Open and build in Visual Studio Community

1. Install Visual Studio Community with **Desktop development with C++**, the MSVC toolset, and a Windows SDK.
2. Clone or download this repository.
3. Open `USBIPSClient.slnx` in Visual Studio Community. If your Visual Studio version does not support `.slnx`, open `USBIPSClient.vcxproj` directly or use the latest Visual Studio Community release.
4. Select the `Debug` configuration and `x64` platform from the toolbar. The project also defines `Release` and `Win32` configurations.
5. Right-click the project and select **Set as Startup Project**.
6. Build with **Build > Build Solution** (`Ctrl+Shift+B`).

The project is configured as a C++20 console application. It links the Windows Configuration Manager library through the source code and builds the bundled SQLite C source as part of the project.

## Run the application

1. Start Visual Studio Community as Administrator, or run the built executable from an elevated terminal.
2. Set the project working directory to the repository root when running from Visual Studio. The application opens `usbips.db` using a relative path, so the working directory determines which database is used.
3. Start the program before connecting a test USB device. Devices already connected when the program starts are not automatically enumerated.
4. When an unknown device is detected, it is quarantined first and device details are printed to the console. Enter `Y` or `y` to add it to the allowlist and release it. Any other response leaves it disabled.
5. Devices already in the allowlist are released automatically.

For a command-line build from a **Developer Command Prompt for Visual Studio**:

```text
msbuild USBIPSClient.slnx /m /p:Configuration=Debug /p:Platform=x64
```

Run the resulting executable from the intended database working directory:

```text
x64\Debug\USBIPSClient.exe
```

The application does not provide a normal interactive shutdown command. Its message loop exits when the hosting window is destroyed. Use a controlled stop and verify device state after testing; forced termination and Ctrl+C do not provide an explicit cleanup path.

## Data and allowlist

The first run creates `usbips.db` and an `allowed_devices` table. A device is identified by the combination of vendor ID, product ID, and serial number. The database is local runtime data and is ignored by Git.

To reset the allowlist during development, stop the application and delete the `usbips.db` file from the working directory used to launch it. The next run creates a fresh database.

## Project structure

| Directory/file | Purpose |
| --- | --- |
| `main.cpp` | Application entry point, USB notifications, and message loop |
| `Extractor/` | USB device metadata extraction |
| `Classifier/` | Device type classification |
| `Allowlist/` | SQLite-backed allowlist management |
| `Enforcement/` | Device quarantine and release operations |
| `Presence/` | Physical removal monitoring |
| `AccessControl/` | Access-control helpers |
| `Models/` | Shared USB device model |
| `ThirdParty/SQLite/` | Embedded SQLite source and header |
| `USBIPSClient.vcxproj` | Visual Studio project configuration |

## Current limitations

- This is a console prototype, not a Windows service; it does not start automatically with Windows.
- There is no UI for listing or removing allowlist entries.
- A device arrival callback waits for console input, so connect and approve devices one at a time during testing.
- There is no automated test project. Test with disposable USB hardware and confirm that devices can be re-enabled.
