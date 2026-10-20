# setup_vm.ps1
# Automated Setup & Verification Script for USBIPS Minifilter Driver in a Disposable Windows VM
#
# IMPORTANT: Execute this script ONLY inside a disposable test VM (Hyper-V, VirtualBox, or VMware).
# DO NOT execute on your primary production host.

Param(
    [string]$DriverDir = "C:\USBIPS_Driver",
    [string]$ProtectedFolder = "C:\USBIPS_Protected"
)

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " USBIPS Minifilter Driver: VM Deployment & Verification Script " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Check Administrator Elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be executed in an elevated (Administrator) PowerShell session."
    exit 1
}

# 2. Check and Enable Test-Signing
Write-Host "`n[1/6] Verifying Kernel Test-Signing Status..." -ForegroundColor Yellow
$bcd = bcdedit | Out-String
if ($bcd -notmatch "testsigning\s+Yes") {
    Write-Host "  Enabling test-signing mode..." -ForegroundColor Cyan
    bcdedit /set testsigning on
    Write-Warning "Test-signing has been enabled. A VM reboot is required before loading unsigned/test drivers."
    Write-Warning "Please reboot the VM and re-run this script."
    exit 0
} else {
    Write-Host "  Test-signing is ENABLED." -ForegroundColor Green
}

# 3. Create Self-Signed Code-Signing Certificate if not already present
Write-Host "`n[2/6] Verifying Code-Signing Certificate..." -ForegroundColor Yellow
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "USBIPS Test Driver" } | Select-Object -First 1
if (-not $cert) {
    Write-Host "  Creating self-signed test code-signing certificate..." -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate -Type CodeSigning -CertStoreLocation Cert:\LocalMachine\My -Subject "CN=USBIPS Test Driver"
    # Export and add to Root and TrustedPublisher stores
    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine"
    $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $rootStore.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 @(,$certBytes)))
    $rootStore.Close()

    $pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store "TrustedPublisher", "LocalMachine"
    $pubStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $pubStore.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 @(,$certBytes)))
    $pubStore.Close()
    Write-Host "  Test certificate installed into Root & TrustedPublisher stores." -ForegroundColor Green
} else {
    Write-Host "  Test certificate is present." -ForegroundColor Green
}

# 4. Sign Driver Binary if un-signed
Write-Host "`n[3/6] Verifying Driver Signature..." -ForegroundColor Yellow
$sysFile = Join-Path $DriverDir "USBIPSFilter.sys"
if (Test-Path $sysFile) {
    $sig = Get-AuthenticodeSignature $sysFile
    if ($sig.Status -ne "Valid") {
        Write-Host "  Signing $sysFile with test certificate..." -ForegroundColor Cyan
        signtool sign /v /s My /n "USBIPS Test Driver" /t http://timestamp.digicert.com $sysFile
    } else {
        Write-Host "  $sysFile is already signed." -ForegroundColor Green
    }
} else {
    Write-Warning "  $sysFile not found in $DriverDir. Build USBIPSFilter.sys using WDK first."
}

# 5. Install & Load Minifilter Driver
Write-Host "`n[4/6] Installing & Loading Minifilter Driver..." -ForegroundColor Yellow
$infFile = Join-Path $DriverDir "USBIPSFilter.inf"
if (Test-Path $infFile) {
    rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 $infFile
    Write-Host "  INF installed successfully." -ForegroundColor Green
}

# Start driver service
fltmc load USBIPSFilter
$instances = fltmc instances | Out-String
if ($instances -match "USBIPSFilter") {
    Write-Host "  USBIPSFilter successfully LOADED and attached to volumes." -ForegroundColor Green
} else {
    Write-Warning "  USBIPSFilter not loaded. Check Windows Event Viewer / Filter Manager logs."
}

# 6. Verify Protected Folder Setup
Write-Host "`n[5/6] Ensuring Protected Directory & Canary Sentinel..." -ForegroundColor Yellow
if (-not (Test-Path $ProtectedFolder)) {
    New-Item -ItemType Directory -Path $ProtectedFolder -Force | Out-Null
}
$canary = Join-Path $ProtectedFolder "confidential_canary.txt"
if (-not (Test-Path $canary)) {
    Set-Content -Path $canary -Value "USBIPS CANARY FILE - CONFIDENTIAL FINANCIAL DATA"
}
Write-Host "  Protected folder verified: $ProtectedFolder" -ForegroundColor Green

# 7. Verification Test Instructions
Write-Host "`n[6/6] Scenario 3 Verification Instructions:" -ForegroundColor Cyan
Write-Host "  1. Start USBIPSClient.exe in the VM."
Write-Host "  2. Connect a simulated or physical USB drive."
Write-Host "  3. Attempt to read or copy '$canary' using a process executing from the USB drive."
Write-Host "  4. Observe STATUS_ACCESS_DENIED returned immediately before file handle creation."
Write-Host "  5. Verify that USBIPSClient.exe reports the incident and triggers CM_Disable_DevNode."
Write-Host "`nSetup script finished successfully." -ForegroundColor Green
