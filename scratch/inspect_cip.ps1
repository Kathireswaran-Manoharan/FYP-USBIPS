$path = "C:\Windows\System32\CodeIntegrity\CIPolicies\Active\{0283AC0F-FFF1-49AE-ADA1-8A933130CAD6}.cip"
if (Test-Path $path) {
    Write-Host "File exists: $path"
    $bytes = [System.IO.File]::ReadAllBytes($path)
    Write-Host "Size: " $bytes.Length
    # Extract readable unicode/ascii strings from binary CIP
    $asciiStr = [System.Text.Encoding]::ASCII.GetString($bytes)
    $unicodeStr = [System.Text.Encoding]::Unicode.GetString($bytes)

    Write-Host "--- Extracting XML / String fragments from CIP ---"
    $pattern = '[\x20-\x7E]{6,}'
    $matches = [regex]::Matches($asciiStr, $pattern)
    foreach ($m in $matches) {
        if ($m.Value -match "Policy|Signer|Certificate|Root|Rule|Microsoft|Name|Id|Allow") {
            Write-Host $m.Value
        }
    }
} else {
    Write-Host "Path not found"
}
