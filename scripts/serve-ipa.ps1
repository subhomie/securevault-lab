# Serve a built .ipa over HTTP on the LAN so TrollStore on the iPhone can fetch it.
#
#   powershell -ExecutionPolicy Bypass -File scripts\serve-ipa.ps1 -IpaPath .\SecureVault-unsigned.ipa
#
# Then open (on the iPhone, same Wi-Fi) the "TrollStore install URL" it prints.
# If Safari can't reach it, allow python through Windows Firewall for Private nets,
# or use the ngrok fallback printed at the end.

param(
    [Parameter(Mandatory = $true)][string]$IpaPath,
    [int]$Port = 8000
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $IpaPath)) {
    throw "IPA not found: $IpaPath"
}
$ipa = (Resolve-Path -LiteralPath $IpaPath).Path
$dir = Split-Path -Parent $ipa
$name = Split-Path -Leaf $ipa

# Best-effort LAN IPv4
$ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
       Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.PrefixOrigin -ne 'WellKnown' } |
       Sort-Object -Property SkipAsSource |
       Select-Object -First 1 -ExpandProperty IPAddress)
if (-not $ip) { $ip = '127.0.0.1' }

$direct = "http://${ip}:${Port}/${name}"
$tsUrl  = "apple-magnifier://install?url=" + [uri]::EscapeDataString($direct)

Write-Host ""
Write-Host "Serving : $dir"
Write-Host "IPA     : $name"
Write-Host "Direct  : $direct"
Write-Host ""
Write-Host "Open this on the iPhone (TrollStore): "
Write-Host "  $tsUrl" -ForegroundColor Green
Write-Host ""
Write-Host "Fallback if not on the same LAN (ngrok is already on PATH):"
Write-Host "  ngrok http $Port" -ForegroundColor Yellow
Write-Host "  then use https://<ngrok-id>.ngrok-free.app/$name as the url= value."
Write-Host ""
Write-Host "Press Ctrl+C to stop."
Write-Host ""

Set-Location -LiteralPath $dir
& python -m http.server $Port
