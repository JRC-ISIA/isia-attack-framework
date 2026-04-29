# start_capture.ps1
param(
  [string]$LCM_URI = "udpm://239.255.76.67:7667?iface=Ethernet 3",
  [string]$DEVICE_ID = "cap-win-mirror-01",
  [switch]$Background
)

Set-Location "C:\opt\attack-framework"

if (-Not (Test-Path .venv)) {
  Write-Host "Creating virtualenv..."
  python -m venv .venv
}

# Activate the venv
Write-Host "Activating venv..."
& .\.venv\Scripts\Activate.ps1

# Export environment vars for this process
$env:LCM_URI = $LCM_URI
$env:DEVICE_ID = $DEVICE_ID

# ensure logs dir exists
if (-Not (Test-Path ".\logs")) { New-Item -ItemType Directory -Path ".\logs" -Force | Out-Null }
if (-Not (Test-Path ".\run"))  { New-Item -ItemType Directory -Path ".\run" -Force | Out-Null }

# Start capture_module.py
$logfile = ".\logs\capture.out"
Write-Host "Starting capture_module.py with LCM_URI=$env:LCM_URI and DEVICE_ID=$env:DEVICE_ID"

if ($Background) {
  $proc = Start-Process -FilePath "python" -ArgumentList ".\capture_module.py" -RedirectStandardOutput ".\logs\capture.out" -RedirectStandardError ".\logs\capture.err" -PassThru
  $proc.Id | Out-File -FilePath ".\run\capture.pid" -Encoding ascii
  Write-Host "capture_module.py started (pid $($proc.Id))"
} else {
  # run in foreground and tee output
  python .\capture_module.py 2>&1 | Tee-Object -FilePath $logfile
}

