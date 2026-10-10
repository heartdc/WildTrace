param([int]$Port = 8765, [switch]$SkipInstall)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (!(Test-Path '.venv/Scripts/python.exe')) {
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed' }
}
$workbenchPython = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
if (!$SkipInstall) {
    & $workbenchPython -m pip install -e '.[workbench]'
    if ($LASTEXITCODE -ne 0) { throw 'Backend installation failed' }
    Push-Location frontend
    try {
        npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw 'Frontend installation failed' }
        npm.cmd run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed' }
    } finally { Pop-Location }
}
& $workbenchPython -X utf8 -m ohvul.workbench.launch --port $Port
