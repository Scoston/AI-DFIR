param(
  [ValidateSet("default","minimal","model","enterprise","dev","pdf-agpl")]
  [string]$Profile = "default",
  [string]$Venv = ".venv"
)
$ErrorActionPreference = "Stop"
py -3 -c "import sys; assert sys.version_info >= (3,11), 'AI-DFIR requires Python 3.11+'"
py -3 -m venv $Venv
& "$Venv\Scripts\python.exe" -m pip install --upgrade pip
$req = switch ($Profile) {
  "model" { "requirements-model.txt" }
  "enterprise" { "requirements-enterprise.txt" }
  "dev" { "requirements-dev.txt" }
  default { "requirements.txt" }
}
& "$Venv\Scripts\python.exe" -m pip install -r $req
if ($Profile -eq "pdf-agpl") {
  & "$Venv\Scripts\python.exe" -m pip install -r requirements-pdf-agpl.txt
  Write-Warning "PyMuPDF is AGPL/commercial. Review LICENSE_GUIDE.md."
}
Get-ChildItem -Filter *.py | ForEach-Object { & "$Venv\Scripts\python.exe" -m py_compile $_.FullName }
Write-Host "AI-DFIR installed. Activate with: $Venv\Scripts\Activate.ps1"
