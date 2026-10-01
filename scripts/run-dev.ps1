# Start the application in Development mode (Fake directory, development sign-in).
Set-Location (Join-Path $PSScriptRoot "..")
$env:SD_ENVIRONMENT = "Development"
python -m uvicorn app.main:app_factory --factory --port 8000 --reload
