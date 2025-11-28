<# 
.SYNOPSIS
    Configure the default Anthropic model for ProcmonAI.

.DESCRIPTION
    Sets permanent USER-scoped environment variables for Anthropic:
    - ANTHROPIC_MODEL: recommended model for ProcmonAI summarization
                       (claude-3-5-haiku-20241022)
    - ANTHROPIC_API_KEY: copied from the current session (if present)

    After running this script, close and reopen PowerShell (and your IDE)
    so the new environment variable is picked up.

.NOTES
    Author: ProcmonAI setup helper
    Usage:
        1. Right-click PowerShell and choose "Run as administrator" (optional; not required for user scope).
        2. From this directory, run:
               .\set_anthropic_model.ps1
#>

$desiredModel = "claude-3-5-haiku-20241022"

Write-Host "Setting ANTHROPIC_MODEL to '$desiredModel' for the current user..." -ForegroundColor Cyan

[Environment]::SetEnvironmentVariable(
    "ANTHROPIC_MODEL",   # variable name
    $desiredModel,       # variable value
    "User"               # scope: User, Machine, or Process
)

# If a USER-scoped ANTHROPIC_API_KEY already exists, leave it alone.
$existingUserKey = [Environment]::GetEnvironmentVariable("ANTHROPIC_API_KEY", "User")

if ($existingUserKey) {
    Write-Host "A USER-scoped ANTHROPIC_API_KEY is already configured; leaving it unchanged." -ForegroundColor Green
}
elseif ($env:ANTHROPIC_API_KEY) {
    # Otherwise, if an API key is present in this session, persist it for the user.
    Write-Host "Persisting ANTHROPIC_API_KEY from current session for the current user..." -ForegroundColor Cyan
    [Environment]::SetEnvironmentVariable(
        "ANTHROPIC_API_KEY",
        $env:ANTHROPIC_API_KEY,
        "User"
    )
}
else {
    # As a last resort, prompt for a key and store it.
    Write-Host "No ANTHROPIC_API_KEY found for the user or in this session." -ForegroundColor Yellow
    $secure = Read-Host -AsSecureString "Enter your Anthropic API key (will be stored as a USER environment variable)"
    if ($secure.Length -gt 0) {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        )
        [Environment]::SetEnvironmentVariable(
            "ANTHROPIC_API_KEY",
            $plain,
            "User"
        )
        Write-Host "ANTHROPIC_API_KEY has been stored for the current user." -ForegroundColor Green
    }
    else {
        Write-Host "No key entered; ANTHROPIC_API_KEY was not set." -ForegroundColor Yellow
    }
}

Write-Host "Done." -ForegroundColor Green
Write-Host ""
Write-Host "Please CLOSE and REOPEN PowerShell (and any IDE) so the new" -ForegroundColor Yellow
Write-Host "ANTHROPIC_MODEL value is available to your sessions." -ForegroundColor Yellow


