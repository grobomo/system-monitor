# Shield registry settings — prevent console windows from stealing focus
# Run with: powershell -ExecutionPolicy Bypass -File shield-registry.ps1 [enable|disable]

param(
    [Parameter(Position=0)]
    [ValidateSet('enable','disable','status')]
    [string]$Action = 'status'
)

$desktopKey = 'HKCU:\Control Panel\Desktop'

switch ($Action) {
    'enable' {
        # Set ForegroundLockTimeout to max — background windows flash in taskbar, don't steal focus
        Set-ItemProperty -Path $desktopKey -Name ForegroundLockTimeout -Value 4294967295 -Type DWord
        # Set ForegroundFlashCount to 1 — minimal taskbar flash
        Set-ItemProperty -Path $desktopKey -Name ForegroundFlashCount -Value 1 -Type DWord

        Write-Host "Shield ENABLED:" -ForegroundColor Green
        Write-Host "  ForegroundLockTimeout = MAX (background windows cannot steal focus)"
        Write-Host "  ForegroundFlashCount = 1 (minimal taskbar flash)"
        Write-Host ""
        Write-Host "You can still switch windows with Alt+Tab or clicking." -ForegroundColor Gray
        Write-Host "Run 'shield-registry.ps1 disable' to restore defaults." -ForegroundColor Gray
    }
    'disable' {
        Set-ItemProperty -Path $desktopKey -Name ForegroundLockTimeout -Value 200000 -Type DWord
        Set-ItemProperty -Path $desktopKey -Name ForegroundFlashCount -Value 7 -Type DWord

        Write-Host "Shield DISABLED — defaults restored:" -ForegroundColor Yellow
        Write-Host "  ForegroundLockTimeout = 200000 (default)"
        Write-Host "  ForegroundFlashCount = 7 (default)"
    }
    'status' {
        $timeout = (Get-ItemProperty -Path $desktopKey -Name ForegroundLockTimeout).ForegroundLockTimeout
        $flash = (Get-ItemProperty -Path $desktopKey -Name ForegroundFlashCount -ErrorAction SilentlyContinue).ForegroundFlashCount

        if ($timeout -ge 4294967295) {
            Write-Host "Shield: ENABLED" -ForegroundColor Green
        } else {
            Write-Host "Shield: DISABLED" -ForegroundColor Yellow
        }
        Write-Host "  ForegroundLockTimeout = $timeout"
        Write-Host "  ForegroundFlashCount = $flash"
    }
}
