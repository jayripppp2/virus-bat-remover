Write-Output "Stopping processes (Solus.exe)"
Stop-Process -Name Solus -Force -ErrorAction SilentlyContinue
Write-Output "Processes stopped"

Write-Output "Deleting executables"
Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\Solus.exe" -Force -ErrorAction SilentlyContinue
Write-Output "Executables deleted"

Write-Output "Reverting WinDefender changes"
Remove-MpPreference -ExclusionPath "C:\Users\Admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionPath "C:\Users\Admin\AppData\Roaming\Microsoft\Windows" -ErrorAction SilentlyContinue
Write-Output "WinDefender Reverted"

Write-Output "Restoring Registry Tools"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t "REG_DWORD" /d "0" /f
Write-Output "Tools restored"

Write-Output "Removing persistence"
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Steam /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows PowerShell" /f
Write-Output "Persistence removed"

Write-Output "Deleting scripts (.ps1, .vbs)"
Remove-Item -Path "C:\ProgramData\edge\Updater\Get-Clipboard.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\ProgramData\edge\Updater\RunBatHidden.vbs" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\CaptureScreens.ps1" -Force -ErrorAction SilentlyContinue
Write-Output "Scripts deleted"

Write-Output "Restoring PowerShell EP to Restricted"
Set-ExecutionPolicy Restricted -Scope LocalMachine -Force -ErrorAction SilentlyContinue
Write-Output "PowerShell policy reset to Restricted"

Write-Output "Cleaning temp files"
$malwareFiles = @(
    "C:\Users\Admin\AppData\Local\Temp\Solus.exe"
)

foreach ($file in $malwareFiles) {
    if (Test-Path $file) {
        Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
    }
}
Write-Output "Temp files cleaned"

Write-Output "Solus was always a fake ahh bitch"
Write-Output "------------------"
Write-Output "JOIN THE DISCORD: discord.gg/2fSx3nBzxb"

Write-Output "Stopping malicious processes (functionHook, BinLaden Mystic Executor)"
Stop-Process -Name functionHook -Force -ErrorAction SilentlyContinue
Stop-Process -Name 'BinLaden Mystic Executor' -Force -ErrorAction SilentlyContinue
Write-Output "Malicious processes stopped"

Write-Output "Deleting executables"
Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\functionHook.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\BinLaden Mystic Executor.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\FastColoredTextBox.dll" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\Newtonsoft.Json.dll" -Force -ErrorAction SilentlyContinue
Write-Output "Executables deleted"

Write-Output "Reverting WinDefender changes"
Remove-MpPreference -ExclusionPath 'C:\Windows\system32' -ErrorAction SilentlyContinue
Write-Output "WinDefender Reverted"

Write-Output "Restoring Registry Tools"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableRegistryTools" /t "REG_DWORD" /d "0" /f
Write-Output "Registry Tools Restored"

Write-Output "Resetting attributes on WinSecurity folder and files"
$folders = @(
    "C:\Windows\System32\Windows Security",
    "C:\Windows\System32\Windows Security\ProtectionHistory_AQ3RYMB7R99GDDSQ7DPR6.log"
)

foreach ($folder in $folders) {
    if (Test-Path $folder) {
        attrib -s -h -r $folder -ErrorAction SilentlyContinue
    }
}

$files = @(
    "C:\Windows\System32\Windows Security\ecopt.spx"
)

foreach ($file in $files) {
    if (Test-Path $file) {
        attrib -s -h -r $file -ErrorAction SilentlyContinue
    }
}

Write-Output "Attributes reset"

Write-Output "Cleaning temp files"
$malwareFiles = @(
    "C:\Users\Admin\AppData\Local\Temp\functionHook.exe",
    "C:\Users\Admin\AppData\Local\Temp\BinLaden Mystic Executor.exe",
    "C:\Users\Admin\AppData\Local\Temp\FastColoredTextBox.dll",
    "C:\Users\Admin\AppData\Local\Temp\Newtonsoft.Json.dll"
)

foreach ($file in $malwareFiles) {
    if (Test-Path $file) {
        Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
    }
}
Write-Output "Temp files cleaned"

Write-Output "bye bye mystic"
Write-Output "credit to nspe lol"
Write-Output "------------------"
Write-Output "JOIN THE DISCORD: discord.gg/2fSx3nBzxb"

Write-Output "Stopping malicious processes (WAE, Dema, AUDIOG)"
Stop-Process -Name "Dema Bootstrapper.exe", "Windows Antivirus Executeable.exe", "AUDIODG.EXE", "activate.bat" -Force -ErrorAction SilentlyContinue
Write-Output "Malicious processes stopped"

Write-Output "Deleting Executables (Dema, WAE, AUDIOG)"
Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\Dema Beta\Thanks For Using Dema\Dema Bootstrapper.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\system32\Windows Antivirus Executeable.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\system32\AUDIODG.EXE" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Admin\Skype\activate.bat" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Admin\Skype" -Recurse -Force -ErrorAction SilentlyContinue
Write-Output "Executables deleted"

Write-Output "Removing exclusion paths"
Remove-MpPreference -ExclusionPath "C:\Users\Admin\Skype" -ErrorAction SilentlyContinue
Write-Output "Paths removed"

Write-Output "Resetting Directory Attributes"
attrib -s -h .
Write-Output "Attributes reset"

Write-Output "ez"
Write-Output "Credit to nspe lol"
Write-Output "------------------"
Write-Output "JOIN THE DISCORD: discord.gg/2fSx3nBzxb"

Write-Output "Stopping Processes (Feather & GooseDesktop)"
Stop-Process -Name FeatherV2 -Force -ErrorAction SilentlyContinue
Stop-Process -Name GooseDesktop -Force -ErrorAction SilentlyContinue
Stop-Process -Name feather -Force -ErrorAction SilentlyContinue
Write-Output "Processes stopped."

Write-Output "Deleting executables (Feather & GooseDesktop)"
$executables = @(
    "C:\Users\Admin\AppData\Local\Temp\2hheqgmb0veHdTSrpfO1ov9gLDF\FeatherV2.exe",
    "C:\Users\Admin\AppData\Local\Temp\EIr\EvilGoose\hg\GooseDesktop.exe",
    "C:\Users\Admin\AppData\Local\Temp\feather.exe",
    "C:\Users\Admin\AppData\Local\Temp\2hk9jVms5WvWmk3O377CwL22qEI\feather.exe"
)
foreach ($executable in $executables) {
    Remove-Item -Path $executable -Force -ErrorAction SilentlyContinue
}
Write-Output "Executables deleted."

Write-Output "Removing registry entries"
$registryPaths = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
foreach ($path in $registryPaths) {
    $keys = Get-Item -Path $path
    foreach ($key in $keys.Property) {
        if ((Get-ItemProperty -Path $path -Name $key).$key -match "FeatherV2.exe" -or (Get-ItemProperty -Path $path -Name $key).$key -match "GooseDesktop.exe" -or (Get-ItemProperty -Path $path -Name $key).$key -match "feather.exe") {
            Remove-ItemProperty -Path $path -Name $key -Force -ErrorAction SilentlyContinue
            Write-Output "Removed registry entry: $key"
        }
    }
}
Write-Output "Entries removed"

Write-Output "Removing scheduled tasks (Persistence)"
$tasks = Get-ScheduledTask | Where-Object {$_.Actions -match "FeatherV2.exe" -or $_.Actions -match "GooseDesktop.exe" -or $_.Actions -match "feather.exe"}
foreach ($task in $tasks) {
    Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "Removed scheduled task: $($task.TaskName)"
}
Write-Output "Scheduled tasks removed"

Write-Output "Removing startup items"
$startupPaths = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
foreach ($path in $startupPaths) {
    $files = Get-ChildItem -Path $path -Filter "*.lnk"
    foreach ($file in $files) {
        if ((Get-ItemProperty -Path $file.FullName).Target -match "FeatherV2.exe" -or (Get-ItemProperty -Path $file.FullName).Target -match "GooseDesktop.exe" -or (Get-ItemProperty -Path $file.FullName).Target -match "feather.exe") {
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
            Write-Output "Removed startup item: $($file.FullName)"
        }
    }
}
Write-Output "Startup items removed"

Write-Output "Cleaning temporary files"
if (Test-Path "C:\Users\Admin\AppData\Local\Temp") {
    Get-ChildItem -Path "C:\Users\Admin\AppData\Local\Temp" -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
}
Write-Output "Temporary files cleaned"

Write-Output "Cleanup of Roaming and CachedFiles"
Remove-Item -Path "C:\Users\Admin\AppData\Roaming\encabezado" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Admin\AppData\Roaming\Microsoft\Windows\Themes\CachedFiles\FeatherV2.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Admin\AppData\Roaming\Microsoft\Windows\Themes\CachedFiles\feather.exe" -Force -ErrorAction SilentlyContinue
Write-Output "Finished extra cleanup"

Write-Output "Removing PowerShell scripts"
$psScripts = @(
    "C:\Users\Admin\AppData\Local\Temp\XkQnCrFhC1uU_tezmp.ps1",
    "C:\Users\Admin\AppData\Roaming\salutqVsKU.ps1"
)
foreach ($script in $psScripts) {
    Remove-Item -Path $script -Force -ErrorAction SilentlyContinue
}
Write-Output "PowerShell scripts removed"

Write-Output "Removing PowerShell exclusions"
Remove-MpPreference -ExclusionPath "C:\Users\Admin\AppData" -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionPath "C:\Users\Admin\Local" -ErrorAction SilentlyContinue
Write-Output "PowerShell exclusions removed"

Write-Output "----------------------------------------------"
Write-Output "JOIN THE DISCORD SERVER: discord.gg/2fSx3nBzxb"
Write-Output "Stopping malicious processes (Nexus, XWorm, XMRig)"
Stop-Process -Name dllhost -Force -ErrorAction SilentlyContinue
Stop-Process -Name xorpgg -Force -ErrorAction SilentlyContinue
Stop-Process -Name nkkypq -Force -ErrorAction SilentlyContinue
Stop-Process -Name "Nexus Loader" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "kanilzbpgdul" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "Windows Runtime" -Force -ErrorAction SilentlyContinue
Write-Output "Malicious processes stopped"

Write-Output "Deleting executables"
Remove-Item -Path "C:\Users\Admin\AppData\Roaming\dllhost.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\xorpgg.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\nkkypq.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\onefile_696_133626440050710383\.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\Nexus Loader.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\ProgramData\hvforlxxtnuo\kanilzbpgdul.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\ProgramData\Windows Runtime.exe" -Force -ErrorAction SilentlyContinue
Write-Output "Deleted executables"

Write-Output "Removing registry entries (Persistence)"
$registryPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($path in $registryPaths) {
    $keys = Get-Item -Path $path
    foreach ($key in $keys.Property) {
        if ((Get-ItemProperty -Path $path -Name $key).$key -match "dllhost.exe" -or 
            (Get-ItemProperty -Path $path -Name $key).$key -match "xorpgg.exe" -or 
            (Get-ItemProperty -Path $path -Name $key).$key -match "nkkypq.exe" -or 
            (Get-ItemProperty -Path $path -Name $key).$key -match "Nexus Loader.exe" -or 
            (Get-ItemProperty -Path $path -Name $key).$key -match "kanilzbpgdul.exe" -or 
            (Get-ItemProperty -Path $path -Name $key).$key -match "Windows Runtime.exe") {
            Remove-ItemProperty -Path $path -Name $key -Force -ErrorAction SilentlyContinue
            Write-Output "Removed registry entry: $key"
        }
    }
}
Write-Output "Entires Removed"

Write-Output "Removing scheduled tasks (Persistence)"
$tasks = Get-ScheduledTask | Where-Object {$_.Actions -match "dllhost.exe" -or 
                                             $_.Actions -match "xorpgg.exe" -or 
                                             $_.Actions -match "nkkypq.exe" -or 
                                             $_.Actions -match "Nexus Loader.exe" -or 
                                             $_.Actions -match "kanilzbpgdul.exe" -or 
                                             $_.Actions -match "Windows Runtime.exe"}
foreach ($task in $tasks) {
    Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "Removed scheduled task: $($task.TaskName)"
}
Write-Output "Tasks removed"

Write-Output "Removing startup items (Persistence)"
$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($path in $startupPaths) {
    $files = Get-ChildItem -Path $path -Filter "*.lnk"
    foreach ($file in $files) {
        if ((Get-ItemProperty -Path $file.FullName).Target -match "dllhost.exe" -or 
            (Get-ItemProperty -Path $file.FullName).Target -match "xorpgg.exe" -or 
            (Get-ItemProperty -Path $file.FullName).Target -match "nkkypq.exe" -or 
            (Get-ItemProperty -Path $file.FullName).Target -match "Nexus Loader.exe" -or 
            (Get-ItemProperty -Path $file.FullName).Target -match "kanilzbpgdul.exe" -or 
            (Get-ItemProperty -Path $file.FullName).Target -match "Windows Runtime.exe") {
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
            Write-Output "Removed startup item: $($file.FullName)"
        }
    }
}
Write-Output "Startup items removed"

Write-Output "Reverting WinDefender Changes"
Remove-MpPreference -ExclusionPath 'C:\Users\Admin\AppData\Roaming\dllhost.exe' -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionProcess 'dllhost.exe' -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionPath 'C:\ProgramData\Windows Runtime.exe' -ErrorAction SilentlyContinue
Remove-MpPreference -ExclusionProcess 'Windows Runtime.exe' -ErrorAction SilentlyContinue
Write-Output "WinDefender Reverted"

Write-Output "Cleaning temp files"
if (Test-Path "C:\Users\Admin\AppData\Local\Temp") {
    Get-ChildItem -Path "C:\Users\Admin\AppData\Local\Temp" -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
}
Write-Output "Temp files cleaned"

Write-Output "Cleaning roaming and cached files"
Remove-Item -Path "C:\Users\Admin\AppData\Roaming\encabezado" -Recurse -Force -ErrorAction SilentlyContinue
Write-Output "Finished cleaning roaming and cached"

Write-Output "ggez bye bye Nexus Loader"
Write-Output "credit to nspe lol"
Write-Output "------------------"
Write-Output "JOIN THE DISCORD: discord.gg/2fSx3nBzxb"
Write-Output "Stopping malicious processes (ReboundBootstrapper)"
Stop-Process -Name ReboundBootstrapper -Force -ErrorAction SilentlyContinue
Write-Output "Malicious processes stopped"

Write-Output "Deleting malware executable"
Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\ReboundBootstrapper.exe" -Force -ErrorAction SilentlyContinue
Write-Output "Executable deleted"

Write-Output "Reverting WinDefender changes"
Remove-MpPreference -ExclusionPath 'C:\Users\Admin\AppData\Local\Temp\ReboundBootstrapper.exe' -ErrorAction SilentlyContinue
Write-Output "WinDefender Reverted"

Write-Output "Removing scheduled tasks (ReboundBootstrapper)"
$tasks = Get-ScheduledTask | Where-Object {$_.Actions -match "ReboundBootstrapper.exe"}
foreach ($task in $tasks) {
    Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Output "Removed scheduled task: $($task.TaskName)"
}
Write-Output "Scheduled tasks removed"

Write-Output "Removing startup items"
Remove-Item -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\   ‌‎.scr' -Force -ErrorAction SilentlyContinue
Write-Output "Startup items removed"

Write-Output "Resetting attributes on hosts file"
attrib -r C:\Windows\System32\drivers\etc\hosts
attrib +r C:\Windows\System32\drivers\etc\hosts

Write-Output "Cleaning temp files"
if (Test-Path "C:\Users\Admin\AppData\Local\Temp\_MEI17682\rar.exe") {
    Remove-Item -Path "C:\Users\Admin\AppData\Local\Temp\_MEI17682\rar.exe" -Force -ErrorAction SilentlyContinue
}
Write-Output "Temp files cleaned"

Write-Output "Finished Cleanign"

Write-Output "kys vale you monkey"
Write-Output "credit to nspe lol"
Write-Output "------------------"
Write-Output "JOIN THE DISCORD: discord.gg/2fSx3nBzxb"
