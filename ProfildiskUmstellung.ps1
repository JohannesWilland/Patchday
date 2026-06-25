function Set-DefaultFSLogixSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$GPOName, 
        [string]$RegkeyPathOfficeDisk = "HKLM\SOFTWARE\Policies\FSLogix\ODFC\",
        [int]$DisabledValue = 0,
        [string]$RegkeyPathProfileDisk = "HKLM\SOFTWARE\FSLogix\Profiles",
        [string]$RegkeyPathRomRecyleBin = "HKLM\SOFTWARE\FSLogix\Apps",
        [string]$SizeInMBValueName = "SizeInMBs",
        [int]$DefaultSizeInMBValue = 51200
    )

    # Standard Profiledisk Einstellungen setzten
    $FsLogixDefaultSettings = @{
        "DeleteLocalProfileWhenVHDShouldApply" = 1
        "RoamIdentity"                         = 1
    }
    foreach ($key in $FsLogixDefaultSettings.Keys) {
        $value = $FsLogixDefaultSettings[$key]
        Set-GPRegistryValue -Name $GPOName -Key $RegkeyPathProfileDisk -ValueName $key -Value $value -Type DWORD
        Write-Host "Der Wert '$($key)' wurde auf '$($value)' gesetzt." -ForegroundColor Green
    }

    # RoamRecycleBin deaktivieren
    Set-GPRegistryValue -Name $GPOName -Key $RegkeyPathRomRecyleBin -ValueName "RoamRecycleBin" -Value 0 -Type DWORD
    Write-Host "Der Wert 'RoamRecycleBin' wurde auf '0' gesetzt." -ForegroundColor Green
    
    # Office Disk Einstellungen deaktivieren

    $OfficeDiskSettings = Get-GPRegistryValue -Name $GPOName -Key $RegkeyPathOfficeDisk -ErrorAction SilentlyContinue

    foreach ($setting in $OfficeDiskSettings) {
        if ($setting.Type -eq "DWord") {
            Set-GPRegistryValue -Name $GPOName -Key $RegkeyPathOfficeDisk -ValueName $setting.ValueName -Value $DisabledValue -Type DWORD
            Write-Host "Der Wert '$($setting.ValueName)' wurde auf '$($DisabledValue)' gesetzt." -ForegroundColor Green
        }
        if ($setting.Type -eq "String") {
            Remove-GPRegistryValue -Name $GPOName -Key $RegkeyPathOfficeDisk -ValueName $setting.ValueName
            Write-Host "Der Wert '$($setting.ValueName)' vom Typ 'REG_SZ' wurde entfernt." -ForegroundColor Green
        }
        else {
            Write-Host "Der Wert '$($setting.ValueName)' ist kein REG_SZ und wurde übersprungen." -ForegroundColor Yellow
        }
    }

    # Standardgröße für Office Disk prüfen
    try {
        $OfficeDiskSizeInMB = Get-GPRegistryValue -Name $GPOName -Key $RegkeyPathOfficeDisk -ValueName $SizeInMBValueName -ErrorAction SilentlyContinue
        Write-Host "Eintrag für Office Disk gefunden" -ForegroundColor Yellow
        $value = [int]$OfficeDiskSizeInMB.Value
        Write-Host "Wert: $value" -ForegroundColor Green
    }
    catch {
        Write-Warning "Registry-Eintrag '$SizeInMBValueName' für Office Disk existiert in dieser GPO nicht. Standardgröße wird auf '$SizeInMBValue' MB gesetzt."
    }
 
    # Standardgröße für Profile Disk prüfen
    try {
        $ProfileDiskSizeInMB = Get-GPRegistryValue -Name $GPOName -Key $RegkeyPathProfileDisk -ValueName $SizeInMBValueName -ErrorAction SilentlyContinue
        Write-Host "Eintrag für Profile Disk gefunden" -ForegroundColor Yellow
        $value = [int]$ProfileDiskSizeInMB.Value
        Write-Host "Wert: $value" -ForegroundColor Green
    }
    catch {
        Write-Warning "Registry-Eintrag '$SizeInMBValueName' für Profile Disk existiert in dieser GPO nicht. Standardgröße wird auf '$SizeInMBValue' MB gesetzt."
    }

    $answer = Read-Host "Soll eine Standardgröße von '$DefaultSizeInMBValue' MB für die Profile Disk gesetzt werden, wenn kein Eintrag vorhanden ist? (J/N)"

    If ($answer -eq "J") {
        Set-GPRegistryValue -Name $GPOName -Key $RegkeyPathProfileDisk -ValueName $SizeInMBValueName -Value $DefaultSizeInMBValue -Type DWORD
        Write-Host "Der Wert '$SizeInMBValueName' für die Profile Disk wurde auf '$DefaultSizeInMBValue' MB gesetzt." -ForegroundColor Green
    }
    else {
        $CustomSizeInMb = Read-Host "Welche Größe in MB soll für die Profile Disk gesetzt werden? (Standard: '$DefaultSizeInMBValue' MB)"
        $IntCustomSizeInMB = [int]$CustomSizeInMb
        Set-GPRegistryValue -Name $GPOName -Key $RegkeyPathProfileDisk -ValueName $SizeInMBValueName -Value $IntCustomSizeInMB -Type DWORD
    }

}
Set-DefaultFSLogixSettings

Invoke-SWSubnet -Scriptblock {reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin" /v BlockAADWorkplaceJoin /t REG_DWORD /d 1 /f}