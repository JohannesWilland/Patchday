<#
.SYNOPSIS
    Vergleicht Windows Terminal Server (WTS) auf Abweichungen (Configuration Drift).
.DESCRIPTION
    Das Skript prueft installierte Software und Dateien auf dem oeffentlichen Desktop.
    Es gibt nur Ergebnisse aus, bei denen sich die Server unterscheiden (unterschiedliche Versionen 
    oder fehlende Installationen/Dateien).
    Zusaetzlich wird auf Abweichungen bei lokalen Gruppenrichtlinien (GPOs) geprueft.
#>

function Compare-SWWts {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, HelpMessage="Manuelles Kunden-Praefix, z.B. 'SW639-*'")]
        [string]$CustomerPrefix,

        [Parameter(HelpMessage="Liste von Servernamen, die von der Pruefung ausgeschlossen werden sollen.")]
        [string[]]$ExcludeServer,

        [Parameter(HelpMessage="Gibt die gefundenen Abweichungen als PowerShell-Objekte zurueck (-PassThru).")]
        [switch]$PassThru
    )

    Write-Host "Ermittle Ziel-Server im Netzwerk..." -ForegroundColor Cyan

    $customerPrefixFilter = "*"
    if ($CustomerPrefix) {
        $customerPrefixFilter = $CustomerPrefix
        Write-Host " -> Manuelles Kunden-Praefix aktiv: $customerPrefixFilter" -ForegroundColor DarkGray
    } elseif ($env:COMPUTERNAME -match "^([a-zA-Z]{2}\d+)-") {
        $customerPrefixFilter = $matches[1] + "-*"
        Write-Host " -> ASP 3 Umgebung erkannt ($($matches[1])). Suche wird optimiert..." -ForegroundColor DarkGray
    } else {
        Write-Host " -> Klassische ASP 2 Umgebung (oder lokales AD) erkannt. Suche im gesamten AD..." -ForegroundColor DarkGray
    }

    $ldapFilter = "(&(objectCategory=computer)(operatingSystem=*Server*)(name=$customerPrefixFilter)(!(name=CTX*))(!(name=FSSRV*)))"
    $searcher = [adsisearcher]$ldapFilter
    $allServers = $searcher.FindAll() | ForEach-Object { $_.Properties.name[0] }

    if (-not $allServers) {
        Write-Host "Fehler: Keine Server fuer den Filter '$ldapFilter' gefunden." -ForegroundColor Red
        return
    }

    Write-Host "Pruefe $($allServers.Count) gefundene Server auf Erreichbarkeit und Terminalserver-Modus..." -ForegroundColor Cyan

    $WTS_List = @()
    $counter = 0

    foreach ($server in $allServers) {
        $counter++
        Write-Progress -Activity "Pruefe Server" -Status "Server $counter von $($allServers.Count): $server" -PercentComplete (($counter / $allServers.Count) * 100)
        
        # Server ausschlieszen, falls ueber Parameter definiert (-ExcludeServer)
        if ($ExcludeServer -and ($server -in $ExcludeServer)) {
            Write-Host " -> Ueberspringe $server (Ausgeschlossen durch Parameter)" -ForegroundColor DarkGray
            continue
        }

        # Ping-Check
        if (Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue) {
            try {
                # Terminalserver-Check via CIM
                $tsSetting = Get-CimInstance -ComputerName $server -Namespace "root\CIMV2\TerminalServices" -Class "Win32_TerminalServiceSetting" -ErrorAction Stop
                
                if ($tsSetting.TerminalServerMode -eq "1") {
                    $WTS_List += $server
                }
            } catch {}
        }
    }

    if (-not $WTS_List -or $WTS_List.Count -eq 0) {
        Write-Host "Fehler: Keine aktiven Terminalserver gefunden." -ForegroundColor Red
        return
    }

    Write-Host "`nEs wurden $($WTS_List.Count) aktive Terminalserver fuer die Abfrage bestaetigt." -ForegroundColor Green
    Write-Host "Starte parallele Datenabfrage..." -ForegroundColor Cyan

    # ==============================================================================
    # 2. ABFRAGE DER WTS (Remote ScriptBlock)
    # ==============================================================================
    $ScriptBlock = {
        # 1. Installierte Software aus der Registry auslesen
        $UninstallKeys = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        $SoftwareList = Get-ItemProperty $UninstallKeys -ErrorAction SilentlyContinue | 
            Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 -and $_.ParentKeyName -eq $null } |
            Select-Object DisplayName, DisplayVersion

        # 2. Public Desktop Dateien auslesen
        $PublicDesktopPath = "C:\Users\Public\Desktop"
        $Shortcuts = @()
        if (Test-Path $PublicDesktopPath) {
            # Filtert maschinenspezifische Verknuepfungen (z.B. WTS1.lnk, WTS18.lnk, SW639-WTS1.lnk) heraus
            $Shortcuts = Get-ChildItem -Path $PublicDesktopPath | 
                Where-Object { $_.Name -notmatch '(?i)WTS\d' } |
                Select-Object Name
        }

        # 3. Windows-Dienste auslesen (Name, Starttyp)
        # User-spezifische Dienste (enden auf _ gefolgt von einem Hex-String wie _98cccc7) werden ignoriert
        $Services = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | 
            Where-Object { $_.Name -notmatch '_[0-9a-fA-F]{4,8}$' } |
            Select-Object Name, StartMode

        # 4. Lokale Gruppenmitgliedschaften (Administratoren & Remotedesktopbenutzer via SIDs)
        $LocalGroups = @()
        $GroupSIDs = @(
            @{ Name = 'Administratoren'; SID = 'S-1-5-32-544' },
            @{ Name = 'Remotedesktopbenutzer'; SID = 'S-1-5-32-555' }
        )
        foreach ($Group in $GroupSIDs) {
            try {
                $Members = Get-LocalGroupMember -SID $Group.SID -ErrorAction Stop | Select-Object -ExpandProperty Name
                
                # Normalisierung: Ersetze den lokalen Computernamen durch "LOCAL", um False-Positives zu verhindern
                $NormalizedMembers = $Members | ForEach-Object { $_ -ireplace "^$([regex]::Escape($env:COMPUTERNAME))\\", "LOCAL\" }
                
                $LocalGroups += [PSCustomObject]@{
                    GroupName = $Group.Name
                    Members   = ($NormalizedMembers | Sort-Object) -join "; "
                }
            } catch {
                # Ignorieren, falls die Gruppe z.B. aufgrund verwaister SIDs einen Fehler wirft
            }
        }

        # 5. Windows Updates (Hotfixes)
        $Hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID

        # 6. Umgebungsvariablen (Systemebene)
        $MachineEnv = [System.Environment]::GetEnvironmentVariables('Machine')
        $EnvList = @()
        foreach ($Key in $MachineEnv.Keys) {
            $EnvList += [PSCustomObject]@{ Name = $Key; Value = $MachineEnv[$Key] }
        }

        # 7. Lokale Gruppenrichtlinien (GPOs) pruefen
        # Wir lesen die genaue Version aus. Eine identische Version > 0 ist oft durch Citrix VDA/Optimizer beabsichtigt.
        $GptIni = "C:\Windows\System32\GroupPolicy\gpt.ini"
        $GpoVersion = "0"
        if (Test-Path $GptIni) {
            $GptContent = Get-Content $GptIni -ErrorAction SilentlyContinue
            if ($GptContent) {
                foreach ($Line in $GptContent) {
                    if ($Line -match "Version\s*=\s*(\d+)") {
                        $GpoVersion = $matches[1].Trim()
                    }
                }
            }
        }

        # Rueckgabe als Custom Object
        [PSCustomObject]@{
            Software  = $SoftwareList
            Shortcuts = $Shortcuts
            Services  = $Services
            Groups    = $LocalGroups
            Hotfixes  = $Hotfixes
            EnvVars   = $EnvList
            LocalGPO  = $GpoVersion
        }
    }

    # Ausfuehrung auf allen Servern
    $RawData = Invoke-Command -ComputerName $WTS_List -ScriptBlock $ScriptBlock -ErrorAction SilentlyContinue

    if (-not $RawData) {
        Write-Warning "Keine Daten empfangen. Bitte Berechtigungen und Erreichbarkeit der Server pruefen."
        return
    }

    # Array zum Sammeln der Ergebnisse fuer -PassThru
    $DriftResults = @()

    # --- AUSWERTUNG: SOFTWARE ---
    Write-Host "`n=== SOFTWARE ABWEICHUNGEN ===" -ForegroundColor Yellow
    $AllSoftware = @()
    foreach ($Node in $RawData) {
        foreach ($App in $Node.Software) {
            $AllSoftware += [PSCustomObject]@{
                Server  = $Node.PSComputerName
                AppName = $App.DisplayName.Trim()
                Version = if ($App.DisplayVersion) { $App.DisplayVersion.Trim() } else { "Unbekannt" }
            }
        }
    }

    # Gruppieren nach Software-Name
    $GroupedSoftware = $AllSoftware | Group-Object AppName

    $SoftwareDiffFound = $false
    foreach ($Group in $GroupedSoftware) {
        $UniqueVersions = $Group.Group | Select-Object Version -Unique
        $InstalledCount = $Group.Count
        $ServerCount = $WTS_List.Count

        # Handlungsbedarf besteht wenn:
        # 1. Mehr als eine Version der Software gefunden wurde ODER
        # 2. Die Software nicht auf allen Servern installiert ist (InstalledCount < ServerCount)
        if ($UniqueVersions.Count -gt 1 -or $InstalledCount -lt $ServerCount) {
            $SoftwareDiffFound = $true
            Write-Host "`nAbweichung gefunden bei: $($Group.Name)" -ForegroundColor Red
            
            $PassThruDetails = @()

            # Zeige, welcher Server welche Version hat (oder ob sie fehlt)
            foreach ($Server in $WTS_List) {
                $ServerApp = $Group.Group | Where-Object { $_.Server -eq $Server }
                if ($ServerApp) {
                    Write-Host "  - $Server : Version $($ServerApp.Version)"
                    $PassThruDetails += "${Server}: $($ServerApp.Version)"
                } else {
                    Write-Host "  - $Server : NICHT INSTALLIERT" -ForegroundColor DarkGray
                    $PassThruDetails += "${Server}: NICHT INSTALLIERT"
                }
            }

            if ($PassThru) {
                $DriftResults += [PSCustomObject]@{
                    Kategorie = 'Software'
                    Element   = $Group.Name
                    Problem   = 'Versionsunterschied oder fehlende Installation'
                    Details   = ($PassThruDetails -join ' | ')
                }
            }
        }
    }

    if (-not $SoftwareDiffFound) {
        Write-Host "Keine Software-Abweichungen gefunden. Alle WTS sind synchron." -ForegroundColor Green
    }

    # --- AUSWERTUNG: PUBLIC DESKTOP Dateien ---
    Write-Host "`n=== DESKTOP-DATEIEN ABWEICHUNGEN (Public) ===" -ForegroundColor Yellow
    $AllShortcuts = @()
    foreach ($Node in $RawData) {
        foreach ($Shortcut in $Node.Shortcuts) {
            $AllShortcuts += [PSCustomObject]@{
                Server       = $Node.PSComputerName
                ShortcutName = $Shortcut.Name
            }
        }
    }

    $GroupedShortcuts = $AllShortcuts | Group-Object ShortcutName
    $ShortcutDiffFound = $false

    foreach ($Group in $GroupedShortcuts) {
        $InstalledCount = $Group.Count
        $ServerCount = $WTS_List.Count

        # Handlungsbedarf wenn die Verknuepfung nicht auf allen Servern liegt
        if ($InstalledCount -lt $ServerCount) {
            $ShortcutDiffFound = $true
            Write-Host "`nUnterschied bei Verknuepfung: $($Group.Name)" -ForegroundColor Red
            
            $PassThruDetails = @()

            foreach ($Server in $WTS_List) {
                $HasShortcut = $Group.Group | Where-Object { $_.Server -eq $Server }
                if ($HasShortcut) {
                    Write-Host "  - $Server : Vorhanden"
                    $PassThruDetails += "${Server}: Vorhanden"
                } else {
                    Write-Host "  - $Server : FEHLT" -ForegroundColor DarkGray
                    $PassThruDetails += "${Server}: FEHLT"
                }
            }

            if ($PassThru) {
                $DriftResults += [PSCustomObject]@{
                    Kategorie = 'Desktop-Datei'
                    Element   = $Group.Name
                    Problem   = 'Datei fehlt auf bestimmten Servern'
                    Details   = ($PassThruDetails -join ' | ')
                }
            }
        }
    }

    if (-not $ShortcutDiffFound) {
        Write-Host "Keine Abweichungen bei den Public Desktop Dateien gefunden." -ForegroundColor Green
    }

    # --- AUSWERTUNG: DIENSTE ---
    Write-Host "`n=== DIENSTE ABWEICHUNGEN ===" -ForegroundColor Yellow
    $AllServices = @()
    foreach ($Node in $RawData) {
        if ($Node.Services) {
            foreach ($Svc in $Node.Services) {
                $AllServices += [PSCustomObject]@{
                    Server    = $Node.PSComputerName
                    Name      = $Svc.Name
                    StartMode = $Svc.StartMode
                }
            }
        }
    }
    $GroupedServices = $AllServices | Group-Object Name
    $ServiceDiffFound = $false

    foreach ($Group in $GroupedServices) {
        $UniqueStartModes = $Group.Group | Select-Object StartMode -Unique
        $InstalledCount = $Group.Count
        $ServerCount = $WTS_List.Count

        # Pruefen, ob Handlungsbedarf besteht
        if ($UniqueStartModes.Count -gt 1 -or $InstalledCount -lt $ServerCount) {
            $ServiceDiffFound = $true
            $ProblemText = ""
            
            # 1. Fall: Dienst fehlt komplett auf einem Server (Kritisch)
            if ($InstalledCount -lt $ServerCount) {
                Write-Host "`n[KRITISCH] Dienst fehlt auf einem oder mehreren WTS: $($Group.Name)" -ForegroundColor Red
                $ProblemText = "Dienst fehlt komplett"
            }
            # 2. Fall: Dienst ist irgendwo "Deaktiviert" (Kritisch)
            elseif ("Disabled" -in $UniqueStartModes) {
                Write-Host "`n[KRITISCH] Dienst ist teilweise deaktiviert: $($Group.Name)" -ForegroundColor Red
                $ProblemText = "Dienst ist teilweise deaktiviert"
            }
            # 3. Fall: Dienst schwankt nur zwischen Auto und Manuell (Hinweis)
            else {
                Write-Host "`n[HINWEIS] Starttyp-Wechsel bei: $($Group.Name) (Oft durch Windows-Trigger verursacht)" -ForegroundColor Yellow
                $ProblemText = "Starttyp weicht ab"
            }

            $PassThruDetails = @()

            # Detaillierte Ausgabe der Serverzustaende
            foreach ($Server in $WTS_List) {
                $ServerSvc = $Group.Group | Where-Object { $_.Server -eq $Server }
                if ($ServerSvc) {
                    # Farbliche Markierung fuer "Deaktiviert" zur besseren Erkennung
                    if ($ServerSvc.StartMode -eq "Disabled") {
                        Write-Host "  - $Server : Starttyp='$($ServerSvc.StartMode)'" -ForegroundColor Red
                    } else {
                        Write-Host "  - $Server : Starttyp='$($ServerSvc.StartMode)'"
                    }
                    $PassThruDetails += "${Server}: $($ServerSvc.StartMode)"
                } else {
                    Write-Host "  - $Server : DIENST FEHLT" -ForegroundColor DarkGray
                    $PassThruDetails += "${Server}: FEHLT"
                }
            }

            if ($PassThru) {
                $DriftResults += [PSCustomObject]@{
                    Kategorie = 'Dienst'
                    Element   = $Group.Name
                    Problem   = $ProblemText
                    Details   = ($PassThruDetails -join ' | ')
                }
            }
        }
    }
    if (-not $ServiceDiffFound) { Write-Host "Keine Abweichungen bei den Windows-Diensten gefunden." -ForegroundColor Green }

    # --- AUSWERTUNG: LOKALE GRUPPEN ---
    Write-Host "`n=== LOKALE GRUPPEN ABWEICHUNGEN ===" -ForegroundColor Yellow
    $AllGroups = @()
    foreach ($Node in $RawData) {
        if ($Node.Groups) {
            foreach ($Grp in $Node.Groups) {
                $AllGroups += [PSCustomObject]@{
                    Server  = $Node.PSComputerName
                    Name    = $Grp.GroupName
                    Members = $Grp.Members
                }
            }
        }
    }
    $GroupedGroups = $AllGroups | Group-Object Name
    $GroupDiffFound = $false

    foreach ($Group in $GroupedGroups) {
        $UniqueMembers = $Group.Group | Select-Object Members -Unique
        if ($UniqueMembers.Count -gt 1) {
            $GroupDiffFound = $true
            Write-Host "`nAbweichung bei lokaler Gruppe: $($Group.Name)" -ForegroundColor Red
            
            $PassThruDetails = @()

            foreach ($Server in $WTS_List) {
                $ServerGrp = $Group.Group | Where-Object { $_.Server -eq $Server }
                if ($ServerGrp) {
                    Write-Host "  - $Server : Mitglieder = $($ServerGrp.Members)"
                    $PassThruDetails += "${Server}: $($ServerGrp.Members)"
                } else {
                    Write-Host "  - $Server : Gruppe nicht abgefragt/gefunden" -ForegroundColor DarkGray
                    $PassThruDetails += "${Server}: Nicht gefunden"
                }
            }

            if ($PassThru) {
                $DriftResults += [PSCustomObject]@{
                    Kategorie = 'Lokale Gruppe'
                    Element   = $Group.Name
                    Problem   = 'Abweichende Gruppenmitgliedschaften'
                    Details   = ($PassThruDetails -join ' | ')
                }
            }
        }
    }
    if (-not $GroupDiffFound) { Write-Host "Keine Abweichungen bei lokalen Gruppenmitgliedschaften gefunden." -ForegroundColor Green }

    # --- AUSWERTUNG: WINDOWS UPDATES (HOTFIXES) ---
    Write-Host "`n=== WINDOWS UPDATES ABWEICHUNGEN ===" -ForegroundColor Yellow
    $AllHotfixes = @()
    foreach ($Node in $RawData) {
        if ($Node.Hotfixes) {
            foreach ($Hf in $Node.Hotfixes) {
                if ($Hf.HotFixID -ne "File 1") { # "File 1" wird manchmal faelschlich von Get-HotFix ausgegeben
                    $AllHotfixes += [PSCustomObject]@{
                        Server   = $Node.PSComputerName
                        HotFixID = $Hf.HotFixID
                    }
                }
            }
        }
    }
    $GroupedHotfixes = $AllHotfixes | Group-Object HotFixID
    $HotfixDiffFound = $false

    foreach ($Group in $GroupedHotfixes) {
        $InstalledCount = $Group.Count
        $ServerCount = $WTS_List.Count

        if ($InstalledCount -lt $ServerCount) {
            $HotfixDiffFound = $true
            Write-Host "`nUpdate nicht auf allen Servern installiert: $($Group.Name)" -ForegroundColor Red
            
            $PassThruDetails = @()

            foreach ($Server in $WTS_List) {
                $HasHf = $Group.Group | Where-Object { $_.Server -eq $Server }
                if ($HasHf) {
                    Write-Host "  - $Server : Installiert"
                    $PassThruDetails += "${Server}: Installiert"
                } else {
                    Write-Host "  - $Server : FEHLT" -ForegroundColor DarkGray
                    $PassThruDetails += "${Server}: FEHLT"
                }
            }

            if ($PassThru) {
                $DriftResults += [PSCustomObject]@{
                    Kategorie = 'Windows Update'
                    Element   = $Group.Name
                    Problem   = 'Update fehlt auf bestimmten Servern'
                    Details   = ($PassThruDetails -join ' | ')
                }
            }
        }
    }
    if (-not $HotfixDiffFound) { Write-Host "Keine Abweichungen bei installierten Windows Updates gefunden." -ForegroundColor Green }

    # --- AUSWERTUNG: UMGEBUNGSVARIABLEN ---
    Write-Host "`n=== UMGEBUNGSVARIABLEN ABWEICHUNGEN ===" -ForegroundColor Yellow
    $AllEnvVars = @()
    foreach ($Node in $RawData) {
        if ($Node.EnvVars) {
            foreach ($Env in $Node.EnvVars) {
                $AllEnvVars += [PSCustomObject]@{
                    Server = $Node.PSComputerName
                    Name   = $Env.Name
                    Value  = $Env.Value
                }
            }
        }
    }
    $GroupedEnvVars = $AllEnvVars | Group-Object Name
    $EnvDiffFound = $false

    foreach ($Group in $GroupedEnvVars) {
        $UniqueValues = $Group.Group | Select-Object Value -Unique
        $InstalledCount = $Group.Count
        $ServerCount = $WTS_List.Count

        if ($UniqueValues.Count -gt 1 -or $InstalledCount -lt $ServerCount) {
            $EnvDiffFound = $true
            Write-Host "`nAbweichung bei Variable: $($Group.Name)" -ForegroundColor Red
            
            $PassThruDetails = @()

            foreach ($Server in $WTS_List) {
                $ServerEnv = $Group.Group | Where-Object { $_.Server -eq $Server }
                if ($ServerEnv) {
                    Write-Host "  - $Server : $($ServerEnv.Value)"
                    $PassThruDetails += "${Server}: $($ServerEnv.Value)"
                } else {
                    Write-Host "  - $Server : FEHLT" -ForegroundColor DarkGray
                    $PassThruDetails += "${Server}: FEHLT"
                }
            }

            if ($PassThru) {
                $DriftResults += [PSCustomObject]@{
                    Kategorie = 'Umgebungsvariable'
                    Element   = $Group.Name
                    Problem   = 'Abweichende Werte oder fehlende Variable'
                    Details   = ($PassThruDetails -join ' | ')
                }
            }
        }
    }
    if (-not $EnvDiffFound) { Write-Host "Keine Abweichungen bei System-Umgebungsvariablen gefunden." -ForegroundColor Green }

    # --- AUSWERTUNG: LOKALE GRUPPENRICHTLINIEN (GPO) ---
    Write-Host "`n=== LOKALE GRUPPENRICHTLINIEN (GPO) ===" -ForegroundColor Yellow
    $AllGpos = @()
    foreach ($Node in $RawData) {
        # Alles hart als String casten und versteckte Zeichen (Trim) entfernen
        $cleanVersion = [string]$Node.LocalGPO
        $cleanVersion = $cleanVersion.Trim()
        if (-not $cleanVersion) { $cleanVersion = "0" }
        
        $AllGpos += [PSCustomObject]@{
            Server  = $Node.PSComputerName
            Version = $cleanVersion
        }
    }

    # Echte Unique-Werte ermitteln (Sicherer als Group-Object bei Typen-Problemen)
    $UniqueGpoVersions = $AllGpos | Select-Object -ExpandProperty Version -Unique
    
    # Handlungsbedarf, wenn es verschiedene Versionen gibt ODER ein Server komplett fehlt
    if ($UniqueGpoVersions.Count -gt 1 -or $AllGpos.Count -lt $WTS_List.Count) {
        Write-Host "`n[KRITISCH] Abweichende lokale GPO-Versionen (oder fehlende Server) gefunden!" -ForegroundColor Red
        Write-Host "  Jemand hat wahrscheinlich lokal auf einzelnen Servern Richtlinien ueber gpedit.msc geaendert." -ForegroundColor Yellow
        
        $PassThruDetailsGpo = @()
        foreach ($Server in $WTS_List) {
            $ServerGpo = $AllGpos | Where-Object { $_.Server -eq $Server }
            if ($ServerGpo) {
                Write-Host "  - $Server : Version $($ServerGpo.Version)"
                $PassThruDetailsGpo += "${Server}: $($ServerGpo.Version)"
            } else {
                Write-Host "  - $Server : FEHLT/FEHLER" -ForegroundColor DarkGray
                $PassThruDetailsGpo += "${Server}: FEHLER"
            }
        }

        if ($PassThru) {
            $DriftResults += [PSCustomObject]@{
                Kategorie = 'Lokale Gruppenrichtlinie (GPO)'
                Element   = 'gpedit.msc'
                Problem   = 'Abweichende lokale Richtlinien-Versionen zwischen den WTS'
                Details   = ($PassThruDetailsGpo -join ' | ')
            }
        }
    } else {
        $SharedVersion = $UniqueGpoVersions[0]
        if ($SharedVersion -eq "0") {
            Write-Host "Keine lokalen Gruppenrichtlinien konfiguriert (Sauberer Zustand auf allen WTS)." -ForegroundColor Green
        } else {
            Write-Host "Lokale GPOs sind auf allen WTS synchron (Version: $SharedVersion)." -ForegroundColor Green
            Write-Host " -> Dies ist typisch fuer automatisierte Citrix VDA / Optimizer Konfigurationen." -ForegroundColor DarkGray
        }
    }

    Write-Host "`nPruefung abgeschlossen." -ForegroundColor Cyan

    # Rueckgabe der gesammelten Objekte, wenn -PassThru verwendet wurde
    if ($PassThru -and $DriftResults.Count -gt 0) {
        return $DriftResults
    }
}