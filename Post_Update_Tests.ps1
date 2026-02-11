####################### Programme Starten ####################################
# REWE #
if ((Test-Path "$env:DATEVPP\PROGRAMM\RWAPPLIC\Irw.exe") -and ((test-path HKLM:\SOFTWARE\WOW6432Node\DATEVeG\Components\R0008301) -eq $false))
{
  & "$env:DATEVPP\PROGRAMM\RWAPPLIC\Irw.exe"
}
# DMS #
if (Test-Path "$env:DATEVPP\PROGRAMM\K0005100\Dokorg.exe")
{
  & "$env:DATEVPP\PROGRAMM\K0005100\Dokorg.exe"
}
# Arbeitsplatz
if (Test-Path "$env:DATEVPP\PROGRAMM\K0005000\Arbeitsplatz.exe")
{
  & "$env:DATEVPP\PROGRAMM\K0005000\Arbeitsplatz.exe"
}

#### Teams neu installieren:

$TeamsScriptblock = {
  if ((Get-Package -Name teams2 -ErrorAction SilentlyContinue) -ne $null) {
    Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -contains "ms-teams" } | ForEach-Object {$_.CloseMainWindow() | Out-Null }
    Uninstall-Package -Name teams2 -AllVersions
    Install-Package -Name teams2 -Source schuwa-repo
  }
}
Invoke-SWSubnet -TSOnly -Scriptblock $TeamsScriptblock
# Wieder entfernen nach dem Patchday, damit nicht bei jedem Start von Start-SWPatchdayPreparationsNG Teams neu installiert wird.

function Send-PatchdayOTState($state)
{
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  if ($env:USERDNSDOMAIN -eq "SW750.local")
  {$VLAN = ((Get-NetAdapter | Get-DnsClient).ConnectionSpecificSuffix).Split(".")[0]
  } else
  {$VLAN = $env:USERDNSDOMAIN.Split(".")[0];
  }
  $headers = @{Authorization="Basic d2ViaG9va3M6UnBHNltGZF9QW1pbI1tFRUx6dCNDJA=="}
  $body = "{`"VLAN`": `"$VLAN`", `"Server`": `"$env:computername`", `"State`": `"$state`"}"
  try
  {
    Invoke-RestMethod 'https://ticket.schuwa.de/OTWSREST/webhooks/PatchdayAutomation' -Method 'POST' -Headers $headers -Body $body 
  } catch
  {
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
  }
  
}

# Variablen fuellen
$kommsrv = (resolve-dnsname -name swss-kommserver -type txt -erroraction silentlycontinue).strings
$RegPath = "HKLM:\SOFTWARE\Wow6432Node\DATEVeG\InstallInfos\DefaultDataServers"
$DATEVSRV = Get-ItemProperty -Path $RegPath
$DATEVSrvName = $DATEVSRV.'(default)'

Send-PatchdayOTState("6 - Post_Update_Tests gestartet")

function AutoPostPatchdayTest()
{
  $TestSuccess = $true
  $TestMessage = ""

  ######################## Funktionstest RZ-Kommunikation #########################
  #Pruefen ob ein Kommunikationsserver eingesetzt wird - ansonsten kann mit lokaler DFue ueber internet kein Funktionstest vom WTS durchgefuehrt werden

  $kommsrv = (resolve-dnsname -name swss-kommserver -type txt -erroraction silentlycontinue).strings
  $kommsession = new-pssession -computername $kommsrv
  $kommSRVInstalled = invoke-command -session $kommsession -scriptblock { $BasePath = "HKLM:\SOFTWARE\WOW6432Node\DATEVeG\Components\B0000004"; Test-Path $BasePath } #B0000004 = DATEV Kommunikationsserver
  if ($kommSRVInstalled)
  {
  
    try
    {
      $com = [activator]::CreateInstance([type]::GetTypeFromCLSID("E029EB85-5020-4558-8AD2-B9B85A9FB09C"))
    } catch
    {
      $TestSuccess = $false
      $TestMessage = "[o] DCOM Entpunkt FUNKTEST.Funktionstest2 nicht gefunden. DATEV nicht installiert?"
      Write-Warning $TestMessage
    }

    # Create Temporary File for Report
    $logfile = New-TemporaryFile
    # Start Test
    $com.Start($logfile.FullName, ""); 
    # Get Process Id wait for Process Exit and check Exit Code
    $p = [System.Diagnostics.Process]::GetProcessById($com.ProcessID)
    $p.EnableRaisingEvents = $true;
    $p.WaitForExit() | Out-Null

    # Check Exitcode for Errors
    # Exitcode 9573 = Erfolgreich
    if ($p.ExitCode -eq 9573)
    {
      Write-Host "[+] RZ-Kommunikation Funktionstest erfolgreich:" $logfile.FullName -ForegroundColor Green
    } else
    {
      $TestSuccess = $false
      $TestMessage = "[-] RZ-Kommunikation Funktionstest mit Fehlern beendet"
      Write-Host -ForegroundColor Red $TestMessage+" bitte pruefen:"
      Get-Content $logfile
    }

    # Cleanup
    Remove-item $logfile
  } else
  {
    Write-Host "[o] Kommunikationsserver nicht installiert. RZ-Funktionstest wird uebersprungen. "
  }

  ###########################
  # Datenanpassungschek 1.1 #
  ###########################

  ######################### Datenanpassungen ###################################
  <#
  If (Test-Path "$env:DATEVPP\PROGRAMM\ZDCLIENT\Datev.DataAdaptation.LogViewer.exe") {
    & "$env:DATEVPP\PROGRAMM\ZDCLIENT\Datev.DataAdaptation.LogViewer.exe"
  }
  #>

  # Pfad zum Ordner
  $TopfolderPath = "L:\DATEV\LOG\INSTALL\$DATEVSrvName\DTTrafo\Tasks"

  # alle Unterordner im angegebenen Pfad
  $subfolders = Get-ChildItem -Path $TopfolderPath -Directory -ErrorAction SilentlyContinue

  # Sortieren der Unterordner nach dem Erstellungsdatum in absteigender Reihenfolge und das erste Element auswaehlen
  $folder = $subfolders | Sort-Object CreationTime -Descending | Select-Object -First 1
  $today = (Get-Date).Date


  if ($folder.LastWriteTime -lt $today)
  {
    Write-Host "[-] Datenanpassung ist nicht gelaufen." -ForegroundColor Red
    $TestSuccess = $false
    $TestMessage = "Datenanpassung ist nicht gelaufen."
  } else
  {
    $folderPath = Join-Path -Path $TopfolderPath -ChildPath $($folder.Name)


    # ein leeres Array erstellen, um die Ergebnisse zu speichern
    $results = @()

    # den Ordner und Unterordner nach XML-Dateien durchsuchen
    Get-ChildItem -Path $folderPath -Filter DpCFinish.xml -Recurse | ForEach-Object {
      # Ladendie XML-Datei Durchsuchen
      $xmlFinishContent = Get-Content $_.FullName
      $xmlFinish = New-Object -TypeName XML
      $xmlFinish.LoadXml($xmlFinishContent)

      # die Werte von DatapathId und StateBeforeAdaptation extrahieren
      $datapathId = $xmlFinish.DataAdaptationRun.DatapathInfo.DatapathId
      $stateBeforeAdaptation = $xmlFinish.DataAdaptationRun.ConfigurationInfo.StateBeforeAdaptation

      # ueberpruefen, ob der Status "Anzupassen" ist
      if ($stateBeforeAdaptation -eq "Anzupassen")
      {
        # den Pfad zum Datapath-Ordner erstellen
        $datapathFolder = Join-Path -Path $folderPath -ChildPath $datapathId

        $InfoFile = Get-ChildItem -Path $datapathFolder -Filter *DpInfo*.xml | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        # die XML-Datei Laden
        $xmlInfoContent = Get-Content $InfoFile.FullName
        $xmlInfo = New-Object -TypeName XML
        $xmlInfo.LoadXml($xmlInfoContent)

        # den Wert Datapath Extrahieren
        $Datapath = $xmlInfo.DataAdaptationRun.DatapathInfo.Datapath

        # nach einer XML-Datei mit "Archiv" im Namen suchen
        $archiveFile = Get-ChildItem -Path $datapathFolder -Filter *Archiv*.xml | Sort-Object LastWriteTime -Descending | Select-Object -First 1

        if ($archiveFile)
        {
          # die XML-Datei laden
          $xmlArchivContent = Get-Content $archiveFile.FullName
          $xmlArchiv = New-Object -TypeName XML
          $xmlArchiv.LoadXml($xmlArchivContent)
          $stateAfterAdaptation = $xmlArchiv.DataAdaptationRun.DatapathInfo.Datacategory
          # die Werte zum Ergebnisarray hinzufuegen
          $results += New-Object PSObject -Property @{
            'Datapath' = $Datapath
            'StateBeforeAdaptation' = $stateBeforeAdaptation
            'StateAfterAdaptation' = $stateAfterAdaptation
            'ID' = $datapathId
          }
        } else
        {
          # nach einer Datei namens DPFinish_#.xml suchen
          $dpFinishFiles = Get-ChildItem -Path $datapathFolder -Filter DPFinish*.xml

          if ($dpFinishFiles)
          {
            # die zuletzt geaenderte Datei nehmen
            $dpFinishFile = $dpFinishFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1

            # die XML-Datei Laden
            $dpFinishXmlContent = Get-Content $dpFinishFile.FullName
            $dpFinishXml = New-Object -TypeName XML
            $dpFinishXml.LoadXml($dpFinishXmlContent)

            # den Wert von StateAfterAdaptation extrahieren
            $stateAfterAdaptation = $dpFinishXml.DataAdaptationRun.AdaptationInfo.StateAfterAdaptation

            # die Werte zum Ergebnisarray hinzufuegen
            $results += New-Object PSObject -Property @{
              'Datapath' = $Datapath
              'StateBeforeAdaptation' = $stateBeforeAdaptation
              'StateAfterAdaptation' = $stateAfterAdaptation
              'ID' = $datapathId
            }
          } else
          {
            # die Werte zum Ergebnisarray hinzufuegen
            $results += New-Object PSObject -Property @{
              'Datapath' = $Datapath
              'StateBeforeAdaptation' = $stateBeforeAdaptation
              'StateAfterAdaptation' = 'FEHLER!'
              'ID' = $datapathId
            }
          }
        }
      }
    }

    # die Ergebnisse in eine Globale Variable zu späteren Anzeige schreiben
    $global:dbresults = $results

    $DatenanpassungsFehler = $false

    foreach ($result in $results)
    {
      if (($result.StateAfterAdaptation -ne "TrafoArchiv") -and  ($result.StateAfterAdaptation -ne "Archiv") -and ($result.StateAfterAdaptation -ne "Angepasst"))
      {
        $DatenanpassungsFehler = $true
        $TestSuccess = $false
        $TestMessage = "Datenbankanpassung mit Fehler"
        Write-Host "[-] DATEV Datenbankanpassung Fehler! Mehr Details: " -ForegroundColor Red -NoNewline; write-host '$DBRESULTS | ogv' -ForegroundColor Cyan
      }
    }
    if ($DatenanpassungsFehler -eq $false)
    {
      Write-Host -ForegroundColor Green "[+] Datenanpassung von heute und ohne Fehler. Mehr details: " -NoNewline; write-host '$DBRESULTS | ogv' -ForegroundColor Cyan
    }
  }


  ############################### Zahlungsverkehr pruefen: ###########################################

  #Write-Host "`nTeste ob der Zahlungsverkehr korrekt laeuft:" -ForegroundColor Cyan

  $kommsession = new-pssession -computername $kommsrv
  $zahlungsverkehrrunning = invoke-command -session $kommsession -scriptblock { get-process -name tocontrol -erroraction silentlycontinue } 
  $zahlungsverkehrinautostart = invoke-command -session $kommsession -scriptblock {Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name WinZV -ErrorAction SilentlyContinue} 

  #pruefen ob der Zahlungsverkehr im Autostart hinterlegt ist
  if (-not $zahlungsverkehrinautostart)
  {
    Write-Host "[o] Zahlungsverkehr Online-Betrieb ist NICHT im Autostart"
  } else
  {
    if ($zahlungsverkehrrunning)
    {
      #pruefen ob Statusdatei vorhanden ist und auslesen
      if (Test-Path "L:\DATEV\DATEN\ZVKW\BESTAND\STANDARD\ToCtrl.sem" -ErrorAction SilentlyContinue)
      {
        $arrZVValues = (Get-Content -Path "L:\DATEV\DATEN\ZVKW\BESTAND\STANDARD\ToCtrl.sem" -ErrorAction SilentlyContinue).Split(",")

        $states = @{
          "1" = "Wird Initialisiert"
          "2" = "Gestartet"
          "7" = "Gestoppt"
          "8" = "Wird gestartet"
        }
        if ($arrZVValues[0] -eq "2")
        {
          Write-host  "[+] Zahlungsverkehr ="$states[$arrZVValues[0]]"seit"$arrZVValues[3] -ForegroundColor Green
        } else
        {
          Write-host  "[-] Zahlungsverkehr ="$states[$arrZVValues[0]]"seit"$arrZVValues[3] -ForegroundColor Red
          $TestSuccess = $false
          $TestMessage = "Zahlungsverkehr = "+$states[$arrZVValues[0]]
        }
      } else
      {Write-Host -ForegroundColor Red "[-] Zahlungverkehr Status konnte nicht ausgelesen werden"
      }
    } else
    {
      Write-Host -ForegroundColor Red "[-] Der Zahlungsverkehr Online-Betrieb ist am $kommsrv nicht gestartet"
      $TestSuccess = $false
      $TestMessage = "Der Zahlungsverkehr nicht gestartet"
    }
  }

  #################################### LiMa Status auslesen: ###########################################
  # Ausfuehren des Programms und Einlesen des Outputs
  #Write-Host "`nLIMA wird getestet:" -ForegroundColor Cyan
  # Programmpfad
  $LimaStatPrg = "$env:datevpp\PROGRAMM\SWS\LimaStatus.exe"

  $pinfo = New-Object System.Diagnostics.ProcessStartInfo
  $pinfo.filename = $LimaStatPrg
  $pinfo.RedirectStandardOutput = $true 
  $pinfo.UseShellExecute = $false 
  $p = New-Object System.Diagnostics.Process
  $p.startinfo = $pinfo
  $p.start() | Out-Null
  $p.WaitForExit() | Out-Null

  if ($p.ExitCode -eq 0)
  {
    Write-Host "[+] Lima funktioniert und ist konsistent." -ForegroundColor Green
  } elseif ($p.ExitCode -eq 4)
  {
    Write-Host "[-] Lima ist inkonsistent!" -ForegroundColor Red
    $TestSuccess = $false
    $TestMessage = "Lima ist inkonsistent!"
  } elseif ($p.ExitCode -eq 1)
  {
    Write-Host "[-] Lima ist nicht gestaretet!" -ForegroundColor Red
    $TestSuccess = $false
    $TestMessage = "Lima nicht gestartet!"
  } else
  {
    Write-Host "[-] Lima konnte nicht getestet werden" -ForegroundColor Yellow
    $TestSuccess = $false
    $TestMessage = "Lima konnte nicht getestet werden"
  }

  ##########################
  #Installierte Versionen pruefen - OPTIMIZED (Decimal Logic & Multi-Language Safe)
  ##########################
  $Scriptblock = {
    $ErrorActionPreference = "Stop"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # -----------------------------------------------------------------------------
    # TEIL 1: Authentifizierung & Session-Aufbau
    # -----------------------------------------------------------------------------
    $UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    $SecChUa = '"Chromium";v="121", "Google Chrome";v="121", "Not_A Brand";v="99"'
    $Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    try {
      # 1. Initiale Cookies
      Invoke-WebRequest -Uri "https://apps.datev.de/myupdates/delivery/all-items" -WebSession $Session -Headers @{
          "Sec-Fetch-Dest"="document"; "Sec-Fetch-Mode"="navigate"; "Sec-Fetch-Site"="none"; "Upgrade-Insecure-Requests"="1"
          "User-Agent"=$UserAgent; "sec-ch-ua"=$SecChUa; "sec-ch-ua-mobile"="?0"; "sec-ch-ua-platform"='"Windows"'
      } -ErrorAction Stop -UseBasicParsing | Out-Null

      # 2. Session & XSRF-Token
      $StatusUrl = "https://apps.datev.de/myupdates/api/login/status"
      Invoke-WebRequest -Uri $StatusUrl -WebSession $Session -Headers @{
          "Sec-Fetch-Dest"="empty"; "Sec-Fetch-Mode"="cors"; "Sec-Fetch-Site"="same-origin"; "X-Requested-With"="dcal"
          "User-Agent"=$UserAgent; "sec-ch-ua"=$SecChUa; "Referer"="https://apps.datev.de/myupdates/delivery/all-items"
      } -ErrorAction Stop -UseBasicParsing | Out-Null

      $XsrfToken = ($Session.Cookies.GetCookies($StatusUrl) | Where-Object { $_.Name -eq "XSRF-TOKEN" }).Value
      if (-not $XsrfToken) { throw "XSRF-TOKEN konnte nicht ermittelt werden." }

      # 3. Header für API-Abrufe vorbereiten
      $HeadersApi = @{
          "Accept"="application/json"; "Content-Type"="application/json"; "X-Requested-With"="dcal"; "X-XSRF-TOKEN"=$XsrfToken
          "User-Agent"=$UserAgent; "sec-ch-ua"=$SecChUa; "Referer"="https://apps.datev.de/myupdates/delivery/all-items"
          "Sec-Fetch-Dest"="empty"; "Sec-Fetch-Mode"="cors"; "Sec-Fetch-Site"="same-origin"
      }

      # -----------------------------------------------------------------------------
      # TEIL 2: Datenabruf & Verarbeitung
      # -----------------------------------------------------------------------------
      $InfoUrl = 'https://apps.datev.de/myupdates/api/amr/myupdates-be/v1/deliveries/info'
      $response = Invoke-RestMethod -Uri $InfoUrl -Method 'GET' -WebSession $Session -Headers $HeadersApi -ErrorAction Stop

      $deliveries = $response.delivery_descriptions | Where-Object { $_ -ne $null }

      $latestReleases = (
        $deliveries |
        Where-Object {
          $deliveryDate = [datetime]$_.delivery_date
          $isReleaseType = $_.delivery_type -in @("service_release", "main_release")
          ($deliveryDate -lt (Get-Date)) -and $isReleaseType
        } |
        Sort-Object @{Expression = {[datetime]$_.delivery_date}; Descending = $true }, `
                    @{Expression = {$_.id}; Descending = $true }
      )

      if ($latestReleases.Count -gt 0) {
        $firstDate = [datetime]$latestReleases[0].delivery_date
        $sameDayReleases = $latestReleases | Where-Object {
          [datetime]$_.delivery_date -eq $firstDate
        }
        
        $ReleasedProducts = @{}
        foreach ($release in $sameDayReleases) {
          $DetailUrl = "https://apps.datev.de/myupdates/api/amr/myupdates-be/v1/deliveries/$($release.id)"
          try {
              $res = Invoke-WebRequest -Uri $DetailUrl -WebSession $Session -Headers $HeadersApi -Method 'GET' -ErrorAction Stop -UseBasicParsing
              
              # Encoding Fix für Umlaute
              $productsJson = [System.Text.Encoding]::UTF8.GetString([System.Text.Encoding]::GetEncoding("ISO-8859-1").GetBytes($res.Content))
              $productsData = $productsJson | ConvertFrom-Json

              $productsData.products | ForEach-Object {
                try {
                  $lastSpaceIndex = $_.title.lastIndexOf(' ')
                  if ($lastSpaceIndex -gt 0) {
                      $ReleasedProducts[$_.title.Substring(0, $lastSpaceIndex).Trim()] = $_.title.Substring($lastSpaceIndex + 1)
                  }
                } catch {}
              }
          } catch {}
        }
      } else {
          $ReleasedProducts = @{}
      }

    } catch {
      $ReleasedProducts = @{}
    }

    # -----------------------------------------------------------------------------
    # TEIL 3: Softwarevergleich (Lokale Registry)
    # -----------------------------------------------------------------------------
    if ($ReleasedProducts.Count -eq 0) {
      Write-Host "[-] $($env:computername) Aktuelle Releases konnten nicht zum Softwarevergleich von der DATEV Website heruntergeladen werden. Bitte manuell pruefen." -ForegroundColor Red
    } else {
      $BasePath = "HKLM:\SOFTWARE\WOW6432Node\DATEVeG\Components"
      if (Test-Path $BasePath) {
        $SoftwareBase = (Get-ChildItem $BasePath).Name
        $errorcount = 0
        foreach ($component in $SoftwareBase) {
          try {
            $productKeyPath = ([string]$component.Replace("HKEY_LOCAL_MACHINE", "HKLM:") + "\Versions")
            $product = Get-ChildItem $productKeyPath -ErrorAction Stop
            
            # Sicherer Abruf der Eigenschaften
            $regProps = Get-ItemProperty -Path $product.Name.Replace("HKEY_LOCAL_MACHINE", "HKLM:") -ErrorAction Stop
            $Name = $regProps.ProductInfoName.Trim()
            
            # Rohwert aus Registry (z.B. "V.16.3")
            $RawLocalVersion = $regProps.ProductInfoVersion
            
            if ($ReleasedProducts.Keys -contains $Name) {
              
              # --- NEUE LOGIK START (DATEV NUMERISCH & MULTI-LANGUAGE SAFE) ---
              
              # 1. Kommas IMMER zu Punkt normalisieren
              # 2. Alles entfernen, was keine Ziffer oder Punkt ist
              # 3. TrimStart('.'): Entfernt den Punkt, der nach dem Löschen von "V" übrig bleibt (".16.3" -> "16.3")
              $CleanLocalVerString = ($RawLocalVersion.ToString().Replace(',', '.') -replace '[^\d\.]', '').TrimStart('.')
              $CleanRemoteVerString = ($ReleasedProducts[$Name].ToString().Replace(',', '.') -replace '[^\d\.]', '').TrimStart('.')

              try {
                  # 3. Explizites Casting in [double] mit InvariantCulture
                  # InvariantCulture ignoriert die OS-Sprache und erzwingt den Punkt als Trenner.
                  $LocalVerVal = [double]::Parse($CleanLocalVerString, [System.Globalization.CultureInfo]::InvariantCulture)
                  $RemoteVerVal = [double]::Parse($CleanRemoteVerString, [System.Globalization.CultureInfo]::InvariantCulture)

                  # 4. Mathematischer Vergleich (16.3 > 16.21 ist hier WAHR)
                  if ($LocalVerVal -ge $RemoteVerVal) {
                    # Installiert ist neuer oder gleich (OK)
                  } else {
                    # Remote ist mathematisch groesser
                    $errorcount++
                    Write-Host "[-] $($env:computername) $Name Installierte Version stimmt nicht mit Release ueberein: $LocalVerVal | $RemoteVerVal -> aktuell" -ForegroundColor Red
                  }

              } catch {
                  # Fallback, falls Casting fehlschlägt
                  Write-Host "[o] $($env:computername) $Name - Version konnte nicht numerisch verglichen werden (Lokal: '$RawLocalVersion' vs Remote: '$($ReleasedProducts[$Name])'). Pilotversion?" -ForegroundColor Yellow
              }
              # --- NEUE LOGIK ENDE ---

            }
          } catch {
            # Fehler ignorieren (Key nicht gefunden etc.)
          }
        }
        if ($errorcount -eq 0) {
          Write-Host "[+] $($env:computername) DATEV Software wurde geprueft. Keine veralteten Produkte gefunden." -ForegroundColor Green
        }
      } else {
        Write-Host "[o] $($env:computername): DATEV Software kann nicht verglichen werden. Pfad nicht gefunden."
      }
    }
  }

  Invoke-SWSubnet -scriptblock $Scriptblock

  ##########################
  #Pruefen ob Netzweite Aktualisierung noch aktiv ist
  ##########################
  if (test-path "L:\DATEV\DATEN\INSTMAN\ASD\") {
    If (Get-Childitem -Path "L:\DATEV\DATEN\INSTMAN\ASD\" -ErrorAction SilentlyContinue -Filter *.dof )
    {
      Write-Host "[-] Es ist noch ein Auftrag zur DATEV Netzweiten aktualisierung vorhanden. Bitte abschließen." -ForegroundColor red
      $TestSuccess = $false
      $TestMessage = "DATEV Netzweite Aktualisierung ist noch nicht abgeschlossen."
    } else
    {
      write-Host "[+] DATEV Netzweite aktualisierung ist abgeschlossen"  -ForegroundColor green
    }
  } else {
    write-Host "[-] Prüfung auf Abschluss der DATEV Netzweiten Aktualisierung fehlgeschlagen: Laufwerk L:\ nicht vorhanden."  -ForegroundColor red
  }

  ##########################
  #DATEV Installationsstatus auswerten und anzeigen
  ##########################
  #$logfile = New-TemporaryFile
  #start-process $ENV:DATEVPP\PROGRAMM\INSTALL\DvInesASDTool.exe -ArgumentList "-collectresults=""$($logfile.FullName)""" -wait

  #$global:DATEVResult = Import-Csv -Path $logfile.FullName -Delimiter ";"

  #if ($DATEVRESULT.count -gt 0)
  #{
   # write-host "[o] DATEV Installationsergebnis:"
    #$DATEVResult | Group-Object Rechnername, Ergebnis | Select-Object Name, Count | Format-Table @{L='Server, Status';E={$_.Name}}, @{L='Anwendungen';E={$_.Count}} | Out-String -Stream | ForEach-Object {Write-Output "    $_"}
    #write-host '    Um weitere Details zur DATEV Installation anzuzeigen, kann der Befehl ' -NoNewline; write-host '$DATEVRESULT | ogv' -ForegroundColor Cyan -NoNewline; Write-host ' verwendet werden'
    
    #} else {
    #  Write-Host "[-] Es konnten keine DATEV Installationsinformationen gefunden werden. Bitte Installationslogbuch pruefen!" -ForegroundColor red
  #}

  ##########################
  # Update Agent Service pruefen (Stop-SWUpdate ausgefuehrt? Abgeschlossen?)
  ##########################
  invoke-swsubnet -scriptblock {if (Get-Service -Name SchuwaUpdateAgent -ErrorAction SilentlyContinue)
    {Write-Host -ForegroundColor yellow "[o] $ENV:COMPUTERNAME Patchday Update Agent laeuft noch. Automatisierung wurde noch nicht abgeschlossen."
    }}

  ##########################
  #Citrix Wartungsmodus pruefen 
  ##########################
 
  $ErrorActionPreference = 'Stop'

  try {
      # --- 1) Controller über SRV-Record finden ---
      $dnsName = "swctxdc._tcp.$($env:USERDNSDOMAIN)"
      $srv = Resolve-DnsName -Type SRV -Name $dnsName |
            Sort-Object -Property Priority,Weight |
            Select-Object -First 1

      if (-not $srv) { throw "Kein SRV-Record für $dnsName gefunden." }

      $ctxComputerName = $srv.NameTarget.TrimEnd('.')


      # --- 2) SessionTimeOuts (lokal, NICHT remote!) ---
      $so = New-PSSessionOption -OperationTimeout 180000 -IdleTimeout 600000


      # --- 3) RemoteSession öffnen ---
      $ctxSession = New-PSSession -ComputerName $ctxComputerName `
                                  -ConfigurationName CitrixConfig `
                                  -SessionOption $so


      # --- 4) ABSOLUT minimaler Citrix Remote Call ---
      #     Keine Syntax, keine Arrays, keine Variablen: nur 1 Cmdlet
      $ctxBroker = Invoke-Command -Session $ctxSession -ScriptBlock {
          Get-BrokerMachine
      }


      # --- 5) Lokale Auswertung ---
      $TestSuccess = $true
      $TestMessage = "Wartungsmodus aus."

      foreach ($m in $ctxBroker) {
          if ($m.InMaintenanceMode) {
              Write-Host -ForegroundColor Red "[-] $($m.MachineName) Wartungsmodus aktiv!"
              $TestSuccess = $false
              $TestMessage = "Mindestens ein System im Wartungsmodus."
          }
          else {
              Write-Host -ForegroundColor Green "[+] $($m.MachineName) Wartungsmodus aus."
          }
      }
  }
  catch {
      Write-Warning "Fehler: $($_.Exception.Message)"
  }
  finally {
      # --- 6) Session bereinigen ---
      if ($ctxSession) {
          try { Remove-PSSession -Session $ctxSession }
          catch { Write-Warning "Session konnte nicht entfernt werden: $($_.Exception.Message)" }
      }
  }

  ##########################
  #Ergebnis an OT uebermitteln
  ##########################
  if ($TestSuccess)
  {
    Send-PatchdayOTState("8 - Tests abgeschlossen: erfolgreich")
  } else
  {
    Send-PatchdayOTState("7 - Tests abgeschlossen: FEHLER: "+$TestMessage)
  }
}

While ($True)
{
  AutoPostPatchdayTest
  $confirmation = Read-Host "Soll der automatische Test wiederholt werden? (y/n)"
  if ($confirmation -eq "n")
  {
    break
  }
}
