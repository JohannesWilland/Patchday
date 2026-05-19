
# Definition der XML-Vorlagen als Here-Strings
# HINWEIS: Bitte den Inhalt von $KorrekteVorlage durch das tatsächliche Ziel-XML ersetzen!

$FalscheVorlage = @"
<?xml version="1.0"  encoding="UTF-8"?>
<FrxProfileFolderRedirection>
	<Excludes>
		<Exclude>AppData\Local\Microsoft\Edge\User Data\Default\Service Worker</Exclude>
		<Exclude>AppData\Local\Microsoft\Edge\User Data\Default\Media Cache</Exclude>
		<Exclude>AppData\Local\Microsoft\Edge\User Data\Default\Code Cache</Exclude>
		<Exclude>AppData\Local\Microsoft\Edge\User Data\Default\Cache</Exclude>
		<Exclude>AppData\Local\Google\Chrome\User Data\Default\Cache</Exclude>
		<Exclude>AppData\Local\Google\Chrome\User Data\Default\Media Cache</Exclude>
		<Exclude>AppData\Local\Google\Chrome\User Data\Default\Code Cache</Exclude>
		<Exclude>AppData\Local\Google\Chrome\User Data\Default\Service Worker</Exclude>
		<Exclude>AppData\Roaming\Google\Chrome\Default\Cache</Exclude>
		<Exclude>AppData\Roaming\Google\Chrome\Default\Media Cache</Exclude>
		<Exclude>AppData\Roaming\Google\Chrome\Default\Code Cache</Exclude>
		<Exclude>AppData\Roaming\Google\Chrome\Default\Service Worker</Exclude>
		<Exclude>AppData\Local\Citrix</Exclude>
		<Exclude>AppData\Local\Microsoft\Windows\INetCache</Exclude>
		<Exclude>AppData\Local\Microsoft\Windows\WebCache</Exclude>
		<Exclude>AppData\Local\Microsoft\Windows\WebCache.old</Exclude>
		<Exclude>AppData\Local\Microsoft\Windows\WER</Exclude>
		<Exclude>AppData\Local\DATEV\LOG</Exclude>
		<Exclude>AppData\Local\CrashDumps</Exclude>
		<Exclude>AppData\LocalLow</Exclude>
		<Exclude>AppData\Local\Microsoft\Windows\Burn</Exclude>
		<Exclude>AppData\Local\Microsoft\Terminal Server Client</Exclude>
		<Exclude>AppData\Local\Temp</Exclude>
		<Exclude>AppData\Local\Packages</Exclude>
		<Exclude>AppData\Local\Microsoft\Teams\Packages\SquirrelTemp</Exclude>
		<Exclude>AppData\Local\Microsoft\Teams\current\resources\locales</Exclude>
		<Exclude>AppData\Local\Microsoft\Teams\Current\Locales</Exclude>
		<Exclude>AppData\Roaming\Microsoft\Teams\Service Worker\CacheStorage</Exclude>
		<Exclude>AppData\Roaming\Microsoft\Teams\Application Cache</Exclude>
		<Exclude>AppData\Roaming\Microsoft\Teams\Cache</Exclude>
		<Exclude>AppData\Roaming\Microsoft Teams\Logs</Exclude>
		<Exclude>AppData\Roaming\Microsoft\Teams\Media-Stack</Exclude>
    </Excludes>
</FrxProfileFolderRedirection>
"@

$KorrekteVorlage = @"
<?xml version="1.0"  encoding="UTF-8"?>
<FrxProfileFolderRedirection>
    <Excludes>
        <Exclude>AppData\Local\Microsoft\Edge\User Data\Default\Service Worker</Exclude>
        <Exclude>AppData\Local\Microsoft\Edge\User Data\Default\Media Cache</Exclude>
        <Exclude>AppData\Local\Microsoft\Edge\User Data\Default\Code Cache</Exclude>
        <Exclude>AppData\Local\Microsoft\Edge\User Data\Default\Cache</Exclude>
        <Exclude>AppData\Local\Citrix</Exclude>
        <Exclude>AppData\Local\Microsoft\Windows\INetCache</Exclude>
        <Exclude>AppData\Local\Microsoft\Windows\WebCache</Exclude>
        <Exclude>AppData\Local\Microsoft\Windows\WebCache.old</Exclude>
        <Exclude>AppData\Local\Microsoft\Windows\WER</Exclude>
        <Exclude>AppData\Local\DATEV\LOG</Exclude>
        <Exclude>AppData\Local\CrashDumps</Exclude>
        <Exclude>AppData\Local\Microsoft\Windows\Burn</Exclude>
        <Exclude>AppData\Local\Microsoft\Terminal Server Client</Exclude>
        <Exclude>AppData\Local\Temp</Exclude>
        <Exclude>AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs</Exclude>
        <Exclude>AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\PerfLogs</Exclude>
        <Exclude>AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView\WV2Profile_tfw\WebStorage</Exclude>
    </Excludes>
</FrxProfileFolderRedirection>
"@

# 1. Umgebung prüfen und Pfad festlegen
if ($env:SWFILESRV1 -or ($env:USERDNSDOMAIN -match "sw750")) {
    # Lokaler ASP 3.0 Pfad
    $FilePath = "D:\Customer\Netlogon\redirections.xml"
    Write-Host "ASP 3.0 Umgebung erkannt. Nutze Pfad: $FilePath" -ForegroundColor Cyan
} elseif ($env:USERDNSDOMAIN) {
    # ASP 2.0 Umgebung (über administrativen Share)
    $FilePath = "\\$env:USERDNSDOMAIN\C$\Windows\SYSVOL\domain\scripts\redirections.xml"
    Write-Host "ASP 2.0 Umgebung erkannt. Nutze Pfad: $FilePath" -ForegroundColor Cyan
} else {
    Write-Host "Fehler: Konnte weder ASP2 noch ASP3 Variablen ermitteln." -ForegroundColor Red
    exit
}

# 2. Prüfen, ob die Datei existiert
if (-not (Test-Path $FilePath)) {
    Write-Host "Fehler: Die Datei $FilePath wurde nicht gefunden." -ForegroundColor Red
    exit
}

# 3. Dateiinhalt einlesen (-Raw liest die Datei als einen zusammenhängenden String ein)
$CurrentContent = Get-Content -Path $FilePath -Raw

# Entfernt jegliche Leerzeichen, Tabs und Zeilenumbrüche komplett aus dem String
$CurrentNoSpace = $CurrentContent -replace '\s+', ''
$FalscheNoSpace = $FalscheVorlage -replace '\s+', ''
$KorrekteNoSpace = $KorrekteVorlage -replace '\s+', ''

# 4. Logik zur Auswertung und Anpassung
if ($CurrentNoSpace -eq $KorrekteNoSpace) {
    Write-Host "Entspricht bereits dem Standard" -ForegroundColor Green
}
elseif ($CurrentNoSpace -eq $FalscheNoSpace) {
    # Ersetzen durch die korrekte Vorlage
    try {
        $KorrekteVorlage | Set-Content -Path $FilePath -Encoding UTF8 -Force
        Write-Host "Falsche Vorlage erkannt und erfolgreich durch den Standard ausgetauscht." -ForegroundColor Green
    } catch {
        Write-Host "Fehler beim Schreiben der Datei: $_" -ForegroundColor Red
    }
}
else {
    # Inhalt entspricht weder der korrekten noch der exakt falschen Vorlage
    if ($CurrentContent -match "<Exclude>AppData\\Local\\Packages</Exclude>") {
        Write-Host "Achtung gefährliche Excludes gesetzt!" -ForegroundColor Red
    } else {
        Write-Host "entspricht nicht dem Standard" -ForegroundColor Yellow
    }

    Write-Host "================ A K T U E L L E R   I N H A L T ================" -ForegroundColor Cyan
    Write-Host $CurrentContent -ForegroundColor Gray
    Write-Host "=================================================================" -ForegroundColor Cyan
    
    # Sicherheitsabfrage für unbekannte Inhalte
    $UserInput = Read-Host "Möchten Sie diesen abweichenden Inhalt durch den Standard ersetzen? (Zum Bestätigen 'y' eingeben)"
    
    if ($UserInput -eq "y") {
        try {
        $KorrekteVorlage | Set-Content -Path $FilePath -Encoding UTF8 -Force
        Write-Host "Abweichender Inhalt erfolgreich durch den Standard ausgetauscht." -ForegroundColor Green
        } catch {
        Write-Host "Fehler beim Schreiben der Datei: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Vorgang abgebrochen. Die Datei wurde nicht verändert." -ForegroundColor Yellow
    }
}