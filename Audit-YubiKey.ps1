[CmdletBinding()]
param(
  [string]$Serial,                              # Nº de serie (si no lo pasas, te pedirá elegir)
  [switch]$ListFidoResidentCredentials,         # Incluye credenciales FIDO2 residentes (requiere PIN)
  [string]$FidoPin,                             # PIN FIDO2 si activas la opción anterior
  [switch]$ListOathAccounts,                    # Incluye cuentas OATH (puede requerir toque / password)
  [string]$OathPassword,                        # Contraseña OATH si procede
  [string]$OutHtml,                             # Ruta de salida HTML opcional (p.ej. .\informe.html)
  [string]$OutJson                              # Ruta de salida JSON opcional
)

# ---------------- Helpers ----------------
function Find-Ykman {
  $cmd = Get-Command -Name ykman, ykman.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($cmd) { return $cmd.Path }
  $candidatos = @(
    "$Env:ProgramFiles\Yubico\YubiKey Manager\ykman.exe",
    "${Env:ProgramFiles(x86)}\Yubico\YubiKey Manager\ykman.exe"
  ) | Where-Object { Test-Path $_ }
  if ($candidatos -and $candidatos.Count -gt 0) { return $candidatos[0] }
  throw "No se encontró 'ykman'. Instala YubiKey Manager CLI o añade la ruta al PATH."
}

function Get-SerialDigits {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
  $m = [regex]::Match($Text.Trim(), '^\d+$')
  if ($m.Success) { return $m.Value } else { return $null }
}

function Invoke-Ykman {
  param([string[]]$CmdArgs)
  if ($null -eq $CmdArgs) { $CmdArgs = @() }
  $escapedCmdArgs = @()
  foreach ($a in $CmdArgs) {
    if ($null -eq $a) { continue }
    $a = $a -replace '"','`"'
    if ($a -match '\s') { $escapedCmdArgs += ('"{0}"' -f $a) } else { $escapedCmdArgs += $a }
  }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $script:ykmanPath
  $psi.Arguments = ($escapedCmdArgs -join ' ')
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  [pscustomobject]@{
    ExitCode = $p.ExitCode
    StdOut   = $stdout.Trim()
    StdErr   = $stderr.Trim()
    Command  = "$($script:ykmanPath) $($psi.Arguments)"
  }
}

# Detecta si tu ykman soporta la opción global --device
function Test-DeviceSupport {
  $h = Invoke-Ykman -CmdArgs @("--help")
  if ($h.ExitCode -ne 0) { return $false }
  return ($h.StdOut -match "(?m)--device\b")
}

# Ejecuta una sección, aplicando --device solo si es soportado y no es 'list'
function Run-Section {
  param(
    [string]$Name,
    [string[]]$CmdArgs,
    [switch]$NoDeviceOverride   # TRUE para comandos como "list"
  )
  if ($null -eq $CmdArgs) { $CmdArgs = @() }
  if ($CmdArgs.Count -eq 0) { throw "Run-Section '$Name' fue invocado sin argumentos." }

  $first = $CmdArgs[0]
  $isListCmd = ($first -eq "list")

  $finalArgs = @()
  if (-not $NoDeviceOverride -and -not $isListCmd -and $script:SupportsDevice -and $script:UseSerial) {
    $finalArgs += @("--device", $script:UseSerial)
  }
  $finalArgs += $CmdArgs

  $res = Invoke-Ykman -CmdArgs $finalArgs
  $ok  = ($res.ExitCode -eq 0)
  [pscustomobject]@{
    name    = $Name
    ok      = $ok
    command = $res.Command
    output  = if ($ok) { $res.StdOut } else { $res.StdErr }
  }
}

# Cuando no haya --device, intenta etiquetar con 'info' del único dispositivo
function Probe-LabelFromInfo_NoDevice {
  $r = Invoke-Ykman -CmdArgs @("info")
  if ($r.ExitCode -ne 0) { return "(YubiKey)" }
  $lines = $r.StdOut -split "`r?`n"
  $type = ($lines | Where-Object { $_ -match '^(?i)Device type:\s*(.+)$' } | ForEach-Object { $matches[1].Trim() } | Select-Object -First 1)
  $fw   = ($lines | Where-Object { $_ -match '^(?i)Firmware version:\s*(.+)$' } | ForEach-Object { $matches[1].Trim() } | Select-Object -First 1)
  if ($type -and $fw) { return "$type (fw $fw)" }
  if ($type) { return $type }
  return "(YubiKey)"
}

function Build-DeviceListBySerial {
  # Siempre sin --device
  $serRes = Invoke-Ykman -CmdArgs @("list","--serials")
  if ($serRes.ExitCode -ne 0 -or -not $serRes.StdOut.Trim()) { return @() }
  $serials = $serRes.StdOut -split "`r?`n" | Where-Object { $_ -and $_.Trim() }
  $out = @()
  $i = 1
  foreach ($s in $serials) {
    $d = Get-SerialDigits $s
    if (-not $d) { continue }
    $label = if ($script:SupportsDevice) {
      # Si soporta --device podemos pedir info específico
      $ri = Invoke-Ykman -CmdArgs @("--device", $d, "info")
      if ($ri.ExitCode -eq 0) {
        $lines = $ri.StdOut -split "`r?`n"
        $type = ($lines | Where-Object { $_ -match '^(?i)Device type:\s*(.+)$' } | ForEach-Object { $matches[1].Trim() } | Select-Object -First 1)
        $fw   = ($lines | Where-Object { $_ -match '^(?i)Firmware version:\s*(.+)$' } | ForEach-Object { $matches[1].Trim() } | Select-Object -First 1)
        if ($type -and $fw) { "$type (fw $fw)" } elseif ($type) { $type } else { "[Serial $d]" }
      } else { "[Serial $d]" }
    } else {
      # Sin --device no podemos diferenciar, damos etiqueta genérica
      Probe-LabelFromInfo_NoDevice
    }
    $out += [pscustomobject]@{ Index = $i; Serial = $d; Label = $label }
    $i++
  }
  return $out
}

function Select-YubiKey {
  $devices = Build-DeviceListBySerial
  if ($devices.Count -gt 0) {
    if ($devices.Count -eq 1) {
      Write-Host "Se encontró 1 YubiKey:"
      Write-Host ("  1) [Serial: {0}] {1}" -f $devices[0].Serial, $devices[0].Label)
      return $devices[0].Serial
    }
    Write-Host "Dispositivos detectados (por serial):"
    foreach ($d in $devices) { Write-Host ("  {0}) [Serial: {1}] {2}" -f $d.Index, $d.Serial, $d.Label) }
    while ($true) {
      $inp = Read-Host ("Elige 1-{0} (Enter=1)" -f $devices.Count)
      if ([string]::IsNullOrWhiteSpace($inp)) { $inp = "1" }
      if ($inp -as [int] -and [int]$inp -ge 1 -and [int]$inp -le $devices.Count) {
        $choice = $devices[[int]$inp - 1]
        return $choice.Serial
      }
      Write-Host "Selección no válida. Intenta de nuevo."
    }
  }

  # Fallback: sin serial visible, permitir continuar solo con 1 dispositivo conectado
  $listRes = Invoke-Ykman -CmdArgs @("list")
  if ($listRes.ExitCode -ne 0) { throw "No se pudo listar dispositivos: $($listRes.StdErr)" }
  $labels = $listRes.StdOut -split "`r?`n" | Where-Object { $_ -and $_.Trim() }
  if ($labels.Count -eq 1) {
    Write-Warning "La YubiKey no expone serial o la versión de ykman no lo soporta. Continuaré sin --device; conecta SOLO esta YubiKey."
    return $null
  }
  throw "No hay seriales disponibles y hay varias YubiKeys conectadas. Desconecta las demás o usa una versión de ykman con soporte de serial."
}

function Escape-Html { param([string]$Text)
  if ($null -eq $Text) { return "" }
  $x = $Text -replace '&','&amp;'
  $x = $x -replace '<','&lt;'
  $x = $x -replace '>','&gt;'
  return $x
}

function Write-SectionConsole {
  param([pscustomobject]$Section)
  $bar = ('-' * 70)
  $status = 'ERROR'; $fg = 'Yellow'
  if ($Section.ok) { $status = 'OK'; $fg = 'Green' }
  Write-Host $bar
  Write-Host ("[{0}] {1}" -f $status, $Section.name) -ForegroundColor $fg
  Write-Host "Comando:"
  Write-Host ("  {0}" -f $Section.command)
  Write-Host "Salida:"
  Write-Host ($Section.output)
}

# --------------- Inicio ---------------
try { $script:ykmanPath = Find-Ykman } catch { Write-Error $_; exit 1 }

# Detectar soporte de --device
$script:SupportsDevice = Test-DeviceSupport
if (-not $script:SupportsDevice) {
  Write-Warning "Tu versión de 'ykman' no soporta la opción global --device. Ejecutaré todos los comandos sin --device."
}

# Selección de dispositivo (si hay serial y soporte se usará; si no, se ignora)
if (-not $Serial) {
  try {
    $Serial = Select-YubiKey
    if ($Serial) {
      $Serial = Get-SerialDigits $Serial
      Write-Host "Seleccionado serial: $Serial`n"
    } else {
      Write-Host "Sin serial (único dispositivo conectado).`n"
    }
  } catch { Write-Error $_; exit 1 }
} else {
  $Serial = Get-SerialDigits $Serial
  if (-not $Serial) { Write-Error "El serial proporcionado no es numérico."; exit 1 }
}

# Solo usaremos el serial si ykman soporta --device
$script:UseSerial = $null
if ($script:SupportsDevice -and $Serial) { $script:UseSerial = $Serial }

$report = [ordered]@{
  meta = [ordered]@{
    generated_at = (Get-Date).ToString("s")
    host         = $env:COMPUTERNAME
    ykman_path   = $script:ykmanPath
    serial_used  = $script:UseSerial
    options      = [ordered]@{
      ListFidoResidentCredentials = [bool]$ListFidoResidentCredentials
      ListOathAccounts            = [bool]$ListOathAccounts
    }
  }
  sections = @()
  warnings = @()
}

# --------- General ----------
$report.sections += Run-Section -Name "ykman_version"  -CmdArgs @("--version")
$report.sections += Run-Section -Name "list_devices"   -CmdArgs @("list") -NoDeviceOverride
$report.sections += Run-Section -Name "device_info"    -CmdArgs @("info")

# Config list -> usar usb/nfc --list
$report.sections += Run-Section -Name "config_usb_list" -CmdArgs @("config","usb","--list")
$report.sections += Run-Section -Name "config_nfc_list" -CmdArgs @("config","nfc","--list")

# --------- FIDO2 ----------
$report.sections += Run-Section -Name "fido_info" -CmdArgs @("fido","info")
if ($ListFidoResidentCredentials) {
  if (-not $FidoPin) {
    $report.warnings += "Se solicitó listar credenciales FIDO2 residentes pero no se proporcionó PIN. Omitiendo para evitar bloqueo interactivo."
  } else {
    $report.sections += Run-Section -Name "fido_credentials_list" -CmdArgs @("fido","credentials","list","--pin",$FidoPin)
  }
} else {
  $report.warnings += "No se listan credenciales FIDO2 residentes (activa -ListFidoResidentCredentials y aporta -FidoPin para incluirlo)."
}

# --------- PIV ----------
$report.sections += Run-Section -Name "piv_info" -CmdArgs @("piv","info")

# --------- OpenPGP ----------
$report.sections += Run-Section -Name "openpgp_info" -CmdArgs @("openpgp","info")

# --------- OTP ----------
$report.sections += Run-Section -Name "otp_info" -CmdArgs @("otp","info")

# --------- OATH ----------
$report.sections += Run-Section -Name "oath_info" -CmdArgs @("oath","info")
if ($ListOathAccounts) {
  $cmdArgsOath = @("oath","accounts","list")
  if ($OathPassword) { $cmdArgsOath += @("--password",$OathPassword) }
  $report.sections += Run-Section -Name "oath_accounts_list" -CmdArgs $cmdArgsOath
} else {
  $report.warnings += "No se listan cuentas OATH (activa -ListOathAccounts y, si procede, -OathPassword). Puede requerir tocar la YubiKey."
}

# --------- Salida por CONSOLA ---------
Write-Host ""
Write-Host "===== Auditoría YubiKey =====" -ForegroundColor Cyan
Write-Host ("Equipo: {0}" -f $report.meta.host)
Write-Host ("ykman:  {0}" -f $report.meta.ykman_path)
$serialDisplay = $report.meta.serial_used
if (-not $serialDisplay) { $serialDisplay = "(no disponible / no soportado)" }
Write-Host ("Serie:  {0}" -f $serialDisplay)
Write-Host ("Fecha:  {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
if ($report.warnings.Count) {
  Write-Host "`nAvisos:" -ForegroundColor Yellow
  foreach ($w in $report.warnings) { Write-Host (" - {0}" -f $w) -ForegroundColor Yellow }
}
Write-Host ""
foreach ($s in $report.sections) { Write-SectionConsole -Section $s }
Write-Host ('-' * 70)

# --------- Exportaciones opcionales ---------
if ($OutJson) {
  try {
    $report | ConvertTo-Json -Depth 8 | Out-File -FilePath $OutJson -Encoding UTF8
    Write-Host ("JSON guardado en: {0}" -f $OutJson) -ForegroundColor Green
  } catch {
    Write-Warning ("No se pudo escribir JSON en '{0}': {1}" -f $OutJson, $_.Exception.Message)
  }
}

if ($OutHtml) {
  try {
    function HTML-Report {
      param($report)
      $html = @()
      $html += '<!doctype html>'
      $html += '<html lang="es"><head><meta charset="utf-8">'
      $html += '<meta name="viewport" content="width=device-width, initial-scale=1">'
      $html += '<title>Informe YubiKey</title>'
      $html += '<style>
        body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",Arial,sans-serif;background:#0b0f14;color:#e6edf3;margin:2rem;}
        h1,h2,h3{color:#fff}
        .meta{margin-bottom:1rem;opacity:.9}
        .warn{background:#583b00;color:#ffd78e;padding:.5rem .75rem;border-radius:.5rem;margin:.5rem 0}
        section{background:#0f1720;border:1px solid #1f2a37;border-radius:.75rem;margin:1rem 0;padding:1rem}
        .ok{color:#22c55e} .err{color:#f59e0b}
        pre{background:#0b1220;border:1px solid #1f2a37;padding:1rem;border-radius:.5rem;overflow:auto}
        code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
        .cmd{opacity:.9}
      </style></head><body>'
      $html += '<h1>Informe de auditoría YubiKey</h1>'
      $metaSerial = $report.meta.serial_used
      if (-not $metaSerial) { $metaSerial = "(no disponible / no soportado)" }
      $html += ('<div class="meta"><div><strong>Equipo:</strong> {0}</div><div><strong>ykman:</strong> {1}</div><div><strong>Serie:</strong> {2}</div><div><strong>Generado:</strong> {3}</div></div>' -f
        (Escape-Html $report.meta.host),
        (Escape-Html $report.meta.ykman_path),
        (Escape-Html $metaSerial),
        (Escape-Html ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')))
      )
      if ($report.warnings.Count) {
        foreach ($w in $report.warnings) { $html += ('<div class="warn">⚠️ {0}</div>' -f (Escape-Html $w)) }
      }
      foreach ($s in $report.sections) {
        $cls = 'err'; $icon = '⚠️'
        if ($s.ok) { $cls = 'ok'; $icon = '✅' }
        $html += ('<section><h2 class="{0}">{1} {2}</h2>' -f $cls, $icon, (Escape-Html $s.name))
        $html += '<h3>Comando</h3>'
        $html += ('<pre class="cmd"><code>{0}</code></pre>' -f (Escape-Html $s.command))
        $html += '<h3>Salida</h3>'
        $html += ('<pre><code>{0}</code></pre>' -f (Escape-Html $s.output))
        $html += '</section>'
      }
      $html += '</body></html>'
      return ($html -join "`r`n")
    }
    (HTML-Report -report $report) | Out-File -FilePath $OutHtml -Encoding UTF8
    Write-Host ("HTML guardado en: {0}" -f $OutHtml) -ForegroundColor Green
  } catch {
    Write-Warning ("No se pudo escribir HTML en '{0}': {1}" -f $OutHtml, $_.Exception.Message)
  }
}
