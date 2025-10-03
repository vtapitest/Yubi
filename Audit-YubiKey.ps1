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
  $cmd = Get-Command -Name ykman, ykman.exe -ErrorAction SilentlyContinue |
         Select-Object -First 1
  if ($cmd) { return $cmd.Path }

  # Fallbacks típicos de instalación en Windows
  $candidatos = @(
    "$Env:ProgramFiles\Yubico\YubiKey Manager\ykman.exe",
    "${Env:ProgramFiles(x86)}\Yubico\YubiKey Manager\ykman.exe"
  ) | Where-Object { Test-Path $_ }
  if ($candidatos -and $candidatos.Count -gt 0) { return $candidatos[0] }

  throw "No se encontró 'ykman'. Instala YubiKey Manager CLI o añade la ruta al PATH."
}

function Invoke-Ykman {
  param([string[]]$CmdArgs)

  # Normaliza y filtra nulls
  if ($null -eq $CmdArgs) { $CmdArgs = @() }
  $escapedCmdArgs = @()
  foreach ($a in $CmdArgs) {
    if ($null -eq $a) { continue }
    # Escapa comillas
    $a = $a -replace '"','`"'
    # Si tiene espacios, lo envolvemos entre comillas
    if ($a -match '\s') { $escapedCmdArgs += ('"{0}"' -f $a) } else { $escapedCmdArgs += $a }
  }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $script:ykmanPath
  # -join tolera arrays vacíos
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

function Run-Section {
  param(
    [string]$Name,
    [string[]]$CmdArgs
  )
  if ($null -eq $CmdArgs) { $CmdArgs = @() }
  if ($Serial) { $CmdArgs = @("--device", $Serial) + $CmdArgs }
  if ($CmdArgs.Count -eq 0) {
    throw "Run-Section '$Name' fue invocado sin argumentos."
  }
  $res = Invoke-Ykman -CmdArgs $CmdArgs
  $ok  = ($res.ExitCode -eq 0)
  [pscustomobject]@{
    name    = $Name
    ok      = $ok
    command = $res.Command
    output  = if ($ok) { $res.StdOut } else { $res.StdErr }
  }
}

function Select-YubiKey {
  # Listado de dispositivos (etiquetas)
  $listRes = Invoke-Ykman -CmdArgs @("list")
  if ($listRes.ExitCode -ne 0) {
    throw "Error en 'ykman list': $($listRes.StdErr)"
  }
  $labels = $listRes.StdOut -split "`r?`n" | Where-Object { $_ -and $_.Trim() }

  if (-not $labels -or $labels.Count -eq 0) {
    throw "No se detectaron YubiKeys conectadas."
  }

  # Seriales por índice
  $serials = @()
  $serRes = Invoke-Ykman -CmdArgs @("list","--serials")
  if ($serRes.ExitCode -eq 0 -and $serRes.StdOut.Trim()) {
    $serials = $serRes.StdOut -split "`r?`n" | Where-Object { $_ -and $_.Trim() }
  } else {
    foreach ($l in $labels) {
      if ($l -match '(?i)serial[:\s]+(\d{4,})') { $serials += $matches[1] } else { $serials += $null }
    }
  }

  $count = [Math]::Min($labels.Count, $serials.Count)
  $devices = @()
  for ($i=0; $i -lt $count; $i++) {
    $devices += [pscustomobject]@{
      Index  = $i + 1
      Serial = $serials[$i]
      Label  = $labels[$i]
    }
  }

  if ($devices.Count -eq 1) {
    Write-Host "Se encontró 1 YubiKey:"
    $serialDisplay = if ($devices[0].Serial) { $devices[0].Serial } else { "desconocido" }
    Write-Host ("  1) [Serial: {0}] {1}" -f $serialDisplay, $devices[0].Label)
    if (-not $devices[0].Serial) { throw "No se pudo determinar el serial de la YubiKey." }
    return $devices[0].Serial
  }

  Write-Host "Dispositivos detectados:"
  foreach ($d in $devices) {
    $s = if ($d.Serial) { $d.Serial } else { "desconocido" }
    Write-Host ("  {0}) [Serial: {1}] {2}" -f $d.Index, $s, $d.Label)
  }

  while ($true) {
    $inp = Read-Host ("Elige 1-{0} (Enter=1)" -f $devices.Count)
    if ([string]::IsNullOrWhiteSpace($inp)) { $inp = "1" }
    if ($inp -as [int] -and [int]$inp -ge 1 -and [int]$inp -le $devices.Count) {
      $choice = $devices[[int]$inp - 1]
      if (-not $choice.Serial) { throw "No se pudo determinar el serial del dispositivo seleccionado." }
      return $choice.Serial
    }
    Write-Host "Selección no válida. Intenta de nuevo."
  }
}

function Escape-Html {
  param([string]$Text)
  if ($null -eq $Text) { return "" }
  $x = $Text -replace '&','&amp;'
  $x = $x -replace '<','&lt;'
  $x = $x -replace '>','&gt;'
  return $x
}

function Write-SectionConsole {
  param([pscustomobject]$Section)
  $bar = ('-' * 70)

  # Precalcular estado y color (sin if inline)
  $status = 'ERROR'
  $fg = 'Yellow'
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

# Si no se pasó -Serial, pedimos selección interactiva
if (-not $Serial) {
  try {
    $Serial = Select-YubiKey
    Write-Host "Usando YubiKey con Serial: $Serial`n"
  } catch {
    Write-Error $_
    exit 1
  }
}

$report = [ordered]@{
  meta = [ordered]@{
    generated_at = (Get-Date).ToString("s")
    host         = $env:COMPUTERNAME
    ykman_path   = $script:ykmanPath
    serial_used  = $Serial
    options      = [ordered]@{
      ListFidoResidentCredentials = [bool]$ListFidoResidentCredentials
      ListOathAccounts            = [bool]$ListOathAccounts
    }
  }
  sections = @()
  warnings = @()
}

# --------- General ----------
$report.sections += Run-Section -Name "ykman_version" -CmdArgs @("--version")
$report.sections += Run-Section -Name "devices_list"  -CmdArgs @("list")
$report.sections += Run-Section -Name "device_info"   -CmdArgs @("info")
$report.sections += Run-Section -Name "config_list"   -CmdArgs @("config","list")

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
$report.sections += Run-Section -Name "piv_info"              -CmdArgs @("piv","info")
$report.sections += Run-Section -Name "piv_list_certificates" -CmdArgs @("piv","list-certificates")

# --------- OpenPGP ----------
$report.sections += Run-Section -Name "openpgp_info" -CmdArgs @("openpgp","info")

# --------- OTP ----------
$report.sections += Run-Section -Name "otp_info" -CmdArgs @("otp","info")
$report.sections += Run-Section -Name "otp_list" -CmdArgs @("otp","list")

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
Write-Host ("Serie:  {0}" -f $report.meta.serial_used)
Write-Host ("Fecha:  {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
if ($report.warnings.Count) {
  Write-Host "`nAvisos:" -ForegroundColor Yellow
  foreach ($w in $report.warnings) { Write-Host (" - {0}" -f $w) -ForegroundColor Yellow }
}
Write-Host ""

foreach ($s in $report.sections) {
  Write-SectionConsole -Section $s
}
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
    $html += ('<div class="meta"><div><strong>Equipo:</strong> {0}</div><div><strong>ykman:</strong> {1}</div><div><strong>Serie:</strong> {2}</div><div><strong>Generado:</strong> {3}</div></div>' -f
      (Escape-Html $report.meta.host),
      (Escape-Html $report.meta.ykman_path),
      (Escape-Html $report.meta.serial_used),
      (Escape-Html ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')))
    )

    if ($report.warnings.Count) {
      foreach ($w in $report.warnings) {
        $html += ('<div class="warn">⚠️ {0}</div>' -f (Escape-Html $w))
      }
    }

    foreach ($s in $report.sections) {
      # Precalcular clase e icono (sin if inline)
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
    $html -join "`r`n" | Out-File -FilePath $OutHtml -Encoding UTF8
    Write-Host ("HTML guardado en: {0}" -f $OutHtml) -ForegroundColor Green
  } catch {
    Write-Warning ("No se pudo escribir HTML en '{0}': {1}" -f $OutHtml, $_.Exception.Message)
  }
}
