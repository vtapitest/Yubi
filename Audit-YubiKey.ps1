[CmdletBinding()]
param(
  [string]$Serial,                              # Nº de serie (si no lo pasas, te pedirá elegir)
  [string]$OutBase = "yubikey_audit_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss"),
  [switch]$ListFidoResidentCredentials,         # Incluye credenciales FIDO2 residentes (requiere PIN)
  [string]$FidoPin,                             # PIN FIDO2 si activas la opción anterior
  [switch]$ListOathAccounts,                    # Incluye cuentas OATH (puede requerir toque / password)
  [string]$OathPassword                         # Contraseña OATH si procede
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

# --------- Guardar archivos ----------
$jsonPath = "$OutBase.json"
$mdPath   = "$OutBase.md"

# JSON completo
$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding UTF8

# Markdown legible (usando 4 backticks como fence)
$fence = '````'

$md = @()
$md += "# Informe de auditoría YubiKey"
$md += ""
$md += "*Generado:* $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$md += "*Equipo:* $($report.meta.host)"
$md += "*ykman:* $($report.meta.ykman_path)"
$md += "*Serie usada:* $Serial"
$md += ""
if ($report.warnings.Count) {
  $md += "## Avisos"
  foreach ($w in $report.warnings) { $md += "- $w" }
  $md += ""
}
$md += "## Secciones"
foreach ($s in $report.sections) {
  $status = if ($s.ok) { "✅" } else { "⚠️" }
  $md += "### $status $($s.name)"
  $md += ""
  $md += "**Comando:**"
  $md += ""
  $md += $fence + "bash"
  $md += $s.command
  $md += $fence
  $md += ""
  $md += "**Salida:**"
  $md += ""
  $md += $fence
  $md += ($s.output | Out-String).TrimEnd()
  $md += $fence
  $md += ""
}
$md -join "`r`n" | Out-File -FilePath $mdPath -Encoding UTF8

Write-Host "`nListo."
Write-Host "JSON:    $jsonPath"
Write-Host "Markdown:$mdPath`n"
