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
  if ($candidatos) { return $candidatos[0] }

  throw "No se encontró 'ykman'. Instala YubiKey Manager CLI o añade la ruta al PATH."
}

function Invoke-Ykman {
  param([string[]]$Args)
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $script:ykmanPath
  $psi.Arguments = [string]::Join(' ', ($Args | ForEach-Object {
      if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ }
  }))
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
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
    [string[]]$Args
  )
  if ($Serial) { $Args = @("--device", $Serial) + $Args }
  $res = Invoke-Ykman -Args $Args
  $ok  = ($res.ExitCode -eq 0)
  [pscustomobject]@{
    name    = $Name
    ok      = $ok
    command = $res.Command
    output  = if ($ok) { $res.StdOut } else { $res.StdErr }
  }
}

function Select-YubiKey {
  # Obtenemos etiquetas (modelo + interfaces)
  $listRes = Invoke-Ykman -Args @("list")
  if ($listRes.ExitCode -ne 0) {
    throw "Error en 'ykman list': $($listRes.StdErr)"
  }
  $labels = $listRes.StdOut -split "`r?`n" | Where-Object { $_.Trim() }

  if (-not $labels -or $labels.Count -eq 0) {
    throw "No se detectaron YubiKeys conectadas."
  }

  # Intentamos obtener seriales alineados por índice
  $serials = @()
  $serRes = Invoke-Ykman -Args @("list","--serials")
  if ($serRes.ExitCode -eq 0 -and $serRes.StdOut.Trim()) {
    $serials = $serRes.StdOut -split "`r?`n" | Where-Object { $_.Trim() }
  } else {
    # Fallback: intentar extraer 'Serial: 1234567' de cada línea
    foreach ($l in $labels) {
      if ($l -match '(?i)serial[:\s]+(\d{4,})') { $serials += $matches[1] } else { $serials += $null }
    }
  }

  # Emparejar por índice
  $count = [Math]::Min($labels.Count, $serials.Count)
  $devices = for ($i=0; $i -lt $count; $i++) {
    [pscustomobject]@{
      Index  = $i + 1
      Serial = $serials[$i]
      Label  = $labels[$i]
    }
  }

  if ($devices.Count -eq 1) {
    Write-Host "Se encontró 1 YubiKey:"
    Write-Host ("  1) [Serial: {0}] {1}" -f ($devices[0].Serial ?? "desconocido"), $devices[0].Label)
    if (-not $devices[0].Serial) { throw "No se pudo determinar el serial de la YubiKey." }
    return $devices[0].Serial
  }

  Write-Host "Dispositivos detectados:"
  foreach ($d in $devices) {
    $s = if ($d.Serial) { $d.Serial } else { "desconocido" }
    Write-Host ("  {0}) [Serial: {1}] {2}" -f $d.Index, $s, $d.Label)
  }

  # Bucle de selección
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
$report.sections += Run-Section -Name "ykman_version" -Args @("--version")
$report.sections += Run-Section -Name "devices_list"   -Args @("list")
$report.sections += Run-Section -Name "device_info"     -Args @("info")
$report.sections += Run-Section -Name "config_list"     -Args @("config","list")

# --------- FIDO2 ----------
$report.sections += Run-Section -Name "fido_info"       -Args @("fido","info")

if ($ListFidoResidentCredentials) {
  if (-not $FidoPin) {
    $report.warnings += "Se solicitó listar credenciales FIDO2 residentes pero no se proporcionó PIN. Omitiendo para evitar bloqueo interactivo."
  } else {
    $report.sections += Run-Section -Name "fido_credentials_list" -Args @("fido","credentials","list","--pin",$FidoPin)
  }
} else {
  $report.warnings += "No se listan credenciales FIDO2 residentes (activa -ListFidoResidentCredentials y aporta -FidoPin para incluirlo)."
}

# --------- PIV ----------
$report.sections += Run-Section -Name "piv_info"              -Args @("piv","info")
$report.sections += Run-Section -Name "piv_list_certificates" -Args @("piv","list-certificates")

# --------- OpenPGP ----------
$report.sections += Run-Section -Name "openpgp_info" -Args @("openpgp","info")

# --------- OTP ----------
$report.sections += Run-Section -Name "otp_info"  -Args @("otp","info")
$report.sections += Run-Section -Name "otp_list"  -Args @("otp","list")

# --------- OATH ----------
$report.sections += Run-Section -Name "oath_info" -Args @("oath","info")
if ($ListOathAccounts) {
  $args = @("oath","accounts","list")
  if ($OathPassword) { $args += @("--password",$OathPassword) }
  $report.sections += Run-Section -Name "oath_accounts_list" -Args $args
} else {
  $report.warnings += "No se listan cuentas OATH (activa -ListOathAccounts y, si procede, -OathPassword). Puede requerir tocar la YubiKey."
}

# --------- Guardar archivos ----------
$jsonPath = "$OutBase.json"
$mdPath   = "$OutBase.md"

$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding UTF8

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
  $report.warnings | ForEach-Object { $md += "- $_" }
  $md += ""
}
$md += "## Secciones"
foreach ($s in $report.sections) {
  $status = if ($s.ok) { "✅" } else { "⚠️" }
  $md += "### $status $($s.name)"
  $md += ""
  $md += "**Comando:**"
  $md += ""
  $md += "```bash"
  $md += $s.command
  $md += "```"
  $md += ""
  $md += "**Salida:**"
  $md += ""
  $md += "```"
  $md += ($s.output | Out-String).TrimEnd()
  $md += "```"
  $md += ""
}
$md -join "`r`n" | Out-File -FilePath $mdPath -Encoding UTF8

Write-Host "`nListo."
Write-Host "JSON:    $jsonPath"
Write-Host "Markdown:$mdPath`n"
