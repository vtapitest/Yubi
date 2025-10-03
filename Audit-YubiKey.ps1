[CmdletBinding()]
param(
  [string]$Serial,                              # Nº de serie de la YubiKey a auditar (opcional)
  [string]$OutBase = "yubikey_audit_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss"),
  [switch]$ListFidoResidentCredentials,         # Activa el listado de credenciales FIDO2 residentes (requiere PIN)
  [string]$FidoPin,                             # PIN FIDO2 (opcional si activas el switch de arriba)
  [switch]$ListOathAccounts,                    # Activa el listado de cuentas OATH (puede requerir toque o password)
  [string]$OathPassword                         # Contraseña OATH si la tienes configurada
)

# ---------------- Helpers ----------------
function Find-Ykman {
  $cmd = @(Get-Command ykman -ErrorAction SilentlyContinue, Get-Command ykman.exe -ErrorAction SilentlyContinue) |
         Where-Object { $_ } | Select-Object -First 1
  if (-not $cmd) {
    throw "No se encontró 'ykman' en el PATH. Instala YubiKey Manager CLI o abre una consola donde esté disponible."
  }
  return $cmd.Path
}

function Invoke-Ykman {
  param([string[]]$Args)
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $script:ykmanPath
  $psi.Arguments = [string]::Join(' ', ($Args | ForEach-Object {
      # Escapar argumentos con espacios
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

# --------------- Inicio ---------------
try { $script:ykmanPath = Find-Ykman } catch { Write-Error $_; exit 1 }

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
    $args = @("fido","credentials","list","--pin",$FidoPin)
    $report.sections += Run-Section -Name "fido_credentials_list" -Args $args
  }
} else {
  $report.warnings += "No se listan credenciales FIDO2 residentes (activa -ListFidoResidentCredentials y aporta -FidoPin para incluirlo)."
}

# --------- PIV ----------
$report.sections += Run-Section -Name "piv_info"            -Args @("piv","info")
$report.sections += Run-Section -Name "piv_list_certificates" -Args @("piv","list-certificates")

# --------- OpenPGP ----------
$report.sections += Run-Section -Name "openpgp_info" -Args @("openpgp","info")

# --------- OTP ----------
$report.sections += Run-Section -Name "otp_info"  -Args @("otp","info")
$report.sections += Run-Section -Name "otp_list"  -Args @("otp","list")

# --------- OATH (TOTP/HOTP app) ----------
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

# JSON completo
$report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding UTF8

# Markdown legible
$md = @()
$md += "# Informe de auditoría YubiKey"
$md += ""
$md += "*Generado:* $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$md += "*Equipo:* $($report.meta.host)"
$md += "*ykman:* $($report.meta.ykman_path)"
if ($Serial) { $md += "*Serie usada:* $Serial" }
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
