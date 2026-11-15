<#
.SYNOPSIS
    Audita una skill, plugin o repositorio de terceros antes de instalarlo (Zero-Trust).

.DESCRIPTION
    Analisis estatico de codigo y prompts, hashes SHA-256/MD5 y veredicto
    PASS / REVIEW / BLOCK. No ejecuta nada: solo lee archivos.

.PARAMETER Path
    Carpeta o archivo a auditar.

.PARAMETER Json
    Devuelve el resultado en JSON.

.PARAMETER MaxFileMB
    Tamano maximo (MB) de archivo a escanear. Por defecto 5.

.EXAMPLE
    .\auditar-skill.ps1 -Path "C:\skills\desconocida"

.EXAMPLE
    .\auditar-skill.ps1 -Path ".\plugin" -Json | Out-File reporte.json

.OUTPUTS
    Codigo de salida: 0 = PASS, 1 = REVIEW, 2 = BLOCK.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path,

    [switch]$Json,

    [int]$MaxFileMB = 5
)

$ErrorActionPreference = 'Stop'

$TextExtensions = @(
    '.ps1', '.psm1', '.psd1', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
    '.py', '.sh', '.bash', '.bat', '.cmd', '.rb', '.go', '.rs', '.java', '.kt',
    '.php', '.pl', '.lua', '.sql', '.json', '.yaml', '.yml', '.toml', '.xml',
    '.md', '.markdown', '.txt', '.html', '.htm', '.css', '.ini', '.cfg', '.conf',
    '.env', '.vdf', '.acf', '.gradle'
)

$BinaryExtensions = @('.exe', '.dll', '.so', '.dylib', '.bin', '.msi', '.node', '.pyc')

$ExcludedDirs = @('.git', '.svn', '.hg', 'node_modules', 'vendor', 'dist', 'build', '__pycache__', '.venv', 'venv')

# Reglas: High = 25, Medium = 10, Low = 3
$Rules = @(
    @{ Id = 'EXEC001'; Severity = 'High';   Tag = 'Ejecucion dinamica de codigo'; Regex = '(?i)\b(eval|exec)\s*\(' }
    @{ Id = 'EXEC002'; Severity = 'High';   Tag = 'Ejecucion de procesos o shell';  Regex = '(?i)\b(child_process|subprocess|os\.system|os\.popen|Runtime\.getRuntime)\b' }
    @{ Id = 'EXEC003'; Severity = 'High';   Tag = 'Ejecucion dinamica en PowerShell'; Regex = '(?i)(Invoke-Expression|\biex\b|-EncodedCommand)' }
    @{ Id = 'NET001';  Severity = 'High';   Tag = 'IP de metadata de nube';          Regex = '169\.254\.169\.254' }
    @{ Id = 'SEC001';  Severity = 'High';   Tag = 'Lectura de variables de entorno'; Regex = '(?i)(process\.env|os\.environ|\$env:)' }
    @{ Id = 'SEC002';  Severity = 'High';   Tag = 'Acceso a llaves o credenciales';  Regex = '(?i)(id_rsa|id_ed25519|\.aws[\\/]|\.ssh[\\/]|credentials\.json|\.netrc)' }
    @{ Id = 'OBF001';  Severity = 'High';   Tag = 'Decodificacion Base64';            Regex = '(?i)(FromBase64String|atob\s*\(|base64\s+--decode|base64\s+-d\b)' }
    @{ Id = 'TRV001';  Severity = 'High';   Tag = 'Path traversal';                   Regex = '(\.\.[\\/]){2,}' }
    @{ Id = 'PRV001';  Severity = 'High';   Tag = 'Contenedor privilegiado / socket'; Regex = '(?i)(--privileged|docker\.sock)' }
    @{ Id = 'INJ001';  Severity = 'High';   Tag = 'Prompt injection: ignorar reglas'; Regex = '(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts?)' }
    @{ Id = 'INJ002';  Severity = 'High';   Tag = 'Prompt injection: ocultar al usuario'; Regex = '(?i)(do\s+not|don''t|never)\s+(tell|inform|notify|reveal\s+to)\s+(the\s+)?(user|human)' }
    @{ Id = 'INJ003';  Severity = 'High';   Tag = 'Prompt injection: system prompt'; Regex = '(?i)(system\s+prompt|developer\s+message|hidden\s+instruction)' }
    @{ Id = 'NET002';  Severity = 'Medium'; Tag = 'Llamada de red';                Regex = '(?i)\b(fetch|urllib|requests\.(get|post)|http\.client|Invoke-WebRequest|Invoke-RestMethod|curl|wget|socket\.socket)\b' }
    @{ Id = 'SEC003';  Severity = 'Medium'; Tag = 'Credencial hardcodeada';        Regex = '(?i)(api[_-]?key|secret|passwd|password|token)\s*[:=]\s*["'']?' }
    @{ Id = 'OBF002';  Severity = 'Medium'; Tag = 'Blob Base64 largo';             Regex = '[A-Za-z0-9+/]{80,}={0,2}' }
    @{ Id = 'TRV002';  Severity = 'Medium'; Tag = 'Ruta de sistema o perfil';      Regex = '(?i)(/etc/passwd|\$HOME|%USERPROFILE%)' }
    @{ Id = 'FS001';   Severity = 'Medium'; Tag = 'Operacion destructiva';         Regex = '(?i)(Remove-Item|rm\s+-rf|del\s+/[fsq]|format\s+[a-z]:)' }
    @{ Id = 'INJ004';  Severity = 'Medium'; Tag = 'Comentario HTML oculto';        Regex = '<!--' }
    @{ Id = 'NET003';  Severity = 'Low';    Tag = 'URL HTTP(S)';                   Regex = '(?i)https?://' }
    @{ Id = 'SEC004';  Severity = 'Low';    Tag = 'Referencia a .env';             Regex = '(?i)\.env\b' }
    @{ Id = 'INJ005';  Severity = 'Low';    Tag = 'Caracteres de ancho cero';      Regex = '[\u200B-\u200D\uFEFF]' }
    @{ Id = 'SEC005';  Severity = 'Critical'; Tag = 'Formato de credencial real';  Regex = '(?i)(sk-[a-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)' }
)

function Test-SkipPath {
    param([string]$FullName)
    $parts = $FullName.Split([IO.Path]::DirectorySeparatorChar)
    foreach ($p in $parts) {
        if ($ExcludedDirs -contains $p) { return $true }
    }
    return $false
}

function Test-PublicIp {
    param([string]$Text)
    $found = @()
    foreach ($m in [regex]::Matches($Text, '(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])')) {
        $candidate = $m.Groups[1].Value
        $ip = $null
        if ([System.Net.IPAddress]::TryParse($candidate, [ref]$ip)) {
            $b = $ip.GetAddressBytes()
            $private = ($b[0] -eq 10) -or ($b[0] -eq 127) -or ($b[0] -eq 0) -or
                       ($b[0] -eq 192 -and $b[1] -eq 168) -or
                       ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
                       ($b[0] -ge 224)
            if (-not $private) { $found += $candidate }
        }
    }
    return $found
}

# --- Recoleccion de archivos -------------------------------------------
if (-not (Test-Path -LiteralPath $Path)) {
    Write-Error "La ruta no existe: $Path"
    exit 1
}

$target = (Resolve-Path -LiteralPath $Path).Path
$isContainer = Test-Path -LiteralPath $target -PathType Container

if ($isContainer) {
    $files = Get-ChildItem -LiteralPath $target -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { -not (Test-SkipPath -FullName $_.FullName) }
} else {
    $files = @(Get-Item -LiteralPath $target -Force)
}

$findings = New-Object System.Collections.Generic.List[object]
$hashes = New-Object System.Collections.Generic.List[object]
$scanned = 0

foreach ($f in $files) {
    $sha = $null
    $md5 = $null
    try {
        $sha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        $md5 = (Get-FileHash -LiteralPath $f.FullName -Algorithm MD5 -ErrorAction Stop).Hash
    } catch {
        $sha = 'ERROR'
    }
    $hashes.Add([pscustomobject]@{
        File = $f.FullName
        Size = $f.Length
        SHA256 = $sha
        MD5 = $md5
    })

    $ext = $f.Extension.ToLowerInvariant()

    # No auditar el propio motor de reglas (se autodetectaria por sus patrones)
    if ($PSCommandPath -and $f.FullName -eq $PSCommandPath) { continue }

    # Archivo .env: contenedor habitual de secretos
    if ($f.Name -match '^\.env') {
        $findings.Add([pscustomobject]@{
            Rule = 'SEC006'; Severity = 'Medium'; Message = 'Archivo .env presente'
            File = $f.FullName; Line = 0; Snippet = $f.Name
        })
    }

    if ($BinaryExtensions -contains $ext) {
        $findings.Add([pscustomobject]@{
            Rule = 'BIN001'; Severity = 'Info'; Message = 'Binario ejecutable presente'
            File = $f.FullName; Line = 0; Snippet = "$([math]::Round($f.Length / 1KB, 1)) KB"
        })
        continue
    }

    if ($TextExtensions -notcontains $ext) { continue }
    if ($f.Length -gt ($MaxFileMB * 1MB)) { continue }

    $content = $null
    try { $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { continue }
    if ([string]::IsNullOrEmpty($content)) { continue }
    $scanned++

    $lines = $content -split "`r?`n"

    foreach ($rule in $Rules) {
        $hits = 0
        for ($i = 0; $i -lt $lines.Length; $i++) {
            if ($lines[$i] -match $rule.Regex) {
                $hits++
                if ($hits -le 3) {
                    $snippet = $lines[$i].Trim()
                    if ($snippet.Length -gt 160) { $snippet = $snippet.Substring(0, 160) + '...' }
                    $findings.Add([pscustomobject]@{
                        Rule = $rule.Id; Severity = $rule.Severity; Message = $rule.Tag
                        File = $f.FullName; Line = ($i + 1); Snippet = $snippet
                    })
                }
            }
        }
    }

    # IP publica embebida
    $publicIps = Test-PublicIp -Text $content
    if ($publicIps.Count -gt 0) {
        $findings.Add([pscustomobject]@{
            Rule = 'NET004'; Severity = 'Medium'; Message = 'IP publica embebida'
            File = $f.FullName; Line = 0; Snippet = (($publicIps | Select-Object -Unique -First 5) -join ', ')
        })
    }
}

# --- Puntuacion ---------------------------------------------------------
$critical = @($findings | Where-Object { $_.Severity -eq 'Critical' }).Count
$high = @($findings | Where-Object { $_.Severity -eq 'High' }).Count
$medium = @($findings | Where-Object { $_.Severity -eq 'Medium' }).Count
$low = @($findings | Where-Object { $_.Severity -eq 'Low' }).Count

$score = ($critical * 50) + ($high * 25) + ($medium * 10) + ($low * 3)
if ($score -gt 100) { $score = 100 }

if ($score -ge 50) { $verdict = 'BLOCK' }
elseif ($score -ge 15) { $verdict = 'REVIEW' }
else { $verdict = 'PASS' }

$result = [pscustomobject]@{
    Target = $target
    ScannedAt = (Get-Date).ToString('s')
    FileCount = @($files).Count
    ScannedTextFiles = $scanned
    Score = $score
    Verdict = $verdict
    Counts = [pscustomobject]@{ Critical = $critical; High = $high; Medium = $medium; Low = $low; Info = (@($findings | Where-Object { $_.Severity -eq 'Info' }).Count) }
    Findings = $findings
    Hashes = $hashes
}

if ($Json) {
    $result | ConvertTo-Json -Depth 6
} else {
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add('=== AUDITORIA DE SEGURIDAD DE SKILL ===')
    $out.Add("Objetivo   : $target")
    $out.Add("Fecha      : $($result.ScannedAt)")
    $out.Add("Archivos   : $($result.FileCount) (texto escaneado: $scanned)")
    $out.Add('')
    $out.Add("Hallazgos  : $critical criticos, $high altos, $medium medios, $low bajos")
    $out.Add('')

    if ($findings.Count -eq 0) {
        $out.Add('Sin hallazgos.')
    } else {
        foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Info')) {
            $group = @($findings | Where-Object { $_.Severity -eq $sev })
            if ($group.Count -eq 0) { continue }
            $out.Add("--- $($sev.ToUpper()) ---")
            foreach ($x in $group) {
                $loc = $x.File
                if ($x.Line -gt 0) { $loc = "$($x.File):$($x.Line)" }
                $out.Add("[$($x.Rule)] $($x.Message)")
                $out.Add("    $loc")
                if ($x.Snippet) { $out.Add("    > $($x.Snippet)") }
            }
            $out.Add('')
        }
    }

    $out.Add('--- HASHES SHA-256 ---')
    $shown = @($hashes | Select-Object -First 25)
    foreach ($h in $shown) {
        $out.Add("$($h.SHA256)  $($h.File)")
    }
    if ($hashes.Count -gt $shown.Count) {
        $out.Add("... y $($hashes.Count - $shown.Count) archivos mas (usa -Json para el listado completo)")
    }

    $out.Add('')
    $out.Add("VEREDICTO: $verdict  (riesgo $score/100)")
    $out.Add('')

    $out -join [Environment]::NewLine | Write-Output
}

switch ($verdict) {
    'BLOCK'  { exit 2 }
    'REVIEW' { exit 1 }
    default  { exit 0 }
}
