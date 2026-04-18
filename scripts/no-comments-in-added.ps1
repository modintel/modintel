$files = @(git diff --cached --name-only --diff-filter=ACMR)
$files = $files | Where-Object { $_ -and $_.Trim().Length -gt 0 }

if ($files.Count -eq 0) {
    exit 0
}

$ignoreFragments = @(
    "node_modules/",
    "node_modules\\"
)

function Get-FileKind {
    param([string]$file)

    $ext = [System.IO.Path]::GetExtension($file).ToLowerInvariant()
    $name = [System.IO.Path]::GetFileName($file).ToLowerInvariant()

    if ($name -eq "dockerfile" -or $name -like "dockerfile.*" -or $ext -eq ".dockerfile") {
        return "hash"
    }

    switch ($ext) {
        ".dart" { return "slash" }
        ".ts" { return "slash" }
        ".tsx" { return "slash" }
        ".js" { return "slash" }
        ".jsx" { return "slash" }
        ".kt" { return "slash" }
        ".java" { return "slash" }
        ".gradle" { return "slash" }
        ".kts" { return "slash" }
        ".go" { return "slash" }
        ".css" { return "css" }
        ".scss" { return "css" }
        ".py" { return "hash" }
        ".yml" { return "hash" }
        ".yaml" { return "hash" }
        ".ps1" { return "hash" }
        ".sh" { return "shell" }
        ".xml" { return "xml" }
        ".html" { return "xml" }
        ".conf" { return "conf" }
        default { return $null }
    }
}

function Test-LineHasComment {
    param(
        [string]$line,
        [string]$kind,
        [int]$lineNumber
    )

    $trimmed = $line.TrimStart()

    switch ($kind) {
        "slash" {
            if ($line -match "(?<!http:)(?<!https:)//" -or $line -match "/\*" -or $line -match "\*/") {
                return $true
            }
        }
        "css" {
            if ($line -match "//" -or $line -match "/\*" -or $line -match "\*/") {
                return $true
            }
        }
        "hash" {
            if ($trimmed.StartsWith("#")) {
                return $true
            }
        }
        "shell" {
            if ($lineNumber -eq 1 -and $trimmed.StartsWith("#!")) {
                return $false
            }
            if ($trimmed.StartsWith("#")) {
                return $true
            }
        }
        "xml" {
            if ($line -match "<!--" -or $line -match "-->") {
                return $true
            }
        }
        "conf" {
            if ($trimmed.StartsWith("#") -or $trimmed.StartsWith(";")) {
                return $true
            }
        }
    }

    return $false
}

$violations = @()

foreach ($file in $files) {
    $skip = $false
    foreach ($fragment in $ignoreFragments) {
        if ($file -like "*$fragment*") {
            $skip = $true
            break
        }
    }
    if ($skip) {
        continue
    }

    $kind = Get-FileKind -file $file
    if (-not $kind) {
        continue
    }

    $diff = git diff --cached --no-color -- "$file" 2>$null
    if ($LASTEXITCODE -ne 0 -or $null -eq $diff) {
        continue
    }

    $lineNumber = 0
    foreach ($line in ($diff -split "`r?`n")) {
        $lineNumber++
        if ($line.StartsWith("+") -and -not $line.StartsWith("+++")) {
            $contentLine = $line.Substring(1)
            if (Test-LineHasComment -line $contentLine -kind $kind -lineNumber $lineNumber) {
                $violations += [PSCustomObject]@{
                    File = $file
                    Line = $lineNumber
                    Text = $contentLine.Trim()
                }
            }
        }
    }
}

if ($violations.Count -gt 0) {
    Write-Error "Staged files contain comments. Remove them before committing."
    foreach ($v in $violations) {
        Write-Host ("{0}:{1} -> {2}" -f $v.File, $v.Line, $v.Text)
    }
    exit 1
}

exit 0
