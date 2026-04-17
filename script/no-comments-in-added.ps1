$files = git diff --cached --name-only --diff-filter=A
$files = $files | Where-Object { $_ -and $_.Trim().Length -gt 0 }

if (-not $files) {
    exit 0
}

$ignoreFragments = @(
    "node_modules",
    ".env.example",
    "dashboard",
    "landing-site",
    "docs",
    "ml-pipeline",
    "proxy-waf",
    "services",
    "src",
    ".agents"
)

$extensions = @(
    ".dart",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".kt",
    ".java",
    ".gradle",
    ".kts",
    ".yml",
    ".yaml",
    ".ps1",
    ".sh",
    ".xml",
    ".html",
    ".css",
    ".scss",
    ".go",
    ".py",
    ".dockerfile",
    ".conf"
)

$commentFiles = @()

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

    $ext = [System.IO.Path]::GetExtension($file)
    if (-not $extensions.Contains($ext)) {
        continue
    }

    if (-not (Test-Path $file)) {
        continue
    }

    $content = Get-Content -Raw -LiteralPath $file -ErrorAction SilentlyContinue
    if ($null -eq $content) {
        continue
    }

    $hasComment = $false

    if ($ext -in @(".dart", ".ts", ".tsx", ".js", ".jsx", ".kt", ".java", ".gradle", ".kts", ".go", ".py", ".dockerfile")) {
        if ($content -match "(?m)^\s*//") {
            $hasComment = $true
        }
        if ($ext -eq ".py" -and $content -match "(?m)^\s*#") {
            $hasComment = $true
        }
        if ($ext -eq ".dockerfile" -and $content -match "(?m)^\s*#") {
            $hasComment = $true
        }
    }
    elseif ($ext -in @(".yml", ".yaml", ".ps1", ".sh")) {
        if ($ext -eq ".sh") {
            $lines = $content -split "`n"
            foreach ($line in $lines) {
                $trimmed = $line.TrimStart()
                if ($trimmed.StartsWith("#") -and -not $trimmed.StartsWith("#!")) {
                    $hasComment = $true
                    break
                }
            }
        }
        else {
            if ($content -match "(?m)^\s*#") {
                $hasComment = $true
            }
        }
    }
    elseif ($ext -in @(".xml", ".html")) {
        if ($content -match "<!--") {
            $hasComment = $true
        }
    }
    elseif ($ext -in @(".css", ".scss")) {
        if ($content -match "(?m)^\s*//") {
            $hasComment = $true
        }
    }
    elseif ($ext -in @(".conf")) {
        if ($content -match "(?m)^\s*#") {
            $hasComment = $true
        }
    }

    if ($hasComment) {
        $commentFiles += $file
    }
}

if ($commentFiles.Count -gt 0) {
    Write-Error "Added files contain comments:`n$($commentFiles -join "`n")"
    exit 1
}

exit 0
