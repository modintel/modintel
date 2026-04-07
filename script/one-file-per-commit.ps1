$files = git diff --cached --name-only --diff-filter=ACM
if ($files.Count -gt 1) {
    Write-Host "ERROR: Multiple files in commit. Each commit should have only 1 file."
    Write-Host "Files staged: $($files -join ', ')"
    exit 1
}
