$msg = Get-Content .git/COMMIT_EDITMSG -Raw
$msg = $msg.Trim()

if ($msg -notmatch '^(feat|fix|docs|style|ci|refactor|test|chore|build)(\(.+\))?:') {
    Write-Error 'Commit must start with: feat|fix|docs|style|ci|refactor|test|chore|build'
    exit 1
}

$body = $msg -replace '^(feat|fix|docs|style|ci|refactor|test|chore|build)(\(.+\))?:\s*', ''
if ($body -cmatch '[A-Z]') {
    Write-Error 'Commit message must be all lowercase'
    exit 1
}

Write-Host 'Commit message OK'
exit 0
