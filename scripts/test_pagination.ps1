# ModIntel Pagination Testing Script
# Tests cursor-based and offset-based pagination

param(
    [string]$BaseUrl = "http://localhost:3000",
    [string]$Token = ""
)

Write-Host "=== ModIntel Pagination Test Suite ===" -ForegroundColor Cyan
Write-Host ""

if ($Token -eq "") {
    Write-Host "ERROR: JWT token required" -ForegroundColor Red
    Write-Host "Usage: .\test_pagination.ps1 -Token 'your_jwt_token'" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To get your token:" -ForegroundColor Yellow
    Write-Host "1. Open browser DevTools (F12)" -ForegroundColor Yellow
    Write-Host "2. Go to Console tab" -ForegroundColor Yellow
    Write-Host "3. Run: localStorage.getItem('access_token')" -ForegroundColor Yellow
    exit 1
}

$headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type" = "application/json"
}

$testsPassed = 0
$testsFailed = 0

function Test-Endpoint {
    param($Name, $Url, $ExpectedStatus, $Validator)
    
    Write-Host "Testing: $Name" -ForegroundColor Yellow
    try {
        $response = Invoke-WebRequest -Uri $Url -Headers $headers -Method GET -ErrorAction Stop
        $data = $response.Content | ConvertFrom-Json
        
        if ($response.StatusCode -eq $ExpectedStatus) {
            if ($null -eq $Validator -or (& $Validator $data)) {
                Write-Host "  PASS" -ForegroundColor Green
                $script:testsPassed++
                return $data
            } else {
                Write-Host "  FAIL: Validation failed" -ForegroundColor Red
                $script:testsFailed++
            }
        } else {
            Write-Host "  FAIL: Expected status $ExpectedStatus, got $($response.StatusCode)" -ForegroundColor Red
            $script:testsFailed++
        }
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq $ExpectedStatus) {
            Write-Host "  PASS (Expected error)" -ForegroundColor Green
            $script:testsPassed++
        } else {
            Write-Host "  FAIL: $($_.Exception.Message)" -ForegroundColor Red
            $script:testsFailed++
        }
    }
    Write-Host ""
}

# Test 1: Cursor-based pagination - First page
Write-Host "`n--- Cursor-Based Pagination Tests ---" -ForegroundColor Cyan
Test-Endpoint `
    "Logs - First page (limit=5)" `
    "$BaseUrl/api/logs?limit=5" `
    200 `
    { param($d) $d.data -and $d.limit -eq 5 -and $d.PSObject.Properties.Name -contains 'next_cursor' }

# Test 2: Cursor-based pagination - With cursor
$firstPage = Test-Endpoint `
    "Logs - First page (limit=10)" `
    "$BaseUrl/api/logs?limit=10" `
    200 `
    { param($d) $d.data -and $d.data.Count -le 10 }

if ($firstPage -and $firstPage.next_cursor) {
    Test-Endpoint `
        "Logs - Second page (with cursor)" `
        "$BaseUrl/api/logs?cursor=$($firstPage.next_cursor)&limit=10" `
        200 `
        { param($d) $d.data -and $d.limit -eq 10 }
}

# Test 3: Invalid cursor
Test-Endpoint `
    "Logs - Invalid cursor" `
    "$BaseUrl/api/logs?cursor=invalid123&limit=10" `
    400 `
    { param($d) $d.error -eq "invalid cursor" }

# Test 4: Invalid limit (too high)
Test-Endpoint `
    "Logs - Limit too high (501)" `
    "$BaseUrl/api/logs?limit=501" `
    400 `
    { param($d) $d.error -like "*limit*" }

# Test 5: Invalid limit (too low)
Test-Endpoint `
    "Logs - Limit too low (0)" `
    "$BaseUrl/api/logs?limit=0" `
    400 `
    { param($d) $d.error -like "*limit*" }

# Test 6: Offset-based pagination - First page
Write-Host "`n--- Offset-Based Pagination Tests ---" -ForegroundColor Cyan
Test-Endpoint `
    "Rules - First page" `
    "$BaseUrl/api/rules?page=1&limit=10" `
    200 `
    { param($d) $d.data -and $d.page -eq 1 -and $d.page_size -eq 10 -and $d.PSObject.Properties.Name -contains 'total_count' }

# Test 7: Offset-based pagination - Second page
Test-Endpoint `
    "Rules - Second page" `
    "$BaseUrl/api/rules?page=2&limit=10" `
    200 `
    { param($d) $d.data -and $d.page -eq 2 }

# Test 8: Invalid page (0)
Test-Endpoint `
    "Rules - Invalid page (0)" `
    "$BaseUrl/api/rules?page=0&limit=10" `
    400 `
    { param($d) $d.error -like "*pagination*" }

# Test 9: Invalid page (negative)
Test-Endpoint `
    "Rules - Invalid page (-1)" `
    "$BaseUrl/api/rules?page=-1&limit=10" `
    400 `
    { param($d) $d.error -like "*pagination*" }

# Test 10: Default parameters
Write-Host "`n--- Default Parameter Tests ---" -ForegroundColor Cyan
Test-Endpoint `
    "Logs - No parameters (should default to limit=50)" `
    "$BaseUrl/api/logs" `
    200 `
    { param($d) $d.data -and $d.limit -eq 50 }

Test-Endpoint `
    "Rules - No parameters (should default to page=1, limit=50)" `
    "$BaseUrl/api/rules" `
    200 `
    { param($d) $d.data -and $d.page -eq 1 -and $d.page_size -eq 50 }

# Test 11: Maximum limit
Write-Host "`n--- Boundary Tests ---" -ForegroundColor Cyan
Test-Endpoint `
    "Logs - Maximum limit (500)" `
    "$BaseUrl/api/logs?limit=500" `
    200 `
    { param($d) $d.data -and $d.limit -eq 500 }

# Test 12: Alerts endpoint (new)
Write-Host "`n--- New Alerts Endpoint Tests ---" -ForegroundColor Cyan
Test-Endpoint `
    "Alerts - First page" `
    "$BaseUrl/api/alerts?limit=10" `
    200 `
    { param($d) $d.data -and $d.limit -eq 10 }

# Summary
Write-Host "`n=== Test Summary ===" -ForegroundColor Cyan
Write-Host "Passed: $testsPassed" -ForegroundColor Green
Write-Host "Failed: $testsFailed" -ForegroundColor Red
Write-Host ""

if ($testsFailed -eq 0) {
    Write-Host "All tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some tests failed" -ForegroundColor Red
    exit 1
}
