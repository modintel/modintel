# Unified Reliability Model - Test Suite
# Usage: ./scripts/test_reliability.ps1
# Optional: ./scripts/test_reliability.ps1 -BaseUrl http://somehost:8082

param(
    [string]$BaseUrl = "http://localhost:8082"
)

$testsPassed = 0
$testsFailed = 0

function Test-IsValidUUID([string]$s) {
    if ($s.Length -ne 36) { return $false }
    $parts = $s -split '-'
    if ($parts.Count -ne 5) { return $false }
    if ($parts[0].Length -ne 8)  { return $false }
    if ($parts[1].Length -ne 4)  { return $false }
    if ($parts[2].Length -ne 4)  { return $false }
    if ($parts[3].Length -ne 4)  { return $false }
    if ($parts[4].Length -ne 12) { return $false }
    foreach ($part in $parts) {
        if ($part -notmatch '^[0-9a-fA-F]+$') { return $false }
    }
    return $true
}

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [int]$ExpectedStatus = 200,
        [scriptblock]$Validator = $null
    )

    Write-Host "`n=== Testing: $Name ===" -ForegroundColor Cyan

    try {
        $params = @{
            Uri             = $Url
            Method          = $Method
            Headers         = $Headers
            UseBasicParsing = $true
        }

        if ($Body) {
            $params.Body        = $Body
            $params.ContentType = "application/json"
        }

        $response = Invoke-WebRequest @params -ErrorAction Stop

        if ($response.StatusCode -ne $ExpectedStatus) {
            Write-Host "  [FAIL] Expected status $ExpectedStatus, got $($response.StatusCode)" -ForegroundColor Red
            $script:testsFailed++
            return
        }

        $json = $response.Content | ConvertFrom-Json

        if ($Validator) {
            $result = & $Validator $json $response
            if (-not $result) {
                Write-Host "  [FAIL] Validation failed" -ForegroundColor Red
                $script:testsFailed++
                return
            }
        }

        Write-Host "  [PASS]" -ForegroundColor Green
        $script:testsPassed++

    } catch {
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
            if ($code -eq $ExpectedStatus) {
                Write-Host "  [PASS] Expected error status $ExpectedStatus" -ForegroundColor Green
                $script:testsPassed++
            } else {
                Write-Host "  [FAIL] Expected $ExpectedStatus, got $code - $($_.Exception.Message)" -ForegroundColor Red
                $script:testsFailed++
            }
        } else {
            Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
            $script:testsFailed++
        }
    }
}

Write-Host "========================================" -ForegroundColor Yellow
Write-Host "Unified Reliability Model Test Suite" -ForegroundColor Yellow
Write-Host "Target: $BaseUrl" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

# Test 1: Health endpoint
Test-Endpoint -Name "Health Check" -Url "$BaseUrl/health" -ExpectedStatus 200

# Test 2: Readiness endpoint
Test-Endpoint -Name "Readiness Check" -Url "$BaseUrl/health/ready" -ExpectedStatus 200 -Validator {
    param($json, $response)
    if (-not $json.status) {
        Write-Host "  Missing 'status' field" -ForegroundColor Red
        return $false
    }
    if ($json.status -ne "ready") {
        Write-Host "  Status: '$($json.status)' (expected 'ready' - may mean MongoDB is down)" -ForegroundColor Yellow
    }
    if (-not $json.checks) {
        Write-Host "  Missing 'checks' field" -ForegroundColor Red
        return $false
    }
    Write-Host "  Status: $($json.status)" -ForegroundColor Gray
    Write-Host "  Checks: $($json.checks | ConvertTo-Json -Compress)" -ForegroundColor Gray
    return $true
}

# Test 3: X-Request-ID header is present and valid UUID format
Test-Endpoint -Name "X-Request-ID Header Present" -Url "$BaseUrl/health" -ExpectedStatus 200 -Validator {
    param($json, $response)
    $id = $response.Headers["X-Request-ID"]
    if (-not $id) {
        Write-Host "  Missing X-Request-ID header" -ForegroundColor Red
        return $false
    }
    if (-not (Test-IsValidUUID $id)) {
        Write-Host "  Invalid UUID format: $id" -ForegroundColor Red
        return $false
    }
    Write-Host "  X-Request-ID: $id" -ForegroundColor Gray
    return $true
}

# Test 4: Client-supplied X-Request-ID is echoed back unchanged
$sentId = "12345678-1234-4abc-8def-123456789012"
Test-Endpoint -Name "Request ID Passthrough" -Url "$BaseUrl/health" -Headers @{ "X-Request-ID" = $sentId } -ExpectedStatus 200 -Validator {
    param($json, $response)
    $got = $response.Headers["X-Request-ID"]
    $want = "12345678-1234-4abc-8def-123456789012"
    if ($got -ne $want) {
        Write-Host "  Sent: $want  Got: $got" -ForegroundColor Red
        return $false
    }
    Write-Host "  Request ID echoed correctly: $got" -ForegroundColor Gray
    return $true
}

# Test 5: Server generates a UUID when none is supplied
Test-Endpoint -Name "Request ID Auto-Generation" -Url "$BaseUrl/health" -ExpectedStatus 200 -Validator {
    param($json, $response)
    $id = $response.Headers["X-Request-ID"]
    if (-not $id) {
        Write-Host "  No X-Request-ID generated" -ForegroundColor Red
        return $false
    }
    if (-not (Test-IsValidUUID $id)) {
        Write-Host "  Generated ID is not a valid UUID: $id" -ForegroundColor Red
        return $false
    }
    Write-Host "  Generated: $id" -ForegroundColor Gray
    return $true
}

# Test 6: CORS exposes X-Request-ID (non-critical, warns only)
Test-Endpoint -Name "CORS Exposes X-Request-ID" -Url "$BaseUrl/health" -Headers @{ "Origin" = "http://localhost:8080" } -ExpectedStatus 200 -Validator {
    param($json, $response)
    $expose = $response.Headers["Access-Control-Expose-Headers"]
    if (-not $expose) {
        Write-Host "  Access-Control-Expose-Headers not present (non-critical)" -ForegroundColor Yellow
        return $true
    }
    if ($expose -notlike "*X-Request-ID*") {
        Write-Host "  X-Request-ID not in exposed headers (non-critical)" -ForegroundColor Yellow
        return $true
    }
    Write-Host "  X-Request-ID correctly exposed via CORS" -ForegroundColor Gray
    return $true
}

# Summary
Write-Host "`n========================================" -ForegroundColor Yellow
Write-Host "Results: $testsPassed passed, $testsFailed failed" -ForegroundColor $(if ($testsFailed -eq 0) { "Green" } else { "Red" })
Write-Host "========================================" -ForegroundColor Yellow

if ($testsFailed -eq 0) {
    Write-Host "[SUCCESS] All tests passed" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[FAILURE] $testsFailed test(s) failed" -ForegroundColor Red
    exit 1
}
