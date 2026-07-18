$baseUrl = "http://localhost:8080"

Write-Host "Testing the local vulnerable web app lab at $baseUrl ..."

Invoke-RestMethod -Method Get -Uri "$baseUrl/health" | Out-Null

Invoke-RestMethod `
  -Method Post `
  -Uri "$baseUrl/lab/sql-injection/login" `
  -ContentType "application/x-www-form-urlencoded" `
  -Body "username=%27%20OR%20%271%27%3D%271%27%20--&password=anything" | Out-Null

Invoke-RestMethod -Method Get -Uri "$baseUrl/lab/xss?q=%3Cmark%3EXSS%20test%3C%2Fmark%3E" | Out-Null

Invoke-RestMethod -Method Get -Uri "$baseUrl/profile/3" | Out-Null

Write-Host "Done. Open the lab:"
Write-Host "$baseUrl"
Write-Host "Scoreboard:"
Write-Host "$baseUrl/scoreboard"
