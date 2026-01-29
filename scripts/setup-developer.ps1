# iGSIM AI Platform - Developer Setup Script
# Simplified version for team onboarding

Write-Host "iGSIM AI Platform - Developer Setup" -ForegroundColor Green
Write-Host "Setting up development environment..." -ForegroundColor Yellow

# Check required tools
$requiredTools = @("git", "node", "python", "firebase")
foreach ($tool in $requiredTools) {
    try {
        Get-Command $tool -ErrorAction Stop | Out-Null
        Write-Host "  VERIFIED: $tool is installed" -ForegroundColor Green
    } catch {
        Write-Host "  MISSING: $tool is NOT installed" -ForegroundColor Red
        Write-Host "    Please install $tool before continuing" -ForegroundColor Yellow
        exit 1
    }
}

# Verify Firebase project binding
Write-Host "Verifying Firebase project binding..." -ForegroundColor Yellow
$firebaseProject = firebase projects:list | Select-String "bamboo-reason-483913-i4"
if ($firebaseProject) {
    Write-Host "  VERIFIED: Firebase project configured" -ForegroundColor Green
} else {
    Write-Host "  ACTION REQUIRED: Run 'firebase use bamboo-reason-483913-i4'" -ForegroundColor Yellow
}

# Install Python dependencies
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
python -m pip install -r requirements.txt --quiet

# Install Node.js dependencies
Write-Host "Installing Node.js dependencies..." -ForegroundColor Yellow
npm install --silent

Write-Host "Developer setup completed successfully!" -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Copy .env.example to .env and add your API keys" -ForegroundColor White
Write-Host "  2. Run 'python src/main.py --web' to start API server" -ForegroundColor White
Write-Host "  3. Run 'npm run dev' to start frontend development" -ForegroundColor White