#!/bin/bash
# 100% Systematic Deployment Script

echo "Starting iGSIM AI Platform Deployment"
echo "Project: bamboo-reason-483913-i4"
echo "Target: bamboo-reason-483913-i4.web.app"

# Build Phase
echo "Phase 1: Building Components"
cd frontend && npm run build
cd ../backend && python -m py_compile src/**/*.py

# Test Phase
echo "Phase 2: Systematic Testing"
pytest tests/ --cov=src --cov-report=xml

# Deploy Phase
echo "Phase 3: Firebase Deployment"
firebase deploy --only hosting,firestore,functions --project bamboo-reason-483913-i4

# Verification Phase
echo "Phase 4: Deployment Verification"
curl -s -o /dev/null -w "%{http_code}" https://bamboo-reason-483913-i4.web.app

echo "Deployment Complete: 100% Systematic"
echo "Access Platform: https://bamboo-reason-483913-i4.web.app"
