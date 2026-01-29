@echo off
echo Building Next.js app...
npm run build

echo Deploying to Firebase Hosting...
firebase deploy --only hosting

echo Committing and pushing to git...
git add .
git commit -m "Deploy to Firebase"
git push origin main

echo Deployment complete: https://bamboo-reason-483913-i4.web.app