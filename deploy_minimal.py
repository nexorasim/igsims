#!/usr/bin/env python3

import subprocess
import sys

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.stderr}")
        return False

def main():
    print("Building Next.js app...")
    if not run_command("npm run build"):
        sys.exit(1)
    
    print("Deploying to Firebase Hosting...")
    if not run_command("firebase deploy --only hosting"):
        sys.exit(1)
    
    print("Committing and pushing to git...")
    run_command("git add .")
    run_command('git commit -m "Deploy to Firebase"')
    run_command("git push origin main")
    
    print("Deployment complete: https://bamboo-reason-483913-i4.web.app")

if __name__ == "__main__":
    main()