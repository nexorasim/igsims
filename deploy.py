#!/usr/bin/env python3
"""
iGSIM AI Agent Platform - Automated Deployment Script
Handles both frontend and backend deployment to Firebase
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path

def run_command(command, cwd=None, check=True):
    """Run shell command with error handling"""
    print(f"Running: {command}")
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            cwd=cwd, 
            check=check,
            capture_output=True,
            text=True
        )
        if result.stdout:
            print(result.stdout)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        if check:
            sys.exit(1)
        return e

def check_prerequisites():
    """Check if required tools are installed"""
    print("Checking prerequisites...")
    
    # Check Node.js and npm
    try:
        subprocess.run(["node", "--version"], check=True, capture_output=True)
        subprocess.run(["npm", "--version"], check=True, capture_output=True)
        print("✓ Node.js and npm are installed")
    except subprocess.CalledProcessError:
        print("✗ Node.js and npm are required")
        return False
    
    # Check Firebase CLI
    try:
        subprocess.run(["firebase", "--version"], check=True, capture_output=True)
        print("✓ Firebase CLI is installed")
    except subprocess.CalledProcessError:
        print("✗ Firebase CLI is required")
        print("Install with: npm install -g firebase-tools")
        return False
    
    # Check Python
    try:
        subprocess.run([sys.executable, "--version"], check=True, capture_output=True)
        print("✓ Python is installed")
    except subprocess.CalledProcessError:
        print("✗ Python is required")
        return False
    
    return True

def install_dependencies():
    """Install project dependencies"""
    print("\nInstalling dependencies...")
    
    # Install Node.js dependencies
    print("Installing Node.js dependencies...")
    run_command("npm install")
    
    # Install Python dependencies
    print("Installing Python dependencies...")
    run_command("pip install -r requirements.txt")
    
    print("✓ Dependencies installed successfully")

def build_frontend():
    """Build the Next.js frontend"""
    print("\nBuilding frontend...")
    
    # Build Next.js application
    run_command("npm run build")
    
    print("✓ Frontend built successfully")

def deploy_to_firebase(hosting_only=False):
    """Deploy to Firebase"""
    print(f"\nDeploying to Firebase...")
    
    if hosting_only:
        run_command("firebase deploy --only hosting")
    else:
        run_command("firebase deploy")
    
    print("✓ Deployed to Firebase successfully")

def setup_environment():
    """Setup environment variables and configuration"""
    print("\nSetting up environment...")
    
    # Check if .env file exists
    env_file = Path(".env")
    if not env_file.exists():
        print("Creating .env template...")
        env_template = """# iGSIM AI Agent Platform Environment Variables
# Copy this file to .env and fill in your API keys

# AI Service API Keys
GEMINI_API_KEY=your_gemini_api_key_here
XAI_API_KEY=your_xai_api_key_here
GROQ_API_KEY=your_groq_api_key_here

# Firebase Configuration
FIREBASE_PROJECT_ID=bamboo-reason-483913-i4

# Development Settings
DEBUG=true
LOG_LEVEL=INFO
"""
        env_file.write_text(env_template)
        print("✓ .env template created")
        print("Please edit .env file with your API keys")
    else:
        print("✓ .env file already exists")

def main():
    """Main deployment function"""
    parser = argparse.ArgumentParser(description="Deploy iGSIM AI Agent Platform")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency installation")
    parser.add_argument("--hosting-only", action="store_true", help="Deploy hosting only")
    parser.add_argument("--setup-only", action="store_true", help="Setup environment only")
    parser.add_argument("--build-only", action="store_true", help="Build only, don't deploy")
    
    args = parser.parse_args()
    
    print("🚀 iGSIM AI Agent Platform Deployment")
    print("=====================================")
    
    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    # Setup environment
    setup_environment()
    
    if args.setup_only:
        print("\n✅ Environment setup completed")
        return
    
    # Install dependencies
    if not args.skip_deps:
        install_dependencies()
    
    # Build frontend
    build_frontend()
    
    if args.build_only:
        print("\n✅ Build completed")
        return
    
    # Deploy to Firebase
    deploy_to_firebase(args.hosting_only)
    
    print("\n🎉 Deployment completed successfully!")
    print(f"🌐 Your app is live at: https://bamboo-reason-483913-i4.web.app")
    print(f"📊 Firebase Console: https://console.firebase.google.com/project/bamboo-reason-483913-i4")

if __name__ == "__main__":
    main()