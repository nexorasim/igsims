#!/usr/bin/env python3
"""
iGSIM AI Agent Platform Setup Script
Automated setup for development environment
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def run_command(command, check=True):
    """Run shell command with error handling"""
    print(f"Running: {command}")
    try:
        result = subprocess.run(command, shell=True, check=check, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        return False

def check_python():
    """Check Python installation"""
    print("Checking Python installation...")
    
    python_executables = ['python', 'python3', 'py']
    
    for exe in python_executables:
        try:
            result = subprocess.run([exe, '--version'], capture_output=True, text=True, check=True)
            print(f"✓ Found Python: {result.stdout.strip()}")
            return exe
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    
    print("✗ Python not found. Please install Python 3.11 or higher.")
    return None

def check_node():
    """Check Node.js installation"""
    print("Checking Node.js installation...")
    
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True, check=True)
        print(f"✓ Found Node.js: {result.stdout.strip()}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("✗ Node.js not found. Please install Node.js 18 or higher.")
        return False

def setup_environment():
    """Setup environment file"""
    print("Setting up environment...")
    
    env_file = Path('.env')
    env_example = Path('.env.example')
    
    if not env_file.exists() and env_example.exists():
        print("Creating .env file from template...")
        env_file.write_text(env_example.read_text())
        print("✓ .env file created. Please edit it with your API keys.")
    elif env_file.exists():
        print("✓ .env file already exists.")
    else:
        print("⚠ No .env.example template found.")

def install_python_deps(python_exe):
    """Install Python dependencies"""
    print("Installing Python dependencies...")
    
    # Check if requirements.txt exists
    if not Path('requirements.txt').exists():
        print("⚠ requirements.txt not found. Skipping Python dependencies.")
        return True
    
    # Try to install with pip
    commands = [
        f"{python_exe} -m pip install --upgrade pip",
        f"{python_exe} -m pip install -r requirements.txt"
    ]
    
    for cmd in commands:
        if not run_command(cmd, check=False):
            print(f"⚠ Failed to run: {cmd}")
            return False
    
    print("✓ Python dependencies installed.")
    return True

def install_node_deps():
    """Install Node.js dependencies"""
    print("Installing Node.js dependencies...")
    
    if not Path('package.json').exists():
        print("⚠ package.json not found. Skipping Node.js dependencies.")
        return True
    
    # Try npm install with fallback options
    commands = [
        "npm install",
        "npm install --legacy-peer-deps",
        "npm install --force"
    ]
    
    for cmd in commands:
        if run_command(cmd, check=False):
            print("✓ Node.js dependencies installed.")
            return True
        print(f"⚠ Failed: {cmd}, trying next option...")
    
    print("✗ Failed to install Node.js dependencies.")
    return False

def main():
    """Main setup function"""
    print("🚀 iGSIM AI Agent Platform Setup")
    print("=================================")
    
    # Check system requirements
    python_exe = check_python()
    node_available = check_node()
    
    if not python_exe:
        print("\n❌ Setup failed: Python not available")
        sys.exit(1)
    
    if not node_available:
        print("\n❌ Setup failed: Node.js not available")
        sys.exit(1)
    
    # Setup environment
    setup_environment()
    
    # Install dependencies
    python_success = install_python_deps(python_exe)
    node_success = install_node_deps()
    
    # Summary
    print("\n📋 Setup Summary")
    print("================")
    print(f"Python: {'✓' if python_exe else '✗'}")
    print(f"Node.js: {'✓' if node_available else '✗'}")
    print(f"Python deps: {'✓' if python_success else '✗'}")
    print(f"Node.js deps: {'✓' if node_success else '✗'}")
    
    if python_success and node_success:
        print("\n🎉 Setup completed successfully!")
        print("\nNext steps:")
        print("1. Edit .env file with your API keys")
        print("2. Run 'npm run dev' for web development")
        print(f"3. Run '{python_exe} src/main.py --gui' for desktop app")
        print("4. Run 'npm run deploy' to deploy to Firebase")
    else:
        print("\n⚠ Setup completed with warnings. Check the errors above.")

if __name__ == "__main__":
    main()