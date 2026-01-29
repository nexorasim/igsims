#!/usr/bin/env python3
"""
iGSIM AI Platform - Core Infrastructure Validation
Task 4 Checkpoint: Validate all core components
"""

import asyncio
import sys
import os
from typing import Dict, Any

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

def validate_imports() -> Dict[str, bool]:
    """Validate all core imports are working"""
    results = {}
    
    try:
        import firebase_admin
        results['firebase_admin'] = True
    except ImportError:
        results['firebase_admin'] = False
    
    try:
        import fastapi
        results['fastapi'] = True
    except ImportError:
        results['fastapi'] = False
    
    try:
        import pydantic
        results['pydantic'] = True
    except ImportError:
        results['pydantic'] = False
    
    try:
        from models.user import User
        results['user_model'] = True
    except ImportError:
        results['user_model'] = False
    
    try:
        from services.auth_service import AuthService
        results['auth_service'] = True
    except ImportError:
        results['auth_service'] = False
    
    try:
        from mcp_server import MCPServer
        results['mcp_server'] = True
    except ImportError:
        results['mcp_server'] = False
    
    return results

def validate_configuration() -> Dict[str, bool]:
    """Validate configuration files exist"""
    results = {}
    
    config_files = [
        'firebase.json',
        'package.json',
        'requirements.txt',
        '.env.example',
        'src/config/settings.py'
    ]
    
    for config_file in config_files:
        results[config_file] = os.path.exists(config_file)
    
    return results

async def validate_services() -> Dict[str, bool]:
    """Validate core services can be instantiated"""
    results = {}
    
    try:
        from services.ai_agent_service import AIAgentService
        ai_service = AIAgentService()
        results['ai_agent_service'] = True
    except Exception as e:
        print(f"AI Agent Service error: {e}")
        results['ai_agent_service'] = False
    
    try:
        from mcp_server import MCPServer
        mcp_server = MCPServer()
        results['mcp_server_init'] = True
    except Exception as e:
        print(f"MCP Server error: {e}")
        results['mcp_server_init'] = False
    
    return results

def print_results(category: str, results: Dict[str, bool]):
    """Print validation results"""
    print(f"\n{category}:")
    for item, status in results.items():
        status_text = "PASS" if status else "FAIL"
        color = "\033[92m" if status else "\033[91m"  # Green or Red
        reset = "\033[0m"
        print(f"  {color}{status_text}{reset}: {item}")

async def main():
    """Main validation function"""
    print("iGSIM AI Platform - Core Infrastructure Validation")
    print("=" * 50)
    
    # Validate imports
    import_results = validate_imports()
    print_results("Core Imports", import_results)
    
    # Validate configuration
    config_results = validate_configuration()
    print_results("Configuration Files", config_results)
    
    # Validate services
    service_results = await validate_services()
    print_results("Service Initialization", service_results)
    
    # Overall status
    all_results = {**import_results, **config_results, **service_results}
    total_checks = len(all_results)
    passed_checks = sum(1 for result in all_results.values() if result)
    
    print(f"\n{'='*50}")
    print(f"VALIDATION SUMMARY: {passed_checks}/{total_checks} checks passed")
    
    if passed_checks == total_checks:
        print("STATUS: INFRASTRUCTURE VALIDATION COMPLETED")
        print("READY: Proceed to Task 5 - MCP Server Development")
        return 0
    else:
        print("STATUS: INFRASTRUCTURE VALIDATION FAILED")
        print("ACTION: Fix failing components before proceeding")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)