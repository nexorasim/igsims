#!/usr/bin/env python3
"""
iGSIM AI Agent Platform - Main Entry Point
iGSIM AI Agent powered by eSIM Myanmar

Supports both GUI and web server modes
"""

import sys
import os
import argparse
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent))

from config.settings import PLATFORM_CONFIG
from services.ai_agent_service import AIAgentService
from services.esim_service import eSIMService
from utils.logger import setup_logger

logger = setup_logger(__name__)

def run_gui_mode():
    """Run the PyQt/PySide GUI application"""
    try:
        from gui.main_window import main as gui_main
        logger.info("Starting GUI mode...")
        gui_main()
    except ImportError as e:
        logger.error(f"GUI dependencies not available: {e}")
        logger.info("Please install PyQt6 or PySide6: pip install PyQt6")
        sys.exit(1)

def run_web_mode(host="127.0.0.1", port=8000):
    """Run the FastAPI web server"""
    try:
        import uvicorn
        from api.main import app
        
        logger.info(f"Starting web server on {host}:{port}")
        uvicorn.run(app, host=host, port=port, log_level="info")
        
    except ImportError as e:
        logger.error(f"Web server dependencies not available: {e}")
        logger.info("Please install FastAPI and uvicorn: pip install fastapi uvicorn")
        sys.exit(1)

def run_console_mode():
    """Run in console mode for testing services"""
    logger.info("Starting console mode...")
    
    # Initialize services
    ai_service = AIAgentService()
    esim_service = eSIMService()
    
    logger.info("Initializing AI Agent Service...")
    ai_success = ai_service.initialize()
    
    logger.info("Initializing eSIM Service...")
    esim_success = esim_service.initialize()
    
    if ai_success and esim_success:
        logger.info("All services initialized successfully!")
        
        # Display service status
        ai_status = ai_service.get_status()
        logger.info(f"AI Service Status: {ai_status}")
        
        # Test eSIM provisioning
        logger.info("Testing eSIM provisioning...")
        test_result = esim_service.provision_esim("test_device_001", {
            "operator": "eSIM Myanmar",
            "country": "MM",
            "data_plan": "5GB"
        })
        logger.info(f"Test provisioning result: {test_result}")
        
        # Keep running
        logger.info("Services running. Press Ctrl+C to exit.")
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            
    else:
        logger.error("Service initialization failed")
        sys.exit(1)

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description=PLATFORM_CONFIG["description"],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} --gui                    # Launch GUI application
  {sys.argv[0]} --web                    # Launch web server
  {sys.argv[0]} --web --host 0.0.0.0     # Launch web server on all interfaces
  {sys.argv[0]} --console                # Run in console mode
  {sys.argv[0]}                          # Default: GUI mode
        """
    )
    
    parser.add_argument(
        "--gui", 
        action="store_true", 
        help="Launch GUI application (default)"
    )
    
    parser.add_argument(
        "--web", 
        action="store_true", 
        help="Launch web server"
    )
    
    parser.add_argument(
        "--console", 
        action="store_true", 
        help="Run in console mode"
    )
    
    parser.add_argument(
        "--host", 
        default="127.0.0.1", 
        help="Web server host (default: 127.0.0.1)"
    )
    
    parser.add_argument(
        "--port", 
        type=int, 
        default=8000, 
        help="Web server port (default: 8000)"
    )
    
    parser.add_argument(
        "--version", 
        action="version", 
        version=f"{PLATFORM_CONFIG['name']} v{PLATFORM_CONFIG['version']}"
    )
    
    args = parser.parse_args()
    
    # Display platform info
    logger.info(f"Starting {PLATFORM_CONFIG['name']}")
    logger.info(f"Version: {PLATFORM_CONFIG['version']}")
    logger.info(f"Description: {PLATFORM_CONFIG['description']}")
    
    try:
        # Determine mode
        if args.web:
            run_web_mode(args.host, args.port)
        elif args.console:
            run_console_mode()
        else:
            # Default to GUI mode
            run_gui_mode()
            
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()