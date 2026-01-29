"""
AI Agent Service for iGSIM Platform
Handles Gemini AI, xai, and groq integrations
"""

import asyncio
import json
from typing import Dict, Any, Optional, List
from config.settings import AI_CONFIG, PLATFORM_CONFIG
from utils.logger import setup_logger

try:
    import google.generativeai as genai
except ImportError:
    genai = None

try:
    import openai
except ImportError:
    openai = None

try:
    import httpx
except ImportError:
    httpx = None

logger = setup_logger(__name__)

class AIAgentService:
    """Main AI Agent service for iGSIM platform"""
    
    def __init__(self):
        self.platform_name = PLATFORM_CONFIG["name"]
        self.gemini_api_key = AI_CONFIG["gemini_api_key"]
        self.xai_api_key = AI_CONFIG["xai_api_key"]
        self.groq_api_key = AI_CONFIG["groq_api_key"]
        self.model_name = AI_CONFIG["model_name"]
        self.initialized = False
        
        # AI clients
        self.gemini_client = None
        self.xai_client = None
        self.groq_client = None
        
    def initialize(self) -> bool:
        """Initialize AI Agent services"""
        try:
            logger.info(f"Initializing {self.platform_name}")
            
            # Initialize Gemini AI
            self._initialize_gemini()
            
            # Initialize xai
            self._initialize_xai()
            
            # Initialize groq
            self._initialize_groq()
            
            self.initialized = True
            logger.info("AI Agent services initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize AI services: {e}")
            return False
    
    def _initialize_gemini(self):
        """Initialize Google Gemini AI"""
        if not self.gemini_api_key or not genai:
            logger.warning("Gemini API key not configured or google-generativeai not installed")
            return
            
        try:
            genai.configure(api_key=self.gemini_api_key)
            self.gemini_client = genai.GenerativeModel(self.model_name)
            logger.info("Google Gemini AI initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini: {e}")
        
    def _initialize_xai(self):
        """Initialize xai service"""
        if not self.xai_api_key or not openai:
            logger.warning("xai API key not configured or openai not installed")
            return
            
        try:
            self.xai_client = openai.OpenAI(
                api_key=self.xai_api_key,
                base_url="https://api.x.ai/v1"
            )
            logger.info("xai service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize xai: {e}")
        
    def _initialize_groq(self):
        """Initialize groq service"""
        if not self.groq_api_key or not openai:
            logger.warning("groq API key not configured or openai not installed")
            return
            
        try:
            self.groq_client = openai.OpenAI(
                api_key=self.groq_api_key,
                base_url="https://api.groq.com/openai/v1"
            )
            logger.info("groq service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize groq: {e}")
    
    async def process_gemini_request(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Process request using Gemini AI"""
        if not self.gemini_client:
            return {"status": "error", "message": "Gemini client not initialized"}
            
        try:
            response = await asyncio.to_thread(
                self.gemini_client.generate_content, prompt
            )
            return {
                "status": "success",
                "provider": "gemini",
                "response": response.text,
                "model": self.model_name
            }
        except Exception as e:
            logger.error(f"Gemini request failed: {e}")
            return {"status": "error", "message": str(e)}
    
    async def process_xai_request(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Process request using xai"""
        if not self.xai_client:
            return {"status": "error", "message": "xai client not initialized"}
            
        try:
            response = await asyncio.to_thread(
                self.xai_client.chat.completions.create,
                model="grok-beta",
                messages=[{"role": "user", "content": prompt}],
                **kwargs
            )
            return {
                "status": "success",
                "provider": "xai",
                "response": response.choices[0].message.content,
                "model": "grok-beta"
            }
        except Exception as e:
            logger.error(f"xai request failed: {e}")
            return {"status": "error", "message": str(e)}
    
    async def process_groq_request(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Process request using groq"""
        if not self.groq_client:
            return {"status": "error", "message": "groq client not initialized"}
            
        try:
            response = await asyncio.to_thread(
                self.groq_client.chat.completions.create,
                model="llama-3.1-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                **kwargs
            )
            return {
                "status": "success",
                "provider": "groq",
                "response": response.choices[0].message.content,
                "model": "llama-3.1-70b-versatile"
            }
        except Exception as e:
            logger.error(f"groq request failed: {e}")
            return {"status": "error", "message": str(e)}
    
    async def process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process AI agent request with intelligent routing"""
        if not self.initialized:
            raise RuntimeError("AI Agent service not initialized")
            
        prompt = request.get("prompt", "")
        provider = request.get("provider", "auto")
        request_type = request.get("type", "general")
        
        logger.info(f"Processing AI request: {request_type} via {provider}")
        
        # Auto-select provider based on request type
        if provider == "auto":
            if request_type in ["esim", "m2m", "technical"]:
                provider = "gemini"  # Use Gemini for technical tasks
            elif request_type in ["creative", "conversation"]:
                provider = "xai"     # Use xai for creative tasks
            elif request_type in ["analysis", "fast"]:
                provider = "groq"    # Use groq for fast analysis
            else:
                provider = "gemini"  # Default to Gemini
        
        # Route to appropriate AI service
        if provider == "gemini":
            result = await self.process_gemini_request(prompt, **request.get("params", {}))
        elif provider == "xai":
            result = await self.process_xai_request(prompt, **request.get("params", {}))
        elif provider == "groq":
            result = await self.process_groq_request(prompt, **request.get("params", {}))
        else:
            result = {"status": "error", "message": f"Unknown provider: {provider}"}
        
        # Add platform metadata
        result["platform"] = self.platform_name
        result["request_id"] = request.get("id", "unknown")
        
        return result
    
    def get_status(self) -> Dict[str, Any]:
        """Get AI Agent service status"""
        return {
            "platform": self.platform_name,
            "initialized": self.initialized,
            "services": {
                "gemini": {
                    "available": bool(self.gemini_client),
                    "model": self.model_name if self.gemini_client else None
                },
                "xai": {
                    "available": bool(self.xai_client),
                    "model": "grok-beta" if self.xai_client else None
                },
                "groq": {
                    "available": bool(self.groq_client),
                    "model": "llama-3.1-70b-versatile" if self.groq_client else None
                }
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all AI services"""
        health_status = {
            "platform": self.platform_name,
            "overall_status": "healthy",
            "services": {}
        }
        
        # Test each service with a simple prompt
        test_prompt = "Hello, this is a health check."
        
        for provider in ["gemini", "xai", "groq"]:
            try:
                result = await self.process_request({
                    "prompt": test_prompt,
                    "provider": provider,
                    "type": "health_check"
                })
                health_status["services"][provider] = {
                    "status": result.get("status", "unknown"),
                    "available": result.get("status") == "success"
                }
            except Exception as e:
                health_status["services"][provider] = {
                    "status": "error",
                    "available": False,
                    "error": str(e)
                }
        
        # Determine overall status
        available_services = sum(1 for service in health_status["services"].values() if service["available"])
        if available_services == 0:
            health_status["overall_status"] = "unhealthy"
        elif available_services < 3:
            health_status["overall_status"] = "degraded"
        
        return health_status