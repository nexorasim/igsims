import asyncio
import json
import logging
import os
from typing import Dict, Any, Optional, List
from datetime import datetime
import aiohttp
from dataclasses import dataclass

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.mcp_models import MCPRequest, MCPResponse
from repositories import MCPRepository
from encryption import SecureStorage

logger = logging.getLogger(__name__)

@dataclass
class AIService:
    name: str
    endpoint: str
    api_key: str
    model: str
    max_tokens: int = 4000

class MCPServer:
    def __init__(self):
        self.storage = SecureStorage()
        self.repository = MCPRepository()
        self.services = self._initialize_services()
        self.context_cache = {}
    
    def _initialize_services(self) -> Dict[str, AIService]:
        return {
            'gemini': AIService(
                name='gemini',
                endpoint='https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent',
                api_key=os.getenv('GEMINI_API_KEY', ''),
                model='gemini-pro'
            ),
            'xai': AIService(
                name='xai',
                endpoint='https://api.x.ai/v1/chat/completions',
                api_key=os.getenv('XAI_API_KEY', ''),
                model='grok-beta'
            ),
            'groq': AIService(
                name='groq',
                endpoint='https://api.groq.com/openai/v1/chat/completions',
                api_key=os.getenv('GROQ_API_KEY', ''),
                model='mixtral-8x7b-32768'
            )
        }
    
    async def process_request(self, request: MCPRequest) -> MCPResponse:
        try:
            await self.repository.create_request(request)
            
            service = self._select_service(request.message)
            response_content = await self._call_ai_service(service, request.message, request.context)
            
            response = MCPResponse(
                request_id=request.request_id,
                service_used=service.name,
                response=response_content,
                timestamp=datetime.utcnow(),
                context_id=request.context_id
            )
            
            await self.repository.create_response(response)
            return response
            
        except Exception as e:
            logger.error(f"Error processing MCP request: {e}")
            return MCPResponse(
                request_id=request.request_id,
                service_used='error',
                response=f"Error: {str(e)}",
                timestamp=datetime.utcnow(),
                context_id=request.context_id
            )
    
    def _select_service(self, message: str) -> AIService:
        message_lower = message.lower()
        
        if any(word in message_lower for word in ['code', 'technical', 'programming', 'debug']):
            return self.services['gemini']
        elif any(word in message_lower for word in ['creative', 'story', 'chat', 'conversation']):
            return self.services['xai']
        elif any(word in message_lower for word in ['fast', 'quick', 'analyze', 'process']):
            return self.services['groq']
        else:
            return self.services['gemini']
    
    async def _call_ai_service(self, service: AIService, message: str, context: Optional[str] = None) -> str:
        try:
            if service.name == 'gemini':
                return await self._call_gemini(service, message, context)
            elif service.name == 'xai':
                return await self._call_xai(service, message, context)
            elif service.name == 'groq':
                return await self._call_groq(service, message, context)
            else:
                raise ValueError(f"Unknown service: {service.name}")
        except Exception as e:
            logger.error(f"Error calling {service.name}: {e}")
            return await self._fallback_service(message, context, service.name)
    
    async def _call_gemini(self, service: AIService, message: str, context: Optional[str] = None) -> str:
        headers = {'Content-Type': 'application/json'}
        
        prompt = f"{context}\n\n{message}" if context else message
        
        payload = {
            'contents': [{
                'parts': [{'text': prompt}]
            }]
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{service.endpoint}?key={service.api_key}",
                headers=headers,
                json=payload
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data['candidates'][0]['content']['parts'][0]['text']
                else:
                    raise Exception(f"Gemini API error: {response.status}")
    
    async def _call_xai(self, service: AIService, message: str, context: Optional[str] = None) -> str:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {service.api_key}'
        }
        
        messages = []
        if context:
            messages.append({'role': 'system', 'content': context})
        messages.append({'role': 'user', 'content': message})
        
        payload = {
            'model': service.model,
            'messages': messages,
            'max_tokens': service.max_tokens
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(service.endpoint, headers=headers, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return data['choices'][0]['message']['content']
                else:
                    raise Exception(f"xAI API error: {response.status}")
    
    async def _call_groq(self, service: AIService, message: str, context: Optional[str] = None) -> str:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {service.api_key}'
        }
        
        messages = []
        if context:
            messages.append({'role': 'system', 'content': context})
        messages.append({'role': 'user', 'content': message})
        
        payload = {
            'model': service.model,
            'messages': messages,
            'max_tokens': service.max_tokens
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(service.endpoint, headers=headers, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return data['choices'][0]['message']['content']
                else:
                    raise Exception(f"Groq API error: {response.status}")
    
    async def _fallback_service(self, message: str, context: Optional[str], failed_service: str) -> str:
        available_services = [s for name, s in self.services.items() if name != failed_service and s.api_key]
        
        if not available_services:
            return "Error: No available AI services"
        
        try:
            fallback_service = available_services[0]
            return await self._call_ai_service(fallback_service, message, context)
        except Exception as e:
            logger.error(f"Fallback service also failed: {e}")
            return f"Error: All AI services unavailable - {str(e)}"
    
    async def health_check(self) -> Dict[str, bool]:
        health_status = {}
        
        for name, service in self.services.items():
            if not service.api_key:
                health_status[name] = False
                continue
            
            try:
                test_response = await self._call_ai_service(service, "Hello", None)
                health_status[name] = bool(test_response and len(test_response) > 0)
            except:
                health_status[name] = False
        
        return health_status