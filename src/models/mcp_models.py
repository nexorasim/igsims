"""
MCP (Model Context Protocol) data models for iGSIM AI Agent Platform
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

@dataclass
class MCPRequest:
    """MCP request model for AI service communication"""
    
    request_id: str
    service_name: str
    method: str
    parameters: Dict[str, Any]
    context: Optional['AIContext'] = None
    timestamp: Optional[datetime] = None
    user_id: Optional[str] = None
    priority: int = 0  # 0 = normal, 1 = high, 2 = urgent
    timeout: Optional[int] = None  # timeout in seconds
    
    def __post_init__(self):
        """Initialize request ID and timestamp if not provided"""
        if not self.request_id:
            self.request_id = str(uuid.uuid4())
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
    
    def is_expired(self, current_time: Optional[datetime] = None) -> bool:
        """Check if request has expired based on timeout"""
        if not self.timeout or not self.timestamp:
            return False
        
        if current_time is None:
            current_time = datetime.utcnow()
        
        elapsed = (current_time - self.timestamp).total_seconds()
        return elapsed > self.timeout
    
    def get_age_seconds(self) -> float:
        """Get age of request in seconds"""
        if not self.timestamp:
            return 0.0
        return (datetime.utcnow() - self.timestamp).total_seconds()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert request to dictionary for transmission"""
        return {
            'request_id': self.request_id,
            'service_name': self.service_name,
            'method': self.method,
            'parameters': self.parameters,
            'context': self.context.to_dict() if self.context else None,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'user_id': self.user_id,
            'priority': self.priority,
            'timeout': self.timeout
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPRequest':
        """Create request from dictionary"""
        from .ai_context import AIContext
        
        request = cls(
            request_id=data['request_id'],
            service_name=data['service_name'],
            method=data['method'],
            parameters=data['parameters'],
            user_id=data.get('user_id'),
            priority=data.get('priority', 0),
            timeout=data.get('timeout'),
            timestamp=datetime.fromisoformat(data['timestamp']) if data.get('timestamp') else None
        )
        
        if data.get('context'):
            request.context = AIContext.from_dict(data['context'])
        
        return request
    
    @classmethod
    def create_ai_request(cls, service_name: str, method: str, parameters: Dict[str, Any],
                         user_id: Optional[str] = None, context: Optional['AIContext'] = None,
                         priority: int = 0, timeout: Optional[int] = 30) -> 'MCPRequest':
        """Create an AI service request"""
        return cls(
            request_id=str(uuid.uuid4()),
            service_name=service_name,
            method=method,
            parameters=parameters,
            context=context,
            user_id=user_id,
            priority=priority,
            timeout=timeout
        )
    
    def validate(self) -> bool:
        """Validate MCP request data"""
        if not self.request_id or not isinstance(self.request_id, str):
            return False
        if not self.service_name or not isinstance(self.service_name, str):
            return False
        if not self.method or not isinstance(self.method, str):
            return False
        if not isinstance(self.parameters, dict):
            return False
        return True

@dataclass
class MCPResponse:
    """MCP response model for AI service communication"""
    
    request_id: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: Optional[datetime] = None
    processing_time: Optional[float] = None  # processing time in seconds
    service_name: Optional[str] = None
    tokens_used: Optional[int] = None
    cost: Optional[float] = None  # cost in USD
    
    def __post_init__(self):
        """Initialize timestamp if not provided"""
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
    
    def is_success(self) -> bool:
        """Check if response indicates success"""
        return self.success and self.error is None
    
    def is_error(self) -> bool:
        """Check if response indicates error"""
        return not self.success or self.error is not None
    
    def get_error_message(self) -> str:
        """Get error message or default"""
        return self.error or "Unknown error occurred"
    
    def get_data_value(self, key: str, default: Any = None) -> Any:
        """Get value from response data"""
        if not self.data:
            return default
        return self.data.get(key, default)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary for transmission"""
        return {
            'request_id': self.request_id,
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'processing_time': self.processing_time,
            'service_name': self.service_name,
            'tokens_used': self.tokens_used,
            'cost': self.cost
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPResponse':
        """Create response from dictionary"""
        return cls(
            request_id=data['request_id'],
            success=data['success'],
            data=data.get('data'),
            error=data.get('error'),
            processing_time=data.get('processing_time'),
            service_name=data.get('service_name'),
            tokens_used=data.get('tokens_used'),
            cost=data.get('cost'),
            timestamp=datetime.fromisoformat(data['timestamp']) if data.get('timestamp') else None
        )
    
    @classmethod
    def create_success(cls, request_id: str, data: Dict[str, Any], 
                      service_name: Optional[str] = None,
                      processing_time: Optional[float] = None,
                      tokens_used: Optional[int] = None) -> 'MCPResponse':
        """Create a success response"""
        return cls(
            request_id=request_id,
            success=True,
            data=data,
            service_name=service_name,
            processing_time=processing_time,
            tokens_used=tokens_used
        )
    
    @classmethod
    def create_error(cls, request_id: str, error_message: str,
                    service_name: Optional[str] = None) -> 'MCPResponse':
        """Create an error response"""
        return cls(
            request_id=request_id,
            success=False,
            error=error_message,
            service_name=service_name
        )
    
    def validate(self) -> bool:
        """Validate MCP response data"""
        if not self.request_id or not isinstance(self.request_id, str):
            return False
        if not isinstance(self.success, bool):
            return False
        if self.success and self.data is None:
            return False  # Success responses should have data
        if not self.success and not self.error:
            return False  # Error responses should have error message
        return True

@dataclass
class MCPTool:
    """MCP tool definition"""
    
    name: str
    description: str
    parameters: Dict[str, Any]
    version: str = "1.0.0"
    category: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert tool to dictionary"""
        return {
            'name': self.name,
            'description': self.description,
            'parameters': self.parameters,
            'version': self.version,
            'category': self.category
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPTool':
        """Create tool from dictionary"""
        return cls(
            name=data['name'],
            description=data['description'],
            parameters=data['parameters'],
            version=data.get('version', '1.0.0'),
            category=data.get('category')
        )

@dataclass
class MCPResource:
    """MCP resource definition"""
    
    name: str
    uri: str
    description: str
    mime_type: Optional[str] = None
    size: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert resource to dictionary"""
        return {
            'name': self.name,
            'uri': self.uri,
            'description': self.description,
            'mime_type': self.mime_type,
            'size': self.size
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPResource':
        """Create resource from dictionary"""
        return cls(
            name=data['name'],
            uri=data['uri'],
            description=data['description'],
            mime_type=data.get('mime_type'),
            size=data.get('size')
        )

@dataclass
class MCPServer:
    """MCP server definition"""
    
    name: str
    description: str
    version: str
    capabilities: Dict[str, Any]
    tools: list[MCPTool] = field(default_factory=list)
    resources: list[MCPResource] = field(default_factory=list)
    id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert server to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'capabilities': self.capabilities,
            'tools': [tool.to_dict() for tool in self.tools],
            'resources': [resource.to_dict() for resource in self.resources]
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPServer':
        """Create server from dictionary"""
        return cls(
            id=data.get('id'),
            name=data['name'],
            description=data['description'],
            version=data['version'],
            capabilities=data['capabilities'],
            tools=[MCPTool.from_dict(tool) for tool in data.get('tools', [])],
            resources=[MCPResource.from_dict(resource) for resource in data.get('resources', [])]
        )