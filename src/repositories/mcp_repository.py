"""
MCP Repository - Model Context Protocol data access layer
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List, Optional, Any
from datetime import datetime
from repositories.base_repository import BaseRepository
from models.mcp_models import MCPServer, MCPTool, MCPResource


class MCPRepository(BaseRepository):
    """Repository for MCP (Model Context Protocol) data operations"""
    
    def __init__(self):
        from models.mcp_models import MCPServer
        super().__init__("mcp_data", MCPServer)
    
    def _to_dict(self, obj: Any) -> Dict[str, Any]:
        """Convert object to dictionary for Firestore storage"""
        if hasattr(obj, 'dict'):
            return obj.dict()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return {"data": str(obj)}
    
    def _from_dict(self, data: Dict[str, Any]) -> Any:
        """Convert dictionary from Firestore to object"""
        # For MCP models, we'll create a simple object from the data
        from models.mcp_models import MCPServer
        if 'name' in data and 'version' in data:
            return MCPServer(**data)
        else:
            return data
    
    def _get_id(self, obj: Any) -> str:
        """Get ID from object"""
        if hasattr(obj, 'id'):
            return obj.id
        elif hasattr(obj, 'request_id'):
            return obj.request_id
        else:
            return str(id(obj))
    
    async def save_server(self, server: MCPServer) -> str:
        """Save MCP server configuration"""
        server_data = {
            "name": server.name,
            "description": server.description,
            "version": server.version,
            "capabilities": server.capabilities,
            "tools": [tool.dict() for tool in server.tools],
            "resources": [resource.dict() for resource in server.resources],
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        doc_ref = self.db.collection(self.collection_name).document()
        await doc_ref.set(server_data)
        return doc_ref.id
    
    async def get_server(self, server_id: str) -> Optional[MCPServer]:
        """Get MCP server by ID"""
        doc = await self.db.collection(self.collection_name).document(server_id).get()
        if not doc.exists:
            return None
        
        data = doc.to_dict()
        return MCPServer(
            id=doc.id,
            name=data["name"],
            description=data["description"],
            version=data["version"],
            capabilities=data["capabilities"],
            tools=[MCPTool(**tool) for tool in data.get("tools", [])],
            resources=[MCPResource(**resource) for resource in data.get("resources", [])]
        )
    
    async def list_servers(self) -> List[MCPServer]:
        """List all MCP servers"""
        docs = await self.db.collection(self.collection_name).get()
        servers = []
        
        for doc in docs:
            data = doc.to_dict()
            server = MCPServer(
                id=doc.id,
                name=data["name"],
                description=data["description"],
                version=data["version"],
                capabilities=data["capabilities"],
                tools=[MCPTool(**tool) for tool in data.get("tools", [])],
                resources=[MCPResource(**resource) for resource in data.get("resources", [])]
            )
            servers.append(server)
        
        return servers
    
    async def update_server(self, server_id: str, updates: Dict[str, Any]) -> bool:
        """Update MCP server configuration"""
        updates["updated_at"] = datetime.utcnow()
        
        doc_ref = self.db.collection(self.collection_name).document(server_id)
        await doc_ref.update(updates)
        return True
    
    async def delete_server(self, server_id: str) -> bool:
        """Delete MCP server"""
        await self.db.collection(self.collection_name).document(server_id).delete()
        return True
    
    async def save_tool_usage(self, server_id: str, tool_name: str, usage_data: Dict[str, Any]) -> str:
        """Save tool usage statistics"""
        usage_doc = {
            "server_id": server_id,
            "tool_name": tool_name,
            "usage_data": usage_data,
            "timestamp": datetime.utcnow()
        }
        
        doc_ref = self.db.collection(f"{self.collection_name}_usage").document()
        await doc_ref.set(usage_doc)
        return doc_ref.id
    
    async def get_tool_usage_stats(self, server_id: str, tool_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get tool usage statistics"""
        query = self.db.collection(f"{self.collection_name}_usage").where("server_id", "==", server_id)
        
        if tool_name:
            query = query.where("tool_name", "==", tool_name)
        
        docs = await query.get()
        return [doc.to_dict() for doc in docs]