"""
iGSIM AI Agent Platform - Data Access Layer
Repository pattern implementation for Firestore
"""

from .base_repository import BaseRepository
from .device_repository import DeviceRepository
from .esim_profile_repository import eSIMProfileRepository
from .user_repository import UserRepository
from .ai_context_repository import AIContextRepository
from .mcp_repository import MCPRepository

__all__ = [
    'BaseRepository',
    'DeviceRepository',
    'eSIMProfileRepository', 
    'UserRepository',
    'AIContextRepository',
    'MCPRepository'
]