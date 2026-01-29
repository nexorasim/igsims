"""
Device data model for iGSIM AI Agent Platform
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum
import json

class DeviceStatus(Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    PROVISIONING = "provisioning"
    ERROR = "error"
    MAINTENANCE = "maintenance"

@dataclass
class Device:
    """Device model for eSIM and M2M device management"""
    
    device_id: str
    device_type: str
    status: DeviceStatus
    esim_profile: Optional['eSIMProfile'] = None
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Initialize timestamps if not provided"""
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = datetime.utcnow()
    
    def is_active(self) -> bool:
        """Check if device is active"""
        return self.status == DeviceStatus.ACTIVE
    
    def is_online(self) -> bool:
        """Check if device is online based on last_seen"""
        if not self.last_seen:
            return False
        # Consider device online if seen within last 5 minutes
        return (datetime.utcnow() - self.last_seen).total_seconds() < 300
    
    def update_status(self, new_status: DeviceStatus) -> None:
        """Update device status with timestamp"""
        self.status = new_status
        self.updated_at = datetime.utcnow()
    
    def update_last_seen(self) -> None:
        """Update last seen timestamp"""
        self.last_seen = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert device to dictionary for Firestore storage"""
        return {
            'device_id': self.device_id,
            'device_type': self.device_type,
            'status': self.status.value,
            'esim_profile': self.esim_profile.to_dict() if self.esim_profile else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Device':
        """Create device from dictionary"""
        from .esim_profile import eSIMProfile
        
        device = cls(
            device_id=data['device_id'],
            device_type=data['device_type'],
            status=DeviceStatus(data['status']),
            metadata=data.get('metadata', {}),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            updated_at=datetime.fromisoformat(data['updated_at']) if data.get('updated_at') else None
        )
        
        if data.get('last_seen'):
            device.last_seen = datetime.fromisoformat(data['last_seen'])
        
        if data.get('esim_profile'):
            device.esim_profile = eSIMProfile.from_dict(data['esim_profile'])
        
        return device
    
    def validate(self) -> bool:
        """Validate device data"""
        if not self.device_id or not isinstance(self.device_id, str):
            return False
        if not self.device_type or not isinstance(self.device_type, str):
            return False
        if not isinstance(self.status, DeviceStatus):
            return False
        return True