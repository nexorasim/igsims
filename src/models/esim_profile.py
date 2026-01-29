"""
eSIM Profile data model for iGSIM AI Agent Platform
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime
import uuid

@dataclass
class eSIMProfile:
    """eSIM Profile model for device provisioning"""
    
    profile_id: str
    iccid: str
    operator: str
    plan_type: str
    activation_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    data_usage: Dict[str, int] = field(default_factory=dict)
    activation_code: Optional[str] = None
    qr_code: Optional[str] = None
    msisdn: Optional[str] = None
    status: str = "provisioned"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Initialize timestamps and codes if not provided"""
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = datetime.utcnow()
        
        # Generate activation code if not provided
        if not self.activation_code:
            self.activation_code = f"LPA:1$activation.esim.myanmar${self.profile_id}"
        
        # Generate QR code data if not provided
        if not self.qr_code:
            self.qr_code = self.activation_code
    
    def is_expired(self) -> bool:
        """Check if eSIM profile is expired"""
        if not self.expiry_date:
            return False
        return self.expiry_date < datetime.utcnow()
    
    def is_active(self) -> bool:
        """Check if eSIM profile is active"""
        return (self.status == "active" and 
                self.activation_date is not None and 
                not self.is_expired())
    
    def activate(self) -> None:
        """Activate the eSIM profile"""
        self.status = "active"
        self.activation_date = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def deactivate(self) -> None:
        """Deactivate the eSIM profile"""
        self.status = "inactive"
        self.updated_at = datetime.utcnow()
    
    def update_data_usage(self, usage_mb: int) -> None:
        """Update data usage statistics"""
        current_month = datetime.utcnow().strftime("%Y-%m")
        if current_month not in self.data_usage:
            self.data_usage[current_month] = 0
        self.data_usage[current_month] += usage_mb
        self.updated_at = datetime.utcnow()
    
    def get_total_usage(self) -> int:
        """Get total data usage across all months"""
        return sum(self.data_usage.values())
    
    def get_current_month_usage(self) -> int:
        """Get current month data usage"""
        current_month = datetime.utcnow().strftime("%Y-%m")
        return self.data_usage.get(current_month, 0)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert eSIM profile to dictionary for Firestore storage"""
        return {
            'profile_id': self.profile_id,
            'iccid': self.iccid,
            'operator': self.operator,
            'plan_type': self.plan_type,
            'activation_date': self.activation_date.isoformat() if self.activation_date else None,
            'expiry_date': self.expiry_date.isoformat() if self.expiry_date else None,
            'data_usage': self.data_usage,
            'activation_code': self.activation_code,
            'qr_code': self.qr_code,
            'msisdn': self.msisdn,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'eSIMProfile':
        """Create eSIM profile from dictionary"""
        profile = cls(
            profile_id=data['profile_id'],
            iccid=data['iccid'],
            operator=data['operator'],
            plan_type=data['plan_type'],
            data_usage=data.get('data_usage', {}),
            activation_code=data.get('activation_code'),
            qr_code=data.get('qr_code'),
            msisdn=data.get('msisdn'),
            status=data.get('status', 'provisioned'),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else None,
            updated_at=datetime.fromisoformat(data['updated_at']) if data.get('updated_at') else None
        )
        
        if data.get('activation_date'):
            profile.activation_date = datetime.fromisoformat(data['activation_date'])
        
        if data.get('expiry_date'):
            profile.expiry_date = datetime.fromisoformat(data['expiry_date'])
        
        return profile
    
    @classmethod
    def create_new(cls, device_id: str, operator: str = "eSIM Myanmar", 
                   plan_type: str = "5GB") -> 'eSIMProfile':
        """Create a new eSIM profile for a device"""
        profile_id = f"esim_{device_id}_{uuid.uuid4().hex[:8]}"
        iccid = f"89860{uuid.uuid4().hex[:15]}"
        
        return cls(
            profile_id=profile_id,
            iccid=iccid,
            operator=operator,
            plan_type=plan_type
        )
    
    def validate(self) -> bool:
        """Validate eSIM profile data"""
        if not self.profile_id or not isinstance(self.profile_id, str):
            return False
        if not self.iccid or not isinstance(self.iccid, str):
            return False
        if not self.operator or not isinstance(self.operator, str):
            return False
        if not self.plan_type or not isinstance(self.plan_type, str):
            return False
        return True