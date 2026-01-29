"""
Device repository for Firestore operations
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.device import Device, DeviceStatus
from .base_repository import BaseRepository

class DeviceRepository(BaseRepository[Device]):
    """Repository for Device entities"""
    
    def __init__(self):
        super().__init__("devices", Device)
    
    def _to_dict(self, entity: Device) -> Dict[str, Any]:
        """Convert Device to dictionary"""
        return entity.to_dict()
    
    def _from_dict(self, data: Dict[str, Any]) -> Device:
        """Convert dictionary to Device"""
        return Device.from_dict(data)
    
    def _get_id(self, entity: Device) -> str:
        """Get Device ID"""
        return entity.device_id
    
    async def get_by_status(self, status: DeviceStatus, limit: Optional[int] = None) -> List[Device]:
        """Get devices by status"""
        return await self.query("status", "==", status.value, limit)
    
    async def get_active_devices(self, limit: Optional[int] = None) -> List[Device]:
        """Get all active devices"""
        return await self.get_by_status(DeviceStatus.ACTIVE, limit)
    
    async def get_by_device_type(self, device_type: str, limit: Optional[int] = None) -> List[Device]:
        """Get devices by type"""
        return await self.query("device_type", "==", device_type, limit)
    
    async def get_online_devices(self, minutes_threshold: int = 5) -> List[Device]:
        """Get devices that were seen recently (considered online)"""
        threshold_time = datetime.utcnow() - timedelta(minutes=minutes_threshold)
        threshold_iso = threshold_time.isoformat()
        
        return await self.query("last_seen", ">=", threshold_iso)
    
    async def get_offline_devices(self, minutes_threshold: int = 5) -> List[Device]:
        """Get devices that haven't been seen recently (considered offline)"""
        threshold_time = datetime.utcnow() - timedelta(minutes=minutes_threshold)
        threshold_iso = threshold_time.isoformat()
        
        return await self.query("last_seen", "<", threshold_iso)
    
    async def update_last_seen(self, device_id: str) -> bool:
        """Update device last seen timestamp"""
        try:
            def update_timestamp(device: Device) -> Device:
                device.update_last_seen()
                return device
            
            result = await self.transaction_update(device_id, update_timestamp)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to update last seen for device {device_id}: {e}")
            return False
    
    async def update_device_status(self, device_id: str, new_status: DeviceStatus) -> bool:
        """Update device status"""
        try:
            def update_status(device: Device) -> Device:
                device.update_status(new_status)
                return device
            
            result = await self.transaction_update(device_id, update_status)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to update status for device {device_id}: {e}")
            return False
    
    async def get_devices_with_esim(self, limit: Optional[int] = None) -> List[Device]:
        """Get devices that have eSIM profiles"""
        # Note: This requires a composite query which might need a custom index
        all_devices = await self.list_all(limit)
        return [device for device in all_devices if device.esim_profile is not None]
    
    async def get_devices_without_esim(self, limit: Optional[int] = None) -> List[Device]:
        """Get devices that don't have eSIM profiles"""
        all_devices = await self.list_all(limit)
        return [device for device in all_devices if device.esim_profile is None]
    
    async def search_devices(self, search_term: str, limit: Optional[int] = None) -> List[Device]:
        """Search devices by device_id or device_type containing search term"""
        # Note: Firestore doesn't support full-text search natively
        # This is a simple implementation that gets all devices and filters
        all_devices = await self.list_all()
        
        matching_devices = []
        search_lower = search_term.lower()
        
        for device in all_devices:
            if (search_lower in device.device_id.lower() or 
                search_lower in device.device_type.lower()):
                matching_devices.append(device)
                
                if limit and len(matching_devices) >= limit:
                    break
        
        return matching_devices
    
    async def get_device_statistics(self) -> Dict[str, Any]:
        """Get device statistics"""
        try:
            all_devices = await self.list_all()
            
            stats = {
                "total_devices": len(all_devices),
                "by_status": {},
                "by_type": {},
                "online_devices": 0,
                "with_esim": 0,
                "without_esim": 0
            }
            
            # Count by status
            for status in DeviceStatus:
                stats["by_status"][status.value] = 0
            
            # Process each device
            for device in all_devices:
                # Count by status
                stats["by_status"][device.status.value] += 1
                
                # Count by type
                device_type = device.device_type
                if device_type not in stats["by_type"]:
                    stats["by_type"][device_type] = 0
                stats["by_type"][device_type] += 1
                
                # Count online devices
                if device.is_online():
                    stats["online_devices"] += 1
                
                # Count eSIM status
                if device.esim_profile:
                    stats["with_esim"] += 1
                else:
                    stats["without_esim"] += 1
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get device statistics: {e}")
            return {
                "total_devices": 0,
                "by_status": {},
                "by_type": {},
                "online_devices": 0,
                "with_esim": 0,
                "without_esim": 0
            }
    
    async def cleanup_old_devices(self, days_threshold: int = 30) -> int:
        """Remove devices that haven't been seen for a specified number of days"""
        try:
            threshold_time = datetime.utcnow() - timedelta(days=days_threshold)
            threshold_iso = threshold_time.isoformat()
            
            old_devices = await self.query("last_seen", "<", threshold_iso)
            
            deleted_count = 0
            for device in old_devices:
                if await self.delete(device.device_id):
                    deleted_count += 1
            
            self.logger.info(f"Cleaned up {deleted_count} old devices")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old devices: {e}")
            return 0