"""
eSIM Profile repository for Firestore operations
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.esim_profile import eSIMProfile
from .base_repository import BaseRepository

class eSIMProfileRepository(BaseRepository[eSIMProfile]):
    """Repository for eSIM Profile entities"""
    
    def __init__(self):
        super().__init__("esim_profiles", eSIMProfile)
    
    def _to_dict(self, entity: eSIMProfile) -> Dict[str, Any]:
        """Convert eSIM Profile to dictionary"""
        return entity.to_dict()
    
    def _from_dict(self, data: Dict[str, Any]) -> eSIMProfile:
        """Convert dictionary to eSIM Profile"""
        return eSIMProfile.from_dict(data)
    
    def _get_id(self, entity: eSIMProfile) -> str:
        """Get eSIM Profile ID"""
        return entity.profile_id
    
    async def get_by_iccid(self, iccid: str) -> Optional[eSIMProfile]:
        """Get eSIM profile by ICCID"""
        profiles = await self.query("iccid", "==", iccid, limit=1)
        return profiles[0] if profiles else None
    
    async def get_by_operator(self, operator: str, limit: Optional[int] = None) -> List[eSIMProfile]:
        """Get eSIM profiles by operator"""
        return await self.query("operator", "==", operator, limit)
    
    async def get_by_status(self, status: str, limit: Optional[int] = None) -> List[eSIMProfile]:
        """Get eSIM profiles by status"""
        return await self.query("status", "==", status, limit)
    
    async def get_active_profiles(self, limit: Optional[int] = None) -> List[eSIMProfile]:
        """Get all active eSIM profiles"""
        return await self.get_by_status("active", limit)
    
    async def get_provisioned_profiles(self, limit: Optional[int] = None) -> List[eSIMProfile]:
        """Get all provisioned eSIM profiles"""
        return await self.get_by_status("provisioned", limit)
    
    async def get_by_plan_type(self, plan_type: str, limit: Optional[int] = None) -> List[eSIMProfile]:
        """Get eSIM profiles by plan type"""
        return await self.query("plan_type", "==", plan_type, limit)
    
    async def get_expiring_profiles(self, days_ahead: int = 7) -> List[eSIMProfile]:
        """Get profiles expiring within specified days"""
        expiry_threshold = datetime.utcnow() + timedelta(days=days_ahead)
        expiry_iso = expiry_threshold.isoformat()
        
        return await self.query("expiry_date", "<=", expiry_iso)
    
    async def get_expired_profiles(self) -> List[eSIMProfile]:
        """Get profiles that have already expired"""
        current_time = datetime.utcnow().isoformat()
        return await self.query("expiry_date", "<", current_time)
    
    async def activate_profile(self, profile_id: str) -> bool:
        """Activate an eSIM profile"""
        try:
            def activate(profile: eSIMProfile) -> eSIMProfile:
                profile.activate()
                return profile
            
            result = await self.transaction_update(profile_id, activate)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to activate profile {profile_id}: {e}")
            return False
    
    async def deactivate_profile(self, profile_id: str) -> bool:
        """Deactivate an eSIM profile"""
        try:
            def deactivate(profile: eSIMProfile) -> eSIMProfile:
                profile.deactivate()
                return profile
            
            result = await self.transaction_update(profile_id, deactivate)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to deactivate profile {profile_id}: {e}")
            return False
    
    async def update_data_usage(self, profile_id: str, usage_mb: int) -> bool:
        """Update data usage for a profile"""
        try:
            def update_usage(profile: eSIMProfile) -> eSIMProfile:
                profile.update_data_usage(usage_mb)
                return profile
            
            result = await self.transaction_update(profile_id, update_usage)
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to update data usage for profile {profile_id}: {e}")
            return False
    
    async def get_usage_statistics(self, operator: Optional[str] = None) -> Dict[str, Any]:
        """Get data usage statistics"""
        try:
            if operator:
                profiles = await self.get_by_operator(operator)
            else:
                profiles = await self.list_all()
            
            stats = {
                "total_profiles": len(profiles),
                "total_usage_mb": 0,
                "average_usage_mb": 0,
                "by_plan_type": {},
                "by_operator": {},
                "active_profiles": 0,
                "expired_profiles": 0
            }
            
            total_usage = 0
            
            for profile in profiles:
                # Total usage
                profile_usage = profile.get_total_usage()
                total_usage += profile_usage
                
                # By plan type
                plan_type = profile.plan_type
                if plan_type not in stats["by_plan_type"]:
                    stats["by_plan_type"][plan_type] = {"count": 0, "usage_mb": 0}
                stats["by_plan_type"][plan_type]["count"] += 1
                stats["by_plan_type"][plan_type]["usage_mb"] += profile_usage
                
                # By operator
                op = profile.operator
                if op not in stats["by_operator"]:
                    stats["by_operator"][op] = {"count": 0, "usage_mb": 0}
                stats["by_operator"][op]["count"] += 1
                stats["by_operator"][op]["usage_mb"] += profile_usage
                
                # Status counts
                if profile.is_active():
                    stats["active_profiles"] += 1
                if profile.is_expired():
                    stats["expired_profiles"] += 1
            
            stats["total_usage_mb"] = total_usage
            if len(profiles) > 0:
                stats["average_usage_mb"] = total_usage / len(profiles)
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get usage statistics: {e}")
            return {
                "total_profiles": 0,
                "total_usage_mb": 0,
                "average_usage_mb": 0,
                "by_plan_type": {},
                "by_operator": {},
                "active_profiles": 0,
                "expired_profiles": 0
            }
    
    async def cleanup_expired_profiles(self, days_after_expiry: int = 30) -> int:
        """Remove profiles that expired more than specified days ago"""
        try:
            cleanup_threshold = datetime.utcnow() - timedelta(days=days_after_expiry)
            cleanup_iso = cleanup_threshold.isoformat()
            
            expired_profiles = await self.query("expiry_date", "<", cleanup_iso)
            
            deleted_count = 0
            for profile in expired_profiles:
                if await self.delete(profile.profile_id):
                    deleted_count += 1
            
            self.logger.info(f"Cleaned up {deleted_count} expired profiles")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup expired profiles: {e}")
            return 0
    
    async def get_monthly_usage_report(self, year: int, month: int) -> Dict[str, Any]:
        """Get monthly usage report for specified year and month"""
        try:
            profiles = await self.list_all()
            month_key = f"{year:04d}-{month:02d}"
            
            report = {
                "year": year,
                "month": month,
                "total_profiles": len(profiles),
                "profiles_with_usage": 0,
                "total_usage_mb": 0,
                "by_operator": {},
                "by_plan_type": {},
                "top_users": []
            }
            
            profile_usage_list = []
            
            for profile in profiles:
                monthly_usage = profile.data_usage.get(month_key, 0)
                
                if monthly_usage > 0:
                    report["profiles_with_usage"] += 1
                    report["total_usage_mb"] += monthly_usage
                    
                    # Track for top users
                    profile_usage_list.append({
                        "profile_id": profile.profile_id,
                        "operator": profile.operator,
                        "plan_type": profile.plan_type,
                        "usage_mb": monthly_usage
                    })
                    
                    # By operator
                    op = profile.operator
                    if op not in report["by_operator"]:
                        report["by_operator"][op] = {"count": 0, "usage_mb": 0}
                    report["by_operator"][op]["count"] += 1
                    report["by_operator"][op]["usage_mb"] += monthly_usage
                    
                    # By plan type
                    plan = profile.plan_type
                    if plan not in report["by_plan_type"]:
                        report["by_plan_type"][plan] = {"count": 0, "usage_mb": 0}
                    report["by_plan_type"][plan]["count"] += 1
                    report["by_plan_type"][plan]["usage_mb"] += monthly_usage
            
            # Top 10 users by usage
            profile_usage_list.sort(key=lambda x: x["usage_mb"], reverse=True)
            report["top_users"] = profile_usage_list[:10]
            
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate monthly usage report: {e}")
            return {
                "year": year,
                "month": month,
                "total_profiles": 0,
                "profiles_with_usage": 0,
                "total_usage_mb": 0,
                "by_operator": {},
                "by_plan_type": {},
                "top_users": []
            }