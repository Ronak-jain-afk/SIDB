"""
Storage layer for Shadow IT Discovery Bot.
Handles JSON-based persistence for scan results.
"""

import json
import os
import time
import aiofiles
from datetime import datetime
from typing import Optional, List
from pathlib import Path

from config import get_settings
from models import ScanResult, ScanStatus


class ScanDatabase:
    """
    JSON file-based storage for scan results.
    Each scan is stored as a separate JSON file in the scans directory.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.scans_dir = Path(self.settings.scans_dir)
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Create necessary data directories if they don't exist."""
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        Path(self.settings.mock_dir).mkdir(parents=True, exist_ok=True)
    
    def _get_scan_path(self, scan_id: str) -> Path:
        """Get the file path for a scan by ID."""
        return self.scans_dir / f"{scan_id}.json"
    
    async def save_scan(self, scan_result: ScanResult) -> bool:
        """
        Save scan result to JSON file.
        
        Args:
            scan_result: The scan result to persist
            
        Returns:
            True if saved successfully
        """
        try:
            scan_path = self._get_scan_path(scan_result.scan_id)
            
            # Convert to JSON-serializable dict with datetime handling
            data = scan_result.model_dump(mode='json')
            
            async with aiofiles.open(scan_path, 'w') as f:
                await f.write(json.dumps(data, indent=2, default=str))
            
            return True
        except Exception as e:
            print(f"Error saving scan {scan_result.scan_id}: {e}")
            return False
    
    async def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        """
        Retrieve scan result by ID.
        
        Args:
            scan_id: The scan identifier
            
        Returns:
            ScanResult if found, None otherwise
        """
        scan_path = self._get_scan_path(scan_id)
        
        if not scan_path.exists():
            return None
        
        try:
            async with aiofiles.open(scan_path, 'r') as f:
                content = await f.read()
                data = json.loads(content)
                return ScanResult(**data)
        except Exception as e:
            print(f"Error reading scan {scan_id}: {e}")
            return None
    
    async def update_scan_status(
        self, 
        scan_id: str, 
        status: ScanStatus,
        error_message: Optional[str] = None
    ) -> bool:
        """
        Update the status of an existing scan.
        
        Args:
            scan_id: The scan identifier
            status: New status to set
            error_message: Optional error message for failed scans
            
        Returns:
            True if updated successfully
        """
        scan = await self.get_scan(scan_id)
        
        if not scan:
            return False
        
        scan.status = status
        
        if status == ScanStatus.COMPLETED:
            scan.completed_at = datetime.utcnow()
        
        if error_message:
            scan.error_message = error_message
        
        return await self.save_scan(scan)
    
    async def list_scans(self, limit: int = 50) -> List[ScanResult]:
        """
        List recent scans.
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of scan results, newest first
        """
        scans = []
        
        try:
            scan_files = sorted(
                self.scans_dir.glob("*.json"),
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )[:limit]
            
            for scan_file in scan_files:
                scan_id = scan_file.stem
                scan = await self.get_scan(scan_id)
                if scan:
                    scans.append(scan)
        except Exception as e:
            print(f"Error listing scans: {e}")
        
        return scans
    
    async def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a scan by ID.
        
        Args:
            scan_id: The scan identifier
            
        Returns:
            True if deleted successfully
        """
        scan_path = self._get_scan_path(scan_id)
        
        if scan_path.exists():
            try:
                scan_path.unlink()
                return True
            except Exception as e:
                print(f"Error deleting scan {scan_id}: {e}")
        
        return False
    
    def scan_exists(self, scan_id: str) -> bool:
        """Check if a scan exists."""
        return self._get_scan_path(scan_id).exists()
    
    def cleanup_old_scans(self) -> int:
        """
        Delete scan files older than retention period.
        
        Returns:
            Number of deleted scan files
        """
        retention_seconds = self.settings.scan_retention_days * 86400
        now = time.time()
        deleted = 0
        
        for scan_file in self.scans_dir.glob("*.json"):
            file_age = now - scan_file.stat().st_mtime
            if file_age > retention_seconds:
                try:
                    scan_file.unlink()
                    deleted += 1
                except Exception as e:
                    print(f"Error deleting old scan {scan_file.name}: {e}")
        
        if deleted:
            print(f"Cleaned up {deleted} old scan(s)")
        return deleted


# Global database instance
_db_instance: Optional[ScanDatabase] = None


def get_database() -> ScanDatabase:
    """Get or create the database singleton instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = ScanDatabase()
    return _db_instance
