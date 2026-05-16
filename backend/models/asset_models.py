"""
Data models for Shadow IT Discovery Bot.
Defines Pydantic schemas for assets, scans, and API responses.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, model_validator


class RiskLevel(str, Enum):
    """Risk severity classification levels."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ExposureLevel(str, Enum):
    """Asset exposure classification."""
    PUBLIC = "Public"
    RESTRICTED = "Restricted"
    INTERNAL = "Internal"


class ScanStatus(str, Enum):
    """Scan operation status states."""
    PENDING = "pending"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class PostureRating(str, Enum):
    """Overall security posture classification."""
    SECURE = "Secure"
    MODERATE_RISK = "Moderate Risk"
    HIGH_RISK = "High Risk"
    CRITICAL_EXPOSURE = "Critical Exposure"


# ============== Core Asset Model ==============

class Asset(BaseModel):
    """
    Represents a discovered internet-facing asset.
    Core data structure for the entire platform.
    """
    asset_id: str = Field(..., description="Unique identifier for the asset")
    ip: str = Field(..., description="IP address of the asset")
    port: int = Field(..., description="Open port number")
    service: str = Field(..., description="Service running on the port (e.g., FTP, HTTP)")
    technology: Optional[str] = Field(None, description="Technology/software detected")
    version: Optional[str] = Field(None, description="Software version if detected")
    hostname: Optional[str] = Field(None, description="Hostname or domain")
    exposure: ExposureLevel = Field(ExposureLevel.PUBLIC, description="Exposure level")
    risk_level: RiskLevel = Field(RiskLevel.LOW, description="Calculated risk level")
    risk_score: int = Field(0, ge=0, le=100, description="Numeric risk score (0-100)")
    risk_factors: List[str] = Field(default_factory=list, description="List of risk factors")
    
    class Config:
        json_schema_extra = {
            "example": {
                "asset_id": "A102",
                "ip": "34.123.45.67",
                "port": 21,
                "service": "FTP",
                "technology": "vsFTPd",
                "version": "2.3.4",
                "hostname": "ftp.example.com",
                "exposure": "Public",
                "risk_level": "Critical",
                "risk_score": 85,
                "risk_factors": ["FTP exposed to internet", "Outdated software version"]
            }
        }


# ============== Recommendation Model ==============

class Recommendation(BaseModel):
    """Remediation recommendation for a security risk."""
    recommendation_id: str = Field(..., description="Unique recommendation ID")
    asset_id: str = Field(..., description="Related asset ID")
    title: str = Field(..., description="Short recommendation title")
    description: str = Field(..., description="Detailed remediation steps")
    priority: RiskLevel = Field(..., description="Priority based on risk")
    category: str = Field(..., description="Category (e.g., Network, Access Control)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "recommendation_id": "REC001",
                "asset_id": "A102",
                "title": "Disable FTP Service",
                "description": "Migrate to SFTP and disable anonymous FTP access.",
                "priority": "Critical",
                "category": "Network Security"
            }
        }


# ============== Security Score Model ==============

class PostureScore(BaseModel):
    """Overall organizational security posture score."""
    score: int = Field(..., ge=0, le=100, description="Security score (0-100)")
    rating: PostureRating = Field(..., description="Posture classification")
    summary: str = Field(..., description="Human-readable summary")
    risk_distribution: dict = Field(..., description="Count by risk level")
    
    class Config:
        json_schema_extra = {
            "example": {
                "score": 42,
                "rating": "High Risk",
                "summary": "Organization has significant exposure requiring immediate attention.",
                "risk_distribution": {
                    "Critical": 2,
                    "High": 3,
                    "Medium": 5,
                    "Low": 2
                }
            }
        }


# ============== API Request/Response Models ==============

class ScanRequest(BaseModel):
    """Request body for starting a new scan."""
    domain: Optional[str] = Field(
        None,
        min_length=3,
        pattern=r"^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
        description="Target domain to scan (e.g., example.com)"
    )
    cidr: Optional[str] = Field(
        None,
        pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$",
        description="CIDR range to scan (e.g., 192.168.1.0/24)"
    )
    enable_network_scan: bool = Field(
        False, 
        description="Enable active network scanning (requires permission)"
    )
    
    @model_validator(mode='after')
    def check_target(self):
        if not self.domain and not self.cidr:
            raise ValueError("Either 'domain' or 'cidr' must be provided")
        if self.domain and self.cidr:
            raise ValueError("Provide either 'domain' or 'cidr', not both")
        return self
    
    class Config:
        json_schema_extra = {
            "examples": [
                {"domain": "example.com", "enable_network_scan": False},
                {"cidr": "192.168.1.0/24", "enable_network_scan": True}
            ]
        }


class ScanResponse(BaseModel):
    """Response after initiating a scan."""
    scan_id: str = Field(..., description="Unique scan identifier")
    status: ScanStatus = Field(..., description="Current scan status")
    message: str = Field(..., description="Status message")


class ScanStatusResponse(BaseModel):
    """Response for scan status polling."""
    scan_id: str
    status: ScanStatus
    progress: str = Field(..., description="Current progress stage")
    started_at: datetime
    completed_at: Optional[datetime] = None


class ScanResult(BaseModel):
    """Complete scan results with all analysis data."""
    scan_id: str
    domain: str
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    assets: List[Asset] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)
    posture_score: Optional[PostureScore] = None
    error_message: Optional[str] = None


class ChangedAsset(BaseModel):
    """An asset whose risk score changed between two scans."""
    asset: Asset
    risk_score_before: int
    risk_level_before: str
    risk_score_after: int
    risk_level_after: str


class ScanComparison(BaseModel):
    """Diff between two scan results."""
    scan_id_before: str
    scan_id_after: str
    domain_before: str
    domain_after: str
    new_assets: List[Asset] = Field(default_factory=list)
    removed_assets: List[Asset] = Field(default_factory=list)
    changed_assets: List[ChangedAsset] = Field(default_factory=list)
    score_before: int = 0
    score_after: int = 0
    rating_before: str = ""
    rating_after: str = ""
    total_new: int = 0
    total_removed: int = 0
    total_changed: int = 0


class DashboardSummary(BaseModel):
    """Aggregated dashboard data for visualization."""
    scan_id: str
    domain: str
    total_assets: int
    severity_distribution: dict = Field(..., description="Asset count by severity")
    highest_risks: List[Asset] = Field(..., description="Top 5 highest risk assets")
    posture_score: PostureScore
    top_recommendations: List[Recommendation] = Field(..., description="Top 5 priority fixes")
    scan_timestamp: datetime
