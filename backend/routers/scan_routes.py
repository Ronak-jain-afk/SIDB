"""
Scan API Routes for Shadow IT Discovery Bot.
Handles all scan-related HTTP endpoints.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status, Request
from typing import List

from config import get_settings
from models import (
    ScanRequest,
    ScanResponse,
    ScanStatusResponse,
    ScanResult,
    DashboardSummary,
    ScanStatus,
    Asset,
    Recommendation
)
from services import get_scan_service
from utils.rate_limiter import get_rate_limiter

router = APIRouter(prefix="/api", tags=["Scans"], dependencies=[Depends(check_rate_limit)])

_api_limiter_initialized = False


async def check_rate_limit(request: Request):
    """Dependency that limits API request rate."""
    global _api_limiter_initialized
    settings = get_settings()
    limiter = get_rate_limiter()
    
    if not _api_limiter_initialized:
        limiter.get_limiter(
            "api",
            requests_per_second=max(settings.api_rate_limit / 60.0, 0.1),
            burst_size=settings.api_rate_limit
        )
        _api_limiter_initialized = True
    
    await limiter.acquire("api", tokens=1)


# ============== SCAN ENDPOINTS ==============

@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start Asset Discovery Scan",
    description="Initiates an asynchronous scan to discover exposed assets for a domain."
)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Start a new scan for the specified domain.
    
    The scan runs asynchronously in the background.
    Use the returned scan_id to poll for status and results.
    
    **Example request:**
    ```json
    {"domain": "example.com", "enable_network_scan": false}
    ```
    
    **Returns:** scan_id and initial status
    
    **Note:** Set `enable_network_scan: true` to perform active port scanning.
    Only enable this for domains you own or have permission to scan.
    """
    service = get_scan_service()
    
    # Create initial scan record
    scan = await service.create_scan(request.domain)
    
    # Queue background scan with network scan option
    background_tasks.add_task(
        service.run_scan,
        scan.scan_id,
        request.domain,
        request.enable_network_scan
    )
    
    scan_type = "network scan" if request.enable_network_scan else "OSINT scan"
    
    return ScanResponse(
        scan_id=scan.scan_id,
        status=ScanStatus.PENDING,
        message=f"{scan_type.capitalize()} initiated for {request.domain}. Poll /api/scan/{scan.scan_id}/status for progress."
    )


@router.get(
    "/scan/{scan_id}/status",
    response_model=ScanStatusResponse,
    summary="Get Scan Status",
    description="Poll this endpoint to check scan progress."
)
async def get_scan_status(scan_id: str):
    """
    Get the current status of a scan.
    
    Use this for polling until status is 'completed' or 'failed'.
    
    **Status progression:** pending → scanning → analyzing → completed
    """
    service = get_scan_service()
    status_data = await service.get_scan_status(scan_id)
    
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )
    
    return ScanStatusResponse(**status_data)


@router.get(
    "/results/{scan_id}",
    response_model=ScanResult,
    summary="Get Full Scan Results",
    description="Retrieve complete scan results including assets, risks, and recommendations."
)
async def get_scan_results(scan_id: str):
    """
    Get complete scan results.
    
    **Returns:**
    - Discovered assets with risk analysis
    - Remediation recommendations
    - Security posture score
    
    **Note:** Only returns data when scan status is 'completed'.
    """
    service = get_scan_service()
    scan = await service.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )
    
    if scan.status == ScanStatus.PENDING or scan.status == ScanStatus.SCANNING:
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail="Scan still in progress. Poll /api/scan/{scan_id}/status"
        )
    
    if scan.status == ScanStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {scan.error_message}"
        )
    
    return scan


@router.get(
    "/dashboard/{scan_id}",
    response_model=DashboardSummary,
    summary="Get Dashboard Summary",
    description="Get aggregated data optimized for dashboard visualization."
)
async def get_dashboard_summary(scan_id: str):
    """
    Get aggregated dashboard data.
    
    **Returns:**
    - Total asset count
    - Severity distribution (for pie/bar charts)
    - Top 5 highest risk assets
    - Security posture score
    - Top 5 priority recommendations
    
    Optimized for frontend dashboard rendering.
    """
    service = get_scan_service()
    scan = await service.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )
    
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail="Scan not yet completed"
        )
    
    # Get top 5 highest risk assets
    sorted_assets = sorted(
        scan.assets,
        key=lambda a: a.risk_score,
        reverse=True
    )
    highest_risks = sorted_assets[:5]
    
    # Get top 5 recommendations
    top_recommendations = scan.recommendations[:5]
    
    return DashboardSummary(
        scan_id=scan.scan_id,
        domain=scan.domain,
        total_assets=len(scan.assets),
        severity_distribution=scan.posture_score.risk_distribution,
        highest_risks=highest_risks,
        posture_score=scan.posture_score,
        top_recommendations=top_recommendations,
        scan_timestamp=scan.started_at
    )


# ============== ASSET ENDPOINTS ==============

@router.get(
    "/assets/{scan_id}",
    response_model=List[Asset],
    summary="Get All Assets",
    description="Get all discovered assets for a scan."
)
async def get_assets(scan_id: str, risk_level: str = None):
    """
    Get all assets from a completed scan.
    
    **Query params:**
    - risk_level: Filter by risk level (Critical, High, Medium, Low)
    """
    service = get_scan_service()
    scan = await service.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )
    
    assets = scan.assets
    
    # Filter by risk level if specified
    if risk_level:
        assets = [a for a in assets if a.risk_level.value == risk_level]
    
    return assets


@router.get(
    "/assets/{scan_id}/{asset_id}",
    response_model=Asset,
    summary="Get Single Asset",
    description="Get details for a specific asset."
)
async def get_asset(scan_id: str, asset_id: str):
    """Get detailed information for a specific asset."""
    service = get_scan_service()
    scan = await service.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )
    
    for asset in scan.assets:
        if asset.asset_id == asset_id:
            return asset
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Asset {asset_id} not found in scan {scan_id}"
    )


# ============== RECOMMENDATION ENDPOINTS ==============

@router.get(
    "/recommendations/{scan_id}",
    response_model=List[Recommendation],
    summary="Get All Recommendations",
    description="Get all remediation recommendations for a scan."
)
async def get_recommendations(scan_id: str, category: str = None):
    """
    Get all recommendations from a completed scan.
    
    **Query params:**
    - category: Filter by category (Network Security, Access Control, etc.)
    """
    service = get_scan_service()
    scan = await service.get_scan(scan_id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )
    
    recommendations = scan.recommendations
    
    # Filter by category if specified
    if category:
        recommendations = [r for r in recommendations if r.category == category]
    
    return recommendations
