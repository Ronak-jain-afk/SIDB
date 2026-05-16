"""
Shadow IT Discovery Bot - Main Application Entry Point

A cybersecurity platform for detecting and analyzing publicly exposed organizational assets.
This is an External Attack Surface Management (EASM) simulation system.

Run with: uvicorn main:app --reload
"""

import os
import logging
from pathlib import Path

from fastapi import FastAPI

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("shadow")
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager

from config import get_settings
from routers import scan_router
from storage import get_database

# Frontend directory path
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    Runs startup and shutdown procedures.
    """
    # Startup
    settings = get_settings()
    logger.info("=" * 60)
    logger.info("Shadow IT Discovery Bot - Starting")
    logger.info("=" * 60)
    logger.info("Demo Mode: %s", settings.demo_mode)
    logger.info("Shodan API: %s", 'Configured' if settings.shodan_api_key else 'Not configured (using mock data)')
    logger.info("Scan Retention: %s days", settings.scan_retention_days)
    
    # Clean up old scans on startup
    db = get_database()
    db.cleanup_old_scans()
    
    logger.info("=" * 60)
    
    yield
    
    # Shutdown
    logger.info("Shadow IT Discovery Bot - Shutting down")


# Initialize FastAPI application
app = FastAPI(
    title="Shadow IT Discovery Bot",
    description="""
    ## External Attack Surface Management (EASM) Platform
    
    This API helps organizations discover, analyze, and remediate publicly exposed assets (Shadow IT).
    
    ### Features
    
    - **Asset Discovery**: Identify internet-facing services using Shodan API or mock data
    - **Risk Analysis**: Rule-based security assessment using cybersecurity heuristics
    - **Recommendations**: Actionable remediation guidance for each vulnerability
    - **Security Scoring**: Overall organizational security posture calculation
    
    ### Workflow
    
    1. **POST /api/scan** - Start a scan for a domain
    2. **GET /api/scan/{id}/status** - Poll until scan completes
    3. **GET /api/results/{id}** - Get full results
    4. **GET /api/dashboard/{id}** - Get dashboard visualization data
    
    ### Note
    
    This is a hackathon project demonstrating EASM concepts.
    It does NOT perform intrusive security testing.
    """,
    version="1.0.0",
    contact={
        "name": "Shadow IT Discovery Bot",
    },
    license_info={
        "name": "MIT",
    },
    lifespan=lifespan
)

# Configure CORS for frontend access
settings = get_settings()
allowed_origins = [o.strip() for o in settings.cors_origins.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan_router)

# Serve frontend static files
if FRONTEND_DIR.exists():
    app.mount("/css", StaticFiles(directory=FRONTEND_DIR / "css"), name="css")
    app.mount("/js", StaticFiles(directory=FRONTEND_DIR / "js"), name="js")


# ============== HEALTH CHECK ==============

@app.get(
    "/health",
    tags=["System"],
    summary="Health Check",
    description="Check if the API is running."
)
async def health_check():
    """
    Simple health check endpoint.
    Returns OK if the service is running.
    """
    return {
        "status": "healthy",
        "service": "Shadow IT Discovery Bot",
        "version": "1.0.0"
    }


@app.get(
    "/",
    tags=["System"],
    summary="Root",
    description="Serve frontend dashboard or API info."
)
async def root():
    """
    Root endpoint - serves frontend if available, otherwise API info.
    """
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    
    return {
        "name": "Shadow IT Discovery Bot API",
        "version": "1.0.0",
        "description": "External Attack Surface Management Platform",
        "docs": "/docs",
        "health": "/health",
        "quick_start": {
            "step_1": "POST /api/scan with {'domain': 'example.com'}",
            "step_2": "GET /api/scan/{scan_id}/status to poll progress",
            "step_3": "GET /api/results/{scan_id} for full results",
            "step_4": "GET /api/dashboard/{scan_id} for visualization data"
        }
    }


# ============== RUN DIRECTLY ==============

if __name__ == "__main__":
    import uvicorn
    
    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=True
    )
