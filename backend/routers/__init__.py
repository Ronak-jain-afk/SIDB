# Routers package
from .report_routes import router as report_router
from .scan_routes import router as scan_router

__all__ = ["scan_router", "report_router"]
