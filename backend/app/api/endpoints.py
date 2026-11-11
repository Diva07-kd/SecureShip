"""
Unified API Router aggregating scan, jobs, reports, and health endpoints.
Provides dual compatibility with PROJECT.md and ORIGINAL_REQUEST.md.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.routers.health import router as health_router
from app.routers.jobs import router as jobs_router
from app.routers.reports import router as reports_router
from app.routers.upload import router as upload_router

api_router = APIRouter()

api_router.include_router(upload_router)
api_router.include_router(jobs_router)
api_router.include_router(reports_router)
api_router.include_router(health_router)

__all__ = ["api_router", "upload_router", "jobs_router", "reports_router", "health_router"]
