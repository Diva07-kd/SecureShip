"""
SecureScan FastAPI Backend Application.
Provides secure archive upload, async single-worker scan execution,
and multi-format vulnerability reporting.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api.endpoints import api_router, health_router
from app.config import settings
from app.core.queue import get_job_queue
from app.routers.upload import limiter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("securescan.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Manages application lifecycle: starts background worker queue on startup
    and gracefully stops it upon shutdown.
    """
    logger.info("Initializing SecureScan backend services...")
    queue = get_job_queue()
    await queue.start()
    yield
    logger.info("Shutting down SecureScan backend services...")
    await queue.stop()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="SecureScan — Defensive Security Scanner Web Platform powered by SecureShip",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Attach SlowAPI limiter state and error handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Configure CORS for local development and Docker / reverse proxy environments
ALLOWED_ORIGINS = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8080",
    "http://127.0.0.1",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8080",
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

# Mount API routers under /api and root health
app.include_router(api_router, prefix=settings.API_V1_PREFIX)
app.include_router(health_router, prefix="")


@app.get("/")
async def root() -> dict[str, Any]:
    return {
        "service": settings.PROJECT_NAME,
        "status": "online",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/health",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
