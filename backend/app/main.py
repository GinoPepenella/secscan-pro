import warnings
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.core.config import settings
from app.core.logging import setup_logging
from app.api.endpoints import scans, remediation, reports, system
from app.db.base import async_engine, Base
from loguru import logger

# Suppress cryptography deprecation warnings from asyncssh
# These are being addressed by pinning cryptography < 48.0.0
warnings.filterwarnings("ignore", category=DeprecationWarning, module="asyncssh")


# Setup logging
setup_logging("INFO" if not settings.DEBUG else "DEBUG")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    logger.info("Starting SecScan Pro API")

    # Create database tables
    try:
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")

    yield

    # Shutdown
    logger.info("Shutting down SecScan Pro API")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scans.router, prefix=f"{settings.API_V1_STR}/scans", tags=["scans"])
app.include_router(remediation.router, prefix=f"{settings.API_V1_STR}/remediation", tags=["remediation"])
app.include_router(reports.router, prefix=f"{settings.API_V1_STR}/reports", tags=["reports"])
app.include_router(system.router, prefix=f"{settings.API_V1_STR}/system", tags=["system"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Welcome to SecScan Pro API",
        "version": settings.VERSION,
        "docs": "/api/docs"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )
