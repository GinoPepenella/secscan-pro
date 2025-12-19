from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from app.scanners.ssh_manager import SSHManager, AuthMethod
from app.scanners.stig_scanner import STIGScanner
import asyncio

router = APIRouter()


class SSHTestRequest(BaseModel):
    host: str
    username: str
    password: Optional[str] = None
    private_key_path: Optional[str] = None
    port: int = 22
    auth_method: AuthMethod = AuthMethod.PASSWORD


class SSHTestResponse(BaseModel):
    connected: bool
    hostname: Optional[str]
    os_info: Optional[str]
    kernel: Optional[str]
    error: Optional[str]


@router.post("/test-ssh", response_model=SSHTestResponse)
async def test_ssh_connection(request: SSHTestRequest):
    """Test SSH connection to a target."""
    from app.scanners.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator()

    result = await orchestrator.test_ssh_connection(
        host=request.host,
        username=request.username,
        password=request.password,
        private_key_path=request.private_key_path,
        port=request.port,
        auth_method=request.auth_method
    )

    return result


@router.get("/stig-profiles")
async def get_available_stig_profiles():
    """Get list of available STIG profiles."""
    scanner = STIGScanner()

    try:
        profiles = await scanner.get_available_stigs()
        return {"profiles": profiles}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "SecScan Pro API",
        "version": "1.0.0"
    }


@router.get("/dependencies")
async def check_dependencies():
    """Check system dependencies."""
    dependencies = {
        "stig_scanner": False,
        "database": False,
        "redis": False
    }

    # Check STIG scanner
    try:
        from pathlib import Path
        from app.core.config import settings

        stig_path = Path(settings.STIG_SCANNER_PATH) / "Evaluate-STIG_Bash.sh"
        dependencies["stig_scanner"] = stig_path.exists()
    except:
        pass

    # Check database
    try:
        from app.db.base import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            await session.execute("SELECT 1")
            dependencies["database"] = True
    except:
        pass

    # Check Redis
    try:
        import redis
        from app.core.config import settings
        r = redis.from_url(settings.REDIS_URL)
        r.ping()
        dependencies["redis"] = True
    except:
        pass

    all_healthy = all(dependencies.values())

    return {
        "healthy": all_healthy,
        "dependencies": dependencies
    }
