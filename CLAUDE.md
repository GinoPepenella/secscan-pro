# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SecScan Pro is a security compliance and vulnerability scanning platform that combines STIG compliance checking with CVE vulnerability assessment. It integrates with the existing Evaluate-STIG framework at `/etc/ansible/roles/Evaluate-STIG` and provides automated remediation capabilities with PDF reporting.

## Architecture

The application follows a three-tier architecture:

### Backend (FastAPI + Python 3.11)
- **Entry Point**: `backend/app/main.py` - FastAPI application with lifespan events for database initialization
- **Configuration**: `backend/app/core/config.py` - Pydantic settings loaded from `.env` file
- **Database**: PostgreSQL with async SQLAlchemy, initialized automatically on startup via `lifespan` context manager
- **API Structure**: Routers in `backend/app/api/endpoints/` mounted at `/api/v1/{resource}`

### Frontend (React 18 + TypeScript)
- **Build Tool**: Vite with hot module replacement
- **State Management**: React Query (TanStack) for server state, theme context for UI state
- **Routing**: React Router v6 with layout wrapper pattern
- **API Integration**: Centralized in `frontend/src/services/api.ts` using Axios

### Infrastructure
- **Container Orchestration**: Docker Compose with health checks and dependency management
- **Reverse Proxy**: Nginx routes `/api` to backend, serves frontend static files
- **Volume Mounts**: STIG scanner at `/etc/ansible/roles/Evaluate-STIG` (read-only), reports in named volume

## Key Architectural Patterns

### Backend Patterns

**Scan Orchestration Flow**:
1. `ScanOrchestrator.execute_scan()` retrieves scan config from database
2. For each target, calls `_scan_target()` which delegates to SSH or local scanning
3. SSH scanning uses `SSHManager` as async context manager, then calls scanner methods
4. Both `STIGScanner` and `VulnerabilityScanner` return findings in standardized format
5. `_calculate_risk_metrics()` aggregates findings into weighted risk score (0-100)

**Scanner Integration**:
- `STIGScanner` executes the Evaluate-STIG Bash wrapper via subprocess
- Parses JSON output or falls back to text parsing
- Maps STIG severity (CAT1/CAT2/CAT3) to standard severity levels (Critical/High/Medium/Low)

**Remediation Engine**:
- Template-based system in `RemediationEngine._load_remediation_templates()`
- Falls back to regex-based script generation from STIG fix text
- Supports dry-run mode to preview changes without execution

**Database Models**:
- `Scan` → one-to-many → `Finding` relationship with cascade delete
- `Scan` → one-to-many → `Report` relationship with cascade delete
- All timestamps use `DateTime(timezone=True)` with UTC
- Enums for status, scan types, auth methods defined in models file

### Frontend Patterns

**Theme Management**:
- `ThemeProvider` in `lib/theme.tsx` wraps entire app
- Theme persisted to localStorage, applied via root class name
- Tailwind configured for class-based dark mode

**API Communication**:
- All API functions return Axios promises
- React Query hooks handle caching, refetching, and loading states
- Scan list refetches every 5 seconds when displayed (for real-time status updates)

**Form Handling**:
- Controlled components with local state
- Multi-line textarea for targets, split on newlines before submission
- SSH config conditionally rendered based on `use_ssh` toggle

## Development Commands

### Docker Environment (Primary)

```bash
# Build and start all services
docker-compose up -d --build

# View logs (follow mode)
docker-compose logs -f

# View backend logs only
docker-compose logs -f backend

# Restart backend after code changes
docker-compose restart backend

# Stop all services
docker-compose down

# Stop and remove volumes (full reset)
docker-compose down -v

# Access backend shell
docker-compose exec backend bash

# Access database shell
docker-compose exec db psql -U secscan

# Run database migrations (auto-runs on startup)
docker-compose exec backend python -c "from app.db.base import sync_engine, Base; Base.metadata.create_all(sync_engine)"
```

### Local Development (Backend)

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run backend with hot reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Access API docs at http://localhost:8000/api/docs
```

**Note**: Local backend requires PostgreSQL and Redis running (use Docker containers or install locally).

### Local Development (Frontend)

```bash
cd frontend

# Install dependencies
npm install

# Run dev server with hot reload
npm run dev
# Access at http://localhost:3000

# Build for production
npm run build

# Preview production build
npm run preview

# Type checking
npx tsc --noEmit

# Lint
npm run lint
```

### System Service Management

```bash
# Start via systemd (after install.sh)
sudo systemctl start secscan-pro

# Stop
sudo systemctl stop secscan-pro

# Restart
sudo systemctl restart secscan-pro

# Check status
sudo systemctl status secscan-pro

# View service logs
journalctl -u secscan-pro -f
```

## Critical Dependencies

### External STIG Scanner Requirement
The application requires Evaluate-STIG installed at `/etc/ansible/roles/Evaluate-STIG`. This path is:
- Mounted read-only into backend container
- Configurable via `STIG_SCANNER_PATH` environment variable
- Checked by `STIGScanner` on initialization

If STIG path differs, update `docker-compose.yml` volume mount:
```yaml
volumes:
  - /your/custom/path:/etc/ansible/roles/Evaluate-STIG:ro
```

### NVD API Integration
- `VulnerabilityScanner` uses `nvdlib` for CVE lookups
- Optional `NVD_API_KEY` in `.env` increases rate limits (5 → 50 requests/30s)
- Without API key, searches are limited and may timeout on large package lists
- Scanner implements conservative version matching when CPE parsing fails

## Database Schema Notes

### Scan Lifecycle States
- `PENDING` → `RUNNING` → `COMPLETED` or `FAILED`
- Frontend polls scans every 5s when status is `RUNNING`
- Cancellation sets status to `CANCELLED` and stops background task

### Finding Status Values
- `open` - Newly discovered or unresolved
- `closed` - STIG check passed (NotAFinding)
- `not_applicable` - Check doesn't apply to system
- `remediated` - Auto-remediation completed successfully

### Risk Score Calculation
Weighted formula in `ScanOrchestrator._calculate_risk_metrics()`:
```
risk_score = (critical × 10) + (high × 5) + (medium × 2) + (low × 0.5)
Capped at 100
```

## Common Development Tasks

### Adding New API Endpoint

1. Create endpoint function in appropriate file under `backend/app/api/endpoints/`
2. Use dependency injection for database session: `db: AsyncSession = Depends(get_db)`
3. Define Pydantic models for request/response at top of file
4. Router already mounted in `main.py`, changes auto-detected with `--reload`

### Adding New Scanner

1. Create scanner class in `backend/app/scanners/`
2. Implement async methods returning standardized finding format:
   ```python
   {
       "finding_type": str,
       "vuln_id": str,
       "title": str,
       "severity": str,  # critical|high|medium|low
       "description": str,
       "can_auto_remediate": bool,
       ...
   }
   ```
3. Integrate in `ScanOrchestrator._scan_target()` based on scan type
4. Add new `ScanType` enum value if needed in `models/scan.py`

### Adding Remediation Template

Edit `backend/app/remediation/engine.py` → `_load_remediation_templates()`:
```python
"V-XXXXX": {
    "description": "Human-readable description",
    "script": "bash command to execute",
    "requires_reboot": bool,
    "risk_level": "low|medium|high"
}
```

### Modifying Database Schema

1. Update models in `backend/app/models/scan.py`
2. Database auto-creates tables on startup via lifespan event
3. For production, use Alembic migrations (not currently configured)
4. Reset database: `docker-compose down -v && docker-compose up -d`

## Frontend Component Patterns

### Creating New Page

1. Add component in `frontend/src/pages/`
2. Add route in `App.tsx`:
   ```tsx
   <Route path="your-path" element={<YourComponent />} />
   ```
3. Update navigation in `Layout.tsx` if needed

### Using React Query

```tsx
const { data, isLoading, error } = useQuery({
  queryKey: ['resource', id],
  queryFn: async () => {
    const response = await apiFunction();
    return response.data;
  },
  refetchInterval: false  // or number in ms for polling
});
```

### Mutations with React Query

```tsx
const mutation = useMutation({
  mutationFn: async (data) => {
    return await apiFunction(data);
  },
  onSuccess: () => {
    // Invalidate queries, navigate, etc.
  }
});
```

## Configuration Management

### Environment Variables

Backend loads from `backend/.env` (copy from `backend/.env.example`):
- Database URLs must match Docker Compose service names in containers
- `STIG_SCANNER_PATH` must match volume mount path
- `REPORT_OUTPUT_DIR` should point to writable directory/volume

Frontend uses `frontend/.env`:
- `VITE_API_URL` should be `/api/v1` when served through Nginx
- For local dev without Docker, set to `http://localhost:8000/api/v1`

### Port Configuration

Default ports in `docker-compose.yml`:
- Frontend (Nginx): 3000
- Backend (FastAPI): 8000
- PostgreSQL: 5432
- Redis: 6379

To change, update port mappings in `docker-compose.yml` and corresponding config files.

## Troubleshooting Development Issues

### Backend won't start
- Check database connection: `docker-compose logs db`
- Verify Redis is healthy: `docker-compose logs redis`
- Check backend logs: `docker-compose logs backend`
- Ensure `.env` file exists and has correct DATABASE_URL

### STIG scanner not found
- Verify mount path: `docker-compose exec backend ls -la /etc/ansible/roles/Evaluate-STIG`
- Check host path exists: `ls -la /etc/ansible/roles/Evaluate-STIG`
- Update volume mount in `docker-compose.yml` if path differs

### Frontend API calls failing
- Verify Nginx proxy: Check `docker/nginx.conf` for `/api` location block
- Check CORS settings in `backend/app/main.py` allow frontend origin
- Inspect browser network tab for actual request URL and status

### Database migrations not applying
- Database schema auto-creates on startup via lifespan event
- Force recreation: `docker-compose down -v && docker-compose up -d`
- For manual control, add Alembic and create migration files

## Security Considerations for Development

- Default database credentials in `docker-compose.yml` are for development only
- CORS is set to `allow_origins=["*"]` - restrict in production
- SSH credentials for scanning should be handled via secrets management in production
- PDF reports may contain sensitive findings - ensure proper access controls
- Background tasks run in same process as API - consider Celery for production scale
