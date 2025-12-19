# SecScan Pro

A comprehensive security compliance and vulnerability scanning platform for Linux systems. SecScan Pro combines STIG compliance checking with CVE vulnerability assessment, providing automated remediation capabilities and detailed PDF reporting.

## Features

### Core Capabilities
- **STIG Compliance Scanning**: Leverages existing Evaluate-STIG framework for comprehensive compliance checks
- **CVE Vulnerability Assessment**: Integrates with NVD database for up-to-date vulnerability detection
- **Multi-Target Scanning**: Scan multiple systems via IP/FQDN lists or SSH
- **Automated Remediation**: One-click remediation for auto-fixable findings with granular control
- **PDF Reporting**: Professional reports with risk metrics, charts, and CVSS scoring

### SSH & Authentication
- Multiple authentication methods: Password and Public Key
- Flexible sudo modes: `sudo`, `sudo su`, `sudo su -`
- Secure connection management
- Config file scanning support

### Modern UI
- Clean, intuitive interface built with React and TypeScript
- Dark and Light mode support
- Real-time scan status updates
- Interactive dashboards with charts and visualizations
- Low learning curve design

### Risk Management
- CVSS-based risk scoring
- Severity-based finding categorization (Critical, High, Medium, Low)
- Trend analysis and metrics
- Compliance tracking

## Architecture

```
┌─────────────────┐
│   Frontend      │ React + TypeScript + Tailwind CSS
│   (Port 3000)   │
└────────┬────────┘
         │
    ┌────▼────┐
    │  Nginx  │
    └────┬────┘
         │
┌────────▼────────┐
│   Backend API   │ FastAPI + Python 3.11
│   (Port 8000)   │
└────────┬────────┘
         │
    ┌────▼─────┬──────────┐
    │          │          │
┌───▼───┐  ┌──▼──┐  ┌───▼────┐
│ PostgreSQL│ Redis│ STIG     │
│ Database  │ Cache│ Scanner  │
└──────────┘ └─────┘ └────────┘
```

## Prerequisites

- Linux distribution (RHEL, Ubuntu, Amazon Linux, etc.)
- Docker and Docker Compose
- Root/sudo access
- Existing Evaluate-STIG installation at `/etc/ansible/roles/Evaluate-STIG`

## Installation

### Quick Install

```bash
cd /opt
git clone <repository-url> secscan-pro
cd secscan-pro
sudo ./install.sh
```

The installation script will:
1. Check and install Docker/Docker Compose if needed
2. Create necessary directories and configuration files
3. Set up systemd service for automatic startup
4. Build and start all containers
5. Configure the system for first use

### Manual Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url> secscan-pro
   cd secscan-pro
   ```

2. **Create environment file**
   ```bash
   cp backend/.env.example backend/.env
   # Edit backend/.env with your configuration
   ```

3. **Build and start services**
   ```bash
   docker-compose build
   docker-compose up -d
   ```

4. **Verify installation**
   ```bash
   docker-compose ps
   curl http://localhost:8000/health
   ```

## Usage

### Access the Application

- **Web Interface**: http://localhost:3000
- **API Documentation**: http://localhost:8000/api/docs

### Creating a Scan

1. Navigate to the **Scans** page
2. Click **New Scan**
3. Configure scan parameters:
   - **Scan Name**: Descriptive name for your scan
   - **Scan Type**: STIG, Vulnerability, or Combined
   - **Targets**: Enter IP addresses or FQDNs (one per line)
   - **SSH Configuration** (if remote scanning):
     - Enable SSH
     - Configure username, port, and authentication method
     - Select appropriate sudo mode
4. Click **Create Scan**

### Viewing Results

1. Navigate to **Dashboard** for overview
2. Click on a scan to view detailed findings
3. Filter findings by severity or type
4. Select findings for remediation
5. Generate and download PDF reports

### Remediation

**Individual Findings:**
1. Open scan details
2. Select checkboxes for findings to remediate
3. Click **Remediate Selected**
4. Review changes before confirming

**Bulk Remediation:**
- Use the bulk remediation feature to fix all auto-remediable findings at once
- Option to filter by severity level
- Dry-run mode available for testing

### Generating Reports

1. Open scan details
2. Click **Download Report**
3. PDF report will be generated with:
   - Executive summary
   - Risk assessment and scoring
   - Finding distribution charts
   - Detailed findings by severity
   - Remediation recommendations

## Configuration

### Environment Variables

Edit `backend/.env`:

```bash
# Database
DATABASE_URL=postgresql+asyncpg://secscan:secscan@db:5432/secscan

# NVD API (optional, for higher rate limits)
NVD_API_KEY=your_api_key_here

# STIG Scanner
STIG_SCANNER_PATH=/etc/ansible/roles/Evaluate-STIG

# Scan Settings
MAX_CONCURRENT_SCANS=5
DEFAULT_SSH_TIMEOUT=30
DEFAULT_SCAN_TIMEOUT=3600
```

### Docker Compose

Modify `docker-compose.yml` to adjust:
- Port mappings
- Volume mounts
- Resource limits
- Network configuration

## Managing the Service

### Systemd Commands

```bash
# Start the service
sudo systemctl start secscan-pro

# Stop the service
sudo systemctl stop secscan-pro

# Restart the service
sudo systemctl restart secscan-pro

# Check status
sudo systemctl status secscan-pro

# Enable startup on boot
sudo systemctl enable secscan-pro
```

### Docker Commands

```bash
# View logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f backend

# Restart specific service
docker-compose restart backend

# Rebuild after code changes
docker-compose up -d --build

# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

## Troubleshooting

### Backend Won't Start

```bash
# Check logs
docker-compose logs backend

# Check database connection
docker-compose exec backend python -c "from app.db.base import sync_engine; sync_engine.connect()"

# Recreate database
docker-compose down -v
docker-compose up -d
```

### STIG Scanner Not Found

Ensure Evaluate-STIG is installed at `/etc/ansible/roles/Evaluate-STIG`:

```bash
ls -la /etc/ansible/roles/Evaluate-STIG
```

Mount the correct path in `docker-compose.yml` if different.

### Permission Issues

```bash
# Fix log directory permissions
sudo chown -R $(whoami):$(whoami) /var/log/secscan-pro

# Fix report directory permissions
sudo chown -R $(whoami):$(whoami) /opt/secscan-reports
```

### Network Issues

```bash
# Check if ports are available
netstat -tulpn | grep -E '3000|8000|5432'

# Modify ports in docker-compose.yml if conflicts exist
```

## Security Considerations

1. **Change Default Credentials**: Update database credentials in production
2. **Use HTTPS**: Configure reverse proxy with SSL/TLS certificates
3. **Secure API Access**: Implement authentication for API endpoints
4. **Network Security**: Restrict access to management ports
5. **SSH Keys**: Use SSH key authentication instead of passwords when possible
6. **Regular Updates**: Keep Docker images and dependencies updated

## Development

### Project Structure

```
secscan-pro/
├── backend/
│   ├── app/
│   │   ├── api/          # API endpoints
│   │   ├── core/         # Core configuration
│   │   ├── db/           # Database setup
│   │   ├── models/       # SQLAlchemy models
│   │   ├── scanners/     # Scanning engines
│   │   ├── remediation/  # Remediation engine
│   │   └── reporting/    # PDF generation
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── pages/        # Page components
│   │   ├── services/     # API services
│   │   └── lib/          # Utilities
│   └── package.json
├── docker/               # Docker configurations
└── install.sh           # Installation script
```

### Running in Development Mode

**Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

## API Reference

Full API documentation available at: http://localhost:8000/api/docs

### Key Endpoints

- `POST /api/v1/scans` - Create new scan
- `GET /api/v1/scans` - List all scans
- `GET /api/v1/scans/{id}` - Get scan details
- `GET /api/v1/scans/{id}/findings` - Get scan findings
- `POST /api/v1/remediation` - Remediate findings
- `POST /api/v1/reports/{id}/generate` - Generate PDF report

## Support

For issues, questions, or contributions:
- Open an issue in the repository
- Review existing documentation
- Check troubleshooting section

## License

[Add your license here]

## Acknowledgments

- Built on top of Evaluate-STIG framework
- Uses NVD database for CVE information
- Powered by FastAPI, React, and PostgreSQL
