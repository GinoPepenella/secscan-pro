# SecScan Pro - Quick Start Guide

## Installation (5 minutes)

### Step 1: Run the installer
```bash
cd /home/gino.pepenella.adm/Projects/secscan-pro
sudo ./install.sh
```

The installer automatically handles:
- Docker and Docker Compose installation
- Directory creation
- Environment configuration
- Service setup
- Container deployment

### Step 2: Access the application
- **Web UI**: http://localhost:3000
- **API Docs**: http://localhost:8000/api/docs

## First Scan (2 minutes)

### 1. Create a New Scan
1. Click **"Scans"** in the navigation
2. Click **"New Scan"** button
3. Fill in the form:
   ```
   Scan Name: My First Scan
   Scan Type: Combined (STIG + Vulnerabilities)
   Target Hosts: localhost
                 127.0.0.1
   ```
4. Click **"Create Scan"**

### 2. Monitor Progress
- Watch real-time scan status on the Dashboard
- Scans refresh automatically every 5 seconds

### 3. View Results
1. Click on your completed scan
2. Review findings organized by severity
3. See risk score and metrics
4. Download PDF report

## Common Operations

### SSH-Based Remote Scanning
```
Scan Name: Production Servers
Scan Type: Combined
Targets: 192.168.1.10
         web-server.example.com

✓ Enable SSH
Username: admin
Port: 22
Auth Method: Password (or Public Key)
Sudo Mode: sudo (or sudo su/sudo su -)
```

### Remediation
1. Open scan details
2. Check findings you want to fix
3. Click **"Remediate Selected"**
4. Confirm changes
5. View remediation results

### Generate Reports
1. Open any completed scan
2. Click **"Download Report"**
3. PDF generated with:
   - Executive summary
   - Risk metrics and charts
   - Detailed findings
   - Remediation recommendations

## Service Management

```bash
# Check status
sudo systemctl status secscan-pro

# View logs
cd /home/gino.pepenella.adm/Projects/secscan-pro
docker-compose logs -f

# Restart service
sudo systemctl restart secscan-pro

# Stop service
sudo systemctl stop secscan-pro

# Start service
sudo systemctl start secscan-pro
```

## Keyboard Shortcuts & Tips

### UI Navigation
- **Dark/Light Mode**: Click moon/sun icon in header
- **Dashboard**: Real-time overview of all scans
- **Scans Page**: Manage and track all security scans

### Scan Types Explained
- **STIG**: Security Technical Implementation Guide compliance checks
- **Vulnerability**: CVE-based vulnerability assessment
- **Combined**: Both STIG and vulnerability scanning (recommended)

### Finding Severity
- 🔴 **Critical**: Immediate action required (CVSS 9.0-10.0)
- 🟠 **High**: Address within days (CVSS 7.0-8.9)
- 🟡 **Medium**: Address within weeks (CVSS 4.0-6.9)
- 🔵 **Low**: Address when possible (CVSS 0.1-3.9)

## Troubleshooting

### Application won't start
```bash
# Check Docker status
sudo systemctl status docker

# Check container logs
docker-compose logs

# Restart everything
sudo systemctl restart secscan-pro
```

### Can't access web interface
```bash
# Verify containers are running
docker-compose ps

# Check port availability
sudo netstat -tulpn | grep -E '3000|8000'

# Check firewall
sudo firewall-cmd --list-ports  # RHEL/CentOS
sudo ufw status                 # Ubuntu
```

### STIG scanner not found
```bash
# Verify STIG installation
ls -la /etc/ansible/roles/Evaluate-STIG

# If different location, update docker-compose.yml:
# volumes:
#   - /your/stig/path:/etc/ansible/roles/Evaluate-STIG:ro
```

## Best Practices

### 1. Regular Scanning
- Schedule weekly scans for critical systems
- Run combined scans for comprehensive coverage
- Review findings promptly

### 2. Remediation Strategy
- Address Critical and High findings first
- Use auto-remediation for safe fixes
- Test remediations in non-production first
- Document manual fixes

### 3. Reporting
- Generate reports after each scan
- Track risk score trends over time
- Share reports with stakeholders
- Archive reports for compliance

### 4. Security
- Change default database credentials
- Use SSH keys instead of passwords
- Restrict network access to management ports
- Keep system and containers updated

## Next Steps

1. **Explore Features**
   - Try different scan types
   - Test remediation on non-critical findings
   - Customize scan configurations

2. **Configure for Production**
   - Set up HTTPS with reverse proxy
   - Configure NVD API key for better CVE data
   - Set up automated scanning schedules
   - Integrate with your workflow

3. **Advanced Usage**
   - Scan multiple targets simultaneously
   - Use STIG profile selection
   - Bulk remediation workflows
   - API integration

## Support & Documentation

- **Full Documentation**: See README.md
- **API Reference**: http://localhost:8000/api/docs
- **Logs**: `/var/log/secscan-pro/`
- **Reports**: `/opt/secscan-reports/`

## Example Workflow

**Weekly Security Scan Routine:**

1. **Monday Morning**: Create new scan for all production servers
2. **Monday Afternoon**: Review findings, prioritize by severity
3. **Tuesday**: Remediate Critical findings
4. **Wednesday**: Remediate High findings
5. **Thursday**: Address Medium findings
6. **Friday**: Generate weekly report, document progress

---

**You're all set!** Start scanning and securing your infrastructure with SecScan Pro.
