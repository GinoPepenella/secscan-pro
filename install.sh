#!/bin/bash

# SecScan Pro Installation Script
# This script installs and configures SecScan Pro on Linux systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
        print_info "Detected OS: $OS $VER"
    else
        print_error "Cannot detect OS version"
        exit 1
    fi
}

check_dependencies() {
    print_info "Checking dependencies..."

    # Check for Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        print_info "Installing Docker..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        rm get-docker.sh
        systemctl enable docker
        systemctl start docker
        print_success "Docker installed"
    else
        print_success "Docker is already installed"
    fi

    # Check for Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed"
        print_info "Installing Docker Compose..."
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        print_success "Docker Compose installed"
    else
        print_success "Docker Compose is already installed"
    fi
}

create_env_file() {
    print_info "Creating environment file..."

    if [ ! -f backend/.env ]; then
        cp backend/.env.example backend/.env

        # Generate random secret key
        SECRET_KEY=$(openssl rand -hex 32)
        sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" backend/.env

        print_success "Environment file created"
    else
        print_info "Environment file already exists"
    fi
}

create_systemd_service() {
    print_info "Creating systemd service..."

    INSTALL_DIR=$(pwd)

    cat > /etc/systemd/system/secscan-pro.service << EOF
[Unit]
Description=SecScan Pro Security Scanner
After=network.target docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable secscan-pro.service
    print_success "Systemd service created"
}

create_directories() {
    print_info "Creating necessary directories..."

    mkdir -p /var/log/secscan-pro
    mkdir -p /opt/secscan-reports

    print_success "Directories created"
}

build_and_start() {
    print_info "Building and starting SecScan Pro..."

    docker-compose build
    docker-compose up -d

    print_success "SecScan Pro started"
}

wait_for_services() {
    print_info "Waiting for services to be ready..."

    sleep 10

    # Check if services are running
    if docker-compose ps | grep -q "Up"; then
        print_success "Services are running"
    else
        print_error "Services failed to start"
        docker-compose logs
        exit 1
    fi
}

display_info() {
    echo ""
    echo "============================================"
    print_success "SecScan Pro Installation Complete!"
    echo "============================================"
    echo ""
    echo "Web Interface: http://localhost:3000"
    echo "API Documentation: http://localhost:8000/api/docs"
    echo ""
    echo "To manage the service:"
    echo "  Start:   sudo systemctl start secscan-pro"
    echo "  Stop:    sudo systemctl stop secscan-pro"
    echo "  Restart: sudo systemctl restart secscan-pro"
    echo "  Status:  sudo systemctl status secscan-pro"
    echo ""
    echo "To view logs:"
    echo "  docker-compose logs -f"
    echo ""
    echo "============================================"
}

# Main installation flow
main() {
    echo "============================================"
    echo "  SecScan Pro Installation"
    echo "============================================"
    echo ""

    check_root
    detect_os
    check_dependencies
    create_directories
    create_env_file
    create_systemd_service
    build_and_start
    wait_for_services
    display_info
}

# Run main function
main
