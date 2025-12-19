import paramiko
import asyncssh
from typing import Optional, Dict, Any, List
from pathlib import Path
from loguru import logger
from app.core.config import settings
from app.models.scan import AuthMethod, SudoMode
import asyncio
import tempfile
import os
from glob import glob


class SSHConnectionError(Exception):
    """Raised when SSH connection fails."""
    pass


class SSHCommandError(Exception):
    """Raised when SSH command execution fails."""
    pass


class SSHManager:
    """Manages SSH connections for remote scanning."""

    def __init__(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        private_key_path: Optional[str] = None,
        private_key_content: Optional[str] = None,
        key_passphrase: Optional[str] = None,
        port: int = 22,
        timeout: int = 30,
        auth_method: AuthMethod = AuthMethod.PASSWORD,
        sudo_mode: SudoMode = SudoMode.SUDO
    ):
        self.host = host
        self.username = username
        self.password = password
        self.private_key_path = private_key_path
        self.private_key_content = private_key_content
        self.key_passphrase = key_passphrase
        self.port = port
        self.timeout = timeout
        self.auth_method = auth_method
        self.sudo_mode = sudo_mode
        self.connection: Optional[asyncssh.SSHClientConnection] = None
        self._temp_key_file: Optional[str] = None

    async def connect(self) -> bool:
        """Establish SSH connection."""
        try:
            logger.info(f"Connecting to {self.host}:{self.port} as {self.username} using {self.auth_method}")

            # Build connection parameters
            conn_params = {
                "host": self.host,
                "port": self.port,
                "username": self.username,
                "known_hosts": None,  # Disable host key checking
                "connect_timeout": self.timeout
            }

            # Handle different authentication methods
            if self.auth_method == AuthMethod.PASSWORD:
                if not self.password:
                    raise SSHConnectionError("Password required for password authentication")
                conn_params["password"] = self.password

            elif self.auth_method == AuthMethod.PUBLIC_KEY:
                if not self.private_key_path:
                    raise SSHConnectionError("Private key path required for public key authentication")
                conn_params["client_keys"] = [self.private_key_path]
                if self.key_passphrase:
                    conn_params["passphrase"] = self.key_passphrase

            elif self.auth_method == AuthMethod.PRIVATE_KEY_CONTENT:
                if not self.private_key_content:
                    raise SSHConnectionError("Private key content required for this authentication method")

                # Write key content to temporary file
                self._temp_key_file = self._create_temp_key_file(self.private_key_content)
                conn_params["client_keys"] = [self._temp_key_file]
                if self.key_passphrase:
                    conn_params["passphrase"] = self.key_passphrase

            elif self.auth_method == AuthMethod.LOCAL_SSH_KEYS:
                # Use keys from ~/.ssh/ or specific path
                if self.private_key_path:
                    # Use specific key from selection
                    conn_params["client_keys"] = [self.private_key_path]
                else:
                    # Try all common keys in ~/.ssh/
                    keys = self._discover_local_ssh_keys()
                    if not keys:
                        raise SSHConnectionError("No SSH keys found in ~/.ssh/")
                    conn_params["client_keys"] = keys

                if self.key_passphrase:
                    conn_params["passphrase"] = self.key_passphrase

            self.connection = await asyncssh.connect(**conn_params)
            logger.info(f"Successfully connected to {self.host}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to {self.host}: {str(e)}")
            # Clean up temp file if it was created
            self._cleanup_temp_key_file()
            raise SSHConnectionError(f"Connection failed: {str(e)}")

    def _create_temp_key_file(self, key_content: str) -> str:
        """Create a temporary file with the private key content."""
        fd, path = tempfile.mkstemp(prefix="ssh_key_", suffix=".pem")
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(key_content)
            # Set restrictive permissions (required for SSH keys)
            os.chmod(path, 0o600)
            logger.debug(f"Created temporary key file: {path}")
            return path
        except Exception as e:
            os.close(fd)
            os.unlink(path)
            raise SSHConnectionError(f"Failed to create temporary key file: {str(e)}")

    def _discover_local_ssh_keys(self) -> List[str]:
        """Discover SSH keys in ~/.ssh/ directory."""
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            return []

        # Common private key names
        key_patterns = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_home"]
        keys = []

        for pattern in key_patterns:
            key_path = ssh_dir / pattern
            if key_path.exists() and key_path.is_file():
                keys.append(str(key_path))
                logger.debug(f"Found SSH key: {key_path}")

        return keys

    def _cleanup_temp_key_file(self):
        """Remove temporary key file if it was created."""
        if self._temp_key_file and os.path.exists(self._temp_key_file):
            try:
                os.unlink(self._temp_key_file)
                logger.debug(f"Cleaned up temporary key file: {self._temp_key_file}")
                self._temp_key_file = None
            except Exception as e:
                logger.warning(f"Failed to clean up temporary key file: {str(e)}")

    async def execute_command(
        self,
        command: str,
        use_sudo: bool = False,
        sudo_password: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute command via SSH."""
        if not self.connection:
            raise SSHConnectionError("Not connected. Call connect() first.")

        try:
            # Prepare command with sudo if needed
            if use_sudo:
                if self.sudo_mode == SudoMode.SUDO:
                    full_command = f"sudo {command}"
                elif self.sudo_mode == SudoMode.SUDO_SU:
                    full_command = f"sudo su -c '{command}'"
                elif self.sudo_mode == SudoMode.SUDO_SU_DASH:
                    full_command = f"sudo su - -c '{command}'"
                else:
                    full_command = f"sudo {command}"

                # If sudo requires password
                if sudo_password:
                    full_command = f"echo '{sudo_password}' | sudo -S {command}"
            else:
                full_command = command

            logger.debug(f"Executing: {full_command[:100]}...")

            result = await self.connection.run(full_command, check=False)

            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_status,
                "success": result.exit_status == 0
            }

        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            raise SSHCommandError(f"Command execution failed: {str(e)}")

    async def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload file to remote host."""
        if not self.connection:
            raise SSHConnectionError("Not connected. Call connect() first.")

        try:
            async with self.connection.start_sftp_client() as sftp:
                await sftp.put(local_path, remote_path)
            logger.info(f"Uploaded {local_path} to {self.host}:{remote_path}")
            return True
        except Exception as e:
            logger.error(f"File upload failed: {str(e)}")
            return False

    async def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download file from remote host."""
        if not self.connection:
            raise SSHConnectionError("Not connected. Call connect() first.")

        try:
            async with self.connection.start_sftp_client() as sftp:
                await sftp.get(remote_path, local_path)
            logger.info(f"Downloaded {self.host}:{remote_path} to {local_path}")
            return True
        except Exception as e:
            logger.error(f"File download failed: {str(e)}")
            return False

    async def disconnect(self):
        """Close SSH connection."""
        if self.connection:
            self.connection.close()
            await self.connection.wait_closed()
            logger.info(f"Disconnected from {self.host}")

        # Clean up temporary key file if created
        self._cleanup_temp_key_file()

    async def test_connection(self) -> Dict[str, Any]:
        """Test SSH connection and gather basic system info."""
        await self.connect()

        try:
            # Get basic system info
            hostname_result = await self.execute_command("hostname")
            os_result = await self.execute_command("cat /etc/os-release")
            kernel_result = await self.execute_command("uname -r")

            return {
                "connected": True,
                "hostname": hostname_result["stdout"].strip(),
                "os_info": os_result["stdout"],
                "kernel": kernel_result["stdout"].strip(),
                "error": None
            }

        except Exception as e:
            return {
                "connected": False,
                "hostname": None,
                "os_info": None,
                "kernel": None,
                "error": str(e)
            }
        finally:
            await self.disconnect()

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
