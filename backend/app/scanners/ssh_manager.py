import paramiko
import asyncssh
from typing import Optional, Dict, Any, List
from pathlib import Path
from loguru import logger
from app.core.config import settings
from app.models.scan import AuthMethod, SudoMode
import asyncio


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
        port: int = 22,
        timeout: int = 30,
        auth_method: AuthMethod = AuthMethod.PASSWORD,
        sudo_mode: SudoMode = SudoMode.SUDO
    ):
        self.host = host
        self.username = username
        self.password = password
        self.private_key_path = private_key_path
        self.port = port
        self.timeout = timeout
        self.auth_method = auth_method
        self.sudo_mode = sudo_mode
        self.connection: Optional[asyncssh.SSHClientConnection] = None

    async def connect(self) -> bool:
        """Establish SSH connection."""
        try:
            logger.info(f"Connecting to {self.host}:{self.port} as {self.username}")

            if self.auth_method == AuthMethod.PUBLIC_KEY:
                if not self.private_key_path:
                    raise SSHConnectionError("Private key path required for public key authentication")

                self.connection = await asyncssh.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    client_keys=[self.private_key_path],
                    known_hosts=None,  # Disable host key checking for now
                    connect_timeout=self.timeout
                )
            else:
                self.connection = await asyncssh.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    known_hosts=None,
                    connect_timeout=self.timeout
                )

            logger.info(f"Successfully connected to {self.host}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to {self.host}: {str(e)}")
            raise SSHConnectionError(f"Connection failed: {str(e)}")

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
