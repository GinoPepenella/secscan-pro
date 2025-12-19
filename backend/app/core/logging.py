from loguru import logger
import sys
from pathlib import Path


def setup_logging(log_level: str = "INFO"):
    """Configure logging for the application."""

    # Remove default handler
    logger.remove()

    # Console handler with colors
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=log_level,
        colorize=True
    )

    # File handler
    log_path = Path("/var/log/secscan-pro")
    log_path.mkdir(parents=True, exist_ok=True)

    logger.add(
        log_path / "secscan-pro.log",
        rotation="500 MB",
        retention="30 days",
        compression="zip",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level=log_level
    )

    return logger
