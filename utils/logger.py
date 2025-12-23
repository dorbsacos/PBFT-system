"""
Logging utilities for Linear-PBFT project
"""

import logging
from typing import Optional


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def create_logger(name: str, level: int = logging.INFO, propagate: bool = False) -> logging.Logger:
    """
    Create or retrieve a logger with a standard formatter.

    Args:
        name: Logger name (e.g., node/client identifier)
        level: Logging level, defaults to INFO
        propagate: Whether to propagate to root logger

    Returns:
        Configured logging.Logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = propagate

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger
