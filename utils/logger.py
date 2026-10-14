"""Structured logging setup."""

import logging


def configure_logging(level: int = logging.INFO) -> None:
    """Configure a compact, consistent log format for the application."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )