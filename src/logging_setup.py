"""Application logging configuration.

Scan *reports* are written by :mod:`src.reporting`; this module only
configures diagnostic logging (what the scanner is doing, warnings, errors).
Both are persisted under the ``logs/`` directory by default.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

__all__ = ["setup_logging", "get_logger", "LOG_FORMAT"]

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)-28s %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

_CONFIGURED = False


def setup_logging(
    log_dir: Path | str = Path("logs"),
    *,
    verbose: bool = False,
    console: bool = True,
) -> logging.Logger:
    """Configure the ``net_spectre`` logger.

    A rotating debug log (``logs/net_spectre.log``) is always written.  The
    console handler is intentionally quiet unless ``verbose`` is set, because
    the CLI renders its own progress output.

    The function is idempotent, which makes it safe to call from the
    interactive menu more than once.
    """
    global _CONFIGURED
    logger = logging.getLogger("net_spectre")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    if _CONFIGURED:
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(
                handler, RotatingFileHandler
            ):
                handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
        return logger

    directory = Path(log_dir).expanduser()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        directory = Path.cwd()
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            directory = Path(".")

    formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

    try:
        file_handler = RotatingFileHandler(
            directory / "net_spectre.log",
            maxBytes=2 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError:
        # Reports are still written even if the diagnostic log cannot be.
        pass

    if console:
        stream_handler = logging.StreamHandler(stream=sys.stderr)
        stream_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    # Third party libraries can be extremely chatty at DEBUG level.
    for noisy in ("urllib3", "asyncio", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger of the application logger.

    The importable package is ``src`` (see the project layout), while the
    diagnostic namespace and log file keep the stable ``net_spectre`` name so
    existing log pipelines continue to work.
    """
    if name.startswith("net_spectre"):
        return logging.getLogger(name)
    if name == "src":
        return logging.getLogger("net_spectre")
    if name.startswith("src."):
        name = name[4:]
    return logging.getLogger(f"net_spectre.{name}")
