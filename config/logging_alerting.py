import logging
import os
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'nids.log')

# Severity levels
SEVERITY_LOW = 'LOW'
SEVERITY_MEDIUM = 'MEDIUM'
SEVERITY_HIGH = 'HIGH'
SEVERITY_CRITICAL = 'CRITICAL'

_logger = None


def setup_logging(log_file=None, level=logging.INFO):
    """Configure logging to both file and console with structured output."""
    global _logger

    if log_file is None:
        log_file = LOG_FILE

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    _logger = logging.getLogger('NIDS')
    _logger.setLevel(level)

    if _logger.handlers:
        _logger.handlers.clear()

    # File handler — full structured logs
    fh = logging.FileHandler(log_file)
    fh.setLevel(level)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))

    # Console handler — human-readable, coloured severity
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-8s | %(message)s',
                                      datefmt='%H:%M:%S'))

    _logger.addHandler(fh)
    _logger.addHandler(ch)

    _logger.info(f"Logging initialised → {log_file}")
    return _logger


def _get_logger():
    global _logger
    if _logger is None:
        _logger = setup_logging()
    return _logger


def log_intrusion(message, severity=SEVERITY_MEDIUM, extra=None):
    """Log an intrusion event with severity and optional metadata."""
    logger = _get_logger()
    full_msg = f"[{severity}] INTRUSION | {message}"
    if extra:
        full_msg += f" | details={extra}"

    if severity == SEVERITY_CRITICAL:
        logger.critical(full_msg)
    elif severity == SEVERITY_HIGH:
        logger.error(full_msg)
    elif severity == SEVERITY_MEDIUM:
        logger.warning(full_msg)
    else:
        logger.info(full_msg)


def alert_intrusion(message, severity=SEVERITY_MEDIUM):
    """Print a colour-coded alert to the console."""
    colours = {
        SEVERITY_LOW:      '\033[94m',   # blue
        SEVERITY_MEDIUM:   '\033[93m',   # yellow
        SEVERITY_HIGH:     '\033[91m',   # red
        SEVERITY_CRITICAL: '\033[95m',   # magenta
    }
    reset = '\033[0m'
    colour = colours.get(severity, '')
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"{colour}[{timestamp}] ⚠  ALERT [{severity}]: {message}{reset}")


def log_event(message, level=logging.INFO):
    """General purpose event logger."""
    _get_logger().log(level, message)
