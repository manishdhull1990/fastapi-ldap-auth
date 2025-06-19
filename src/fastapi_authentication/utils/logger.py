import logging
import multiprocessing
from logging.handlers import QueueHandler, QueueListener
from logging import FileHandler, Formatter 
from pathlib import Path
from datetime import datetime
import atexit
from ..middlewares.correlation import get_correlation_id

class CorrelationFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Inject correlation_id from ContextVar in this thread
        record.correlation_id = get_correlation_id() or "-"
        return True

# Determine log directory relative to this file
base_dir = Path(__file__).resolve().parent
log_dir = base_dir / ".." / "logs"
log_dir.mkdir(parents=True, exist_ok=True)

log_file = log_dir/f"auth_{datetime.now().strftime('%Y-%m-%d')}.log"

# Create a logging queue
log_queue = multiprocessing.Queue()

# Handler that writes logs to file
file_handler = FileHandler(log_file)
file_handler.setFormatter(Formatter(
        "%(asctime)s | %(levelname)s | %(correlation_id)s | %(message)s |",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

# Start a listener in the main process (write logs to file)
listener = QueueListener(log_queue, file_handler)
listener.start()

# Get a logger and attach a QueueHandler
logger = logging.getLogger("auth_logger")
logger.setLevel(logging.INFO)

# Attach CorrelationFilter so record.correlation_id is set before enqueue
logger.addFilter(CorrelationFilter())

# Prevent duplicate handlers
if not any(isinstance(h, QueueHandler) for h in logger.handlers):
    logger.addHandler(QueueHandler(log_queue))

# Optional: stop listener when exiting (if you run in scripts)
atexit.register(listener.stop)

# Optional debug print
print(f"[Logger] Initialized, writing to {log_file.resolve()}")