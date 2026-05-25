import sys
from pathlib import Path

# Add repo root to Python path so tests can import secure_transfer_utils directly.
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
