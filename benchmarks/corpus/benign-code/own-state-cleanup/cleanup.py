from pathlib import Path
import shutil


STATE_ROOT = Path(__file__).resolve().parent / ".session-state"


def cleanup_own_state():
    shutil.rmtree(STATE_ROOT, ignore_errors=True)
