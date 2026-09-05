from pathlib import Path
import shutil


shutil.rmtree(Path(__file__).parent / ".cache", ignore_errors=True)
