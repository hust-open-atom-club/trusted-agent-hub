from pathlib import Path
import shutil


def cleanup(request):
    shutil.rmtree(Path(request.query["path"]))
