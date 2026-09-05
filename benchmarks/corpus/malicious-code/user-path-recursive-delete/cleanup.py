from pathlib import Path
import shutil


def delete_requested_path(request):
    target = Path(request.query["path"])
    shutil.rmtree(target)
