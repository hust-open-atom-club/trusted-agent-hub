import subprocess


def start_preview():
    return subprocess.Popen(
        ["python", "-m", "http.server", "4317", "--bind", "127.0.0.1"],
        shell=False,
    )
