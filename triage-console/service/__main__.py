import sys

if sys.stdout is None or sys.stderr is None:       # pythonw (autostart.ps1): no console, so the service writes to a log
    from .config import VAR
    VAR.mkdir(parents=True, exist_ok=True)
    sys.stdout = sys.stderr = open(VAR / "service.log", "a", encoding="utf-8", buffering=1)

from .server import main  # noqa: E402

main()
