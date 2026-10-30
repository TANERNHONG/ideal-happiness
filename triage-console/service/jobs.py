"""Background jobs with step progress, so long analyses do not block a request."""
from __future__ import annotations

import threading
import time
import traceback
import uuid

_jobs: dict[str, dict] = {}
_lock = threading.Lock()
KEEP_SECONDS = 3600


def start(function, *args, **kwargs) -> str:
    job_id = uuid.uuid4().hex[:12]
    job = {"id": job_id, "status": "running", "steps": [], "result": None, "error": "", "started": time.time()}
    with _lock:
        for old in [k for k, v in _jobs.items() if time.time() - v["started"] > KEEP_SECONDS]:
            _jobs.pop(old, None)
        _jobs[job_id] = job

    def progress(step: str, detail: str) -> None:
        with _lock:
            job["steps"].append({"step": step, "detail": detail, "at": round(time.time() - job["started"], 1)})

    def run() -> None:
        try:
            result = function(*args, progress=progress, **kwargs)
            with _lock:
                job.update(status="done", result=result)
        except ValueError as error:
            with _lock:
                job.update(status="failed", error=str(error))
        except Exception as error:                          # report, keep the service up
            traceback.print_exc()
            with _lock:
                job.update(status="failed", error=f"{type(error).__name__}: {error}")

    threading.Thread(target=run, daemon=True).start()
    return job_id


def get(job_id: str) -> dict:
    with _lock:
        job = _jobs.get(job_id)
        if job is None:
            raise KeyError("No such job (it may have expired).")
        return {**job, "steps": list(job["steps"]), "seconds": round(time.time() - job["started"], 1)}
