"""Datasets and training: the groundwork for adding data and training models from the console.

* The four built-in datasets (auth, OSSEC, PF, IPFilter) are what the pipeline already holds.
* An admin can register a new dataset: a folder of monthly archives (``YYYY-MM name.zip``)
  of one of the log types the pipeline can read. A different log type can be registered
  too, but cannot be trained until a developer adds a Phase 1 classifier for it.
* An admin can import a dataset's archives into the pipeline's raw folder and start a
  training run: ``run_pipeline.py --source <type> --from-phase <phase> --with-model-zoo``,
  run without a shell, one run at a time, with its output kept in ``var/training/``.

Every change is admin-only (service/auth.require_admin) and written to the activity log.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import store
from .catalog import SOURCES
from .config import DATA, ROOT, VAR

REGISTRY = VAR / "datasets.json"
RUNS_DIR = VAR / "training"
ARCHIVES = DATA / "phase0_raw" / "archives"
ARCHIVE_NAME = re.compile(r"^\d{4}-(0[1-9]|1[0-2]) .+\.zip$", re.I)
DATASET_ID = re.compile(r"^[a-z][a-z0-9_-]{2,30}$")
PHASES = ("1", "2", "2c", "3", "4a", "4b", "4c", "4d", "4e", "5", "6", "7", "7c", "7b")   # run_pipeline.py order
_lock = threading.Lock()
_active: dict | None = None


def _load() -> list[dict]:
    try:
        return json.loads(REGISTRY.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def _save(entries: list[dict]) -> None:
    VAR.mkdir(parents=True, exist_ok=True)
    tmp = REGISTRY.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    tmp.replace(REGISTRY)


def _archives(folder: Path) -> list[Path]:
    return sorted(p for p in folder.iterdir() if p.is_file() and ARCHIVE_NAME.match(p.name))


def listing() -> dict:
    builtin = []
    for source, meta in SOURCES.items():
        summary = DATA / "phase4_detection" / source / "detectors" / "experiment_summary.json"
        builtin.append({"id": source, "name": meta["label"], "log_type": source, "builtin": True,
                        "trainable": True, "views": len(meta["views"]),
                        "trained_at": time.strftime("%Y-%m-%d %H:%M", time.localtime(summary.stat().st_mtime)) if summary.exists() else None})
    added = [{**entry, "builtin": False, "trainable": entry["log_type"] in SOURCES} for entry in _load()]
    return {"datasets": builtin + added, "log_types": [[k, v["label"]] for k, v in SOURCES.items()],
            "phases": list(PHASES), "runs": runs()}


def add(body: dict, actor: str) -> dict:
    dataset_id = str(body.get("id", "")).strip().lower()
    name = str(body.get("name", "")).strip()[:80]
    log_type = str(body.get("log_type", ""))
    folder = Path(str(body.get("folder", "")).strip().strip('"'))
    if not DATASET_ID.match(dataset_id):
        raise ValueError("The short name must be 3-31 characters: lower-case letters, digits, - or _, starting with a letter.")
    if dataset_id in SOURCES or any(e["id"] == dataset_id for e in _load()):
        raise ValueError(f"A dataset called {dataset_id} already exists.")
    if not name:
        raise ValueError("Give the dataset a name.")
    if log_type not in (*SOURCES, "other"):
        raise ValueError("Choose a log type.")
    if not folder.is_dir():
        raise ValueError(f"No folder at {folder}.")
    archives = _archives(folder)
    entry = {"id": dataset_id, "name": name, "log_type": log_type, "folder": str(folder),
             "archives": len(archives), "notes": str(body.get("notes", ""))[:1000],
             "added_by": actor, "added_at": store.now(), "imported": []}
    with _lock:
        _save(_load() + [entry])
    store.log_action(actor, "dataset_add", dataset_id, {"log_type": log_type, "folder": str(folder), "archives": len(archives)})
    return entry


def import_archives(dataset_id: str, actor: str) -> dict:
    """Copy the dataset's monthly archives into the pipeline's raw folder (never overwriting a different file)."""
    entries = _load()
    entry = next((e for e in entries if e["id"] == dataset_id), None)
    if entry is None:
        raise KeyError("No such dataset.")
    if entry["log_type"] not in SOURCES:
        raise ValueError("This log type has no classifier yet, so the pipeline cannot read it.")
    ARCHIVES.mkdir(parents=True, exist_ok=True)
    copied, skipped, conflicts = [], [], []
    for archive in _archives(Path(entry["folder"])):
        target = ARCHIVES / archive.name
        if target.exists():
            (skipped if target.stat().st_size == archive.stat().st_size else conflicts).append(archive.name)
            continue
        shutil.copy2(archive, target)
        copied.append(archive.name)
    with _lock:
        for e in entries:
            if e["id"] == dataset_id:
                e["imported"] = sorted(set(e.get("imported", [])) | set(copied) | set(skipped))
        _save(entries)
    store.log_action(actor, "dataset_import", dataset_id, {"copied": copied, "already_there": skipped, "conflicts": conflicts})
    return {"copied": copied, "already_there": skipped, "conflicts": conflicts}


# --- training runs ------------------------------------------------------------------------

def _runs_file() -> Path:
    return RUNS_DIR / "runs.json"


def runs() -> list[dict]:
    try:
        history = json.loads(_runs_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        history = []
    out = []
    for run in history[-10:][::-1]:
        log = RUNS_DIR / f"{run['id']}.log"
        tail = log.read_text(encoding="utf-8", errors="replace").splitlines()[-25:] if log.exists() else []
        out.append({**run, "tail": tail})
    return out


def _record(run: dict) -> None:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        history = json.loads(_runs_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        history = []
    history = [r for r in history if r["id"] != run["id"]] + [run]
    _runs_file().write_text(json.dumps(history[-50:], indent=2), encoding="utf-8")


def train(dataset_id: str, from_phase: str, actor: str) -> dict:
    """Start one pipeline run for the dataset's log type. Arguments are allow-listed; no shell."""
    global _active
    log_type = dataset_id if dataset_id in SOURCES else next((e["log_type"] for e in _load() if e["id"] == dataset_id), None)
    if log_type is None:
        raise KeyError("No such dataset.")
    if log_type not in SOURCES:
        raise ValueError("This log type has no classifier yet, so the pipeline cannot train on it.")
    if from_phase not in PHASES:
        raise ValueError("Unknown starting phase.")
    with _lock:
        if _active and _active["process"].poll() is None:
            raise ValueError("A training run is already going. Wait for it to finish, or stop it.")
        run_id = time.strftime("%Y%m%d-%H%M%S") + f"-{log_type}"
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        command = [sys.executable, str(ROOT / "run_pipeline.py"), "--source", log_type, "--from-phase", from_phase, "--with-model-zoo"]
        log = (RUNS_DIR / f"{run_id}.log").open("w", encoding="utf-8")
        process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, shell=False,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        run = {"id": run_id, "dataset": dataset_id, "log_type": log_type, "from_phase": from_phase,
               "started_by": actor, "started_at": store.now(), "status": "running", "exit_code": None}
        _active = {"process": process, "run": run, "log": log}
        _record(run)
    store.log_action(actor, "training_start", dataset_id, {"run": run_id, "from_phase": from_phase})

    def watch():
        code = process.wait()
        log.close()
        run.update(status="finished" if code == 0 else "stopped" if run.get("status") == "stopping" else "failed",
                   exit_code=code, finished_at=store.now())
        _record(run)

    threading.Thread(target=watch, daemon=True, name=f"training-{run_id}").start()
    return run


def stop(actor: str) -> dict:
    with _lock:
        if not _active or _active["process"].poll() is not None:
            raise ValueError("No training run is going.")
        _active["run"]["status"] = "stopping"
        _active["process"].terminate()
        run = dict(_active["run"])
    store.log_action(actor, "training_stop", run["dataset"], {"run": run["id"]})
    return run
