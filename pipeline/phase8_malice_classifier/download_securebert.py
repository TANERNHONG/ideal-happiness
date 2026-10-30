"""Download SecureBERT (ehsanaghaei/SecureBERT) weights and tokenizer files.

  python pipeline/phase8_malice_classifier/download_securebert.py                       # to ~/hf_models/SecureBERT
  python pipeline/phase8_malice_classifier/download_securebert.py --dest D:/models/SecureBERT

Only the files needed to run the model are fetched (about 500 MB); the
training leftovers in the repository (optimizer.pt, 1 GB) are skipped. The
revision is pinned and every file is checked against the hash Hugging Face
publishes, so a changed or corrupted file is refused. Standard library only.
Keep the destination outside OneDrive so the weights are not synced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)

REPO = "ehsanaghaei/SecureBERT"
REVISION = "3a47918dd874e5c769efd152b51c5756a953fb67"      # main on 2026-09-29
FILES = ["config.json", "vocab.json", "merges.txt", "tokenizer.json", "tokenizer_config.json",
         "special_tokens_map.json", "README.md", "pytorch_model.bin"]
DEFAULT_DEST = Path(os.environ.get("SECUREBERT_DIR", Path.home() / "hf_models" / "SecureBERT"))


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)


def git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(path: Path, meta: dict) -> bool:
    if not path.exists():
        return False
    if meta.get("lfs"):
        return path.stat().st_size == meta["lfs"]["size"] and sha256(path) == meta["lfs"]["sha256"]
    return git_blob_sha1(path) == meta["blobId"]


def download(url: str, target: Path, size: int | None) -> None:
    part = target.with_name(target.name + ".part")
    with urllib.request.urlopen(url, timeout=120) as response, part.open("wb") as handle:
        done = 0
        progress = runlog.Progress(f"{target.name}: MB downloaded", round(size / 1e6)) if size and size > 20 << 20 else None
        while block := response.read(1 << 20):
            handle.write(block)
            done += len(block)
            if progress:
                progress.report(round(done / 1e6))
    part.replace(target)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST)
    runlog.add_arguments(parser)
    args = parser.parse_args()

    info = fetch_json(f"https://huggingface.co/api/models/{REPO}/revision/{REVISION}?blobs=true")
    metadata = {item["rfilename"]: item for item in info["siblings"]}
    args.dest.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        target = args.dest / name
        meta = metadata[name]
        if verify(target, meta):
            runlog.log(f"{name}: already present and verified")
            continue
        size = meta.get("lfs", {}).get("size") or meta.get("size")
        download(f"https://huggingface.co/{REPO}/resolve/{REVISION}/{name}", target, size)
        if not verify(target, meta):
            target.unlink(missing_ok=True)
            runlog.emit(f"{name}: hash mismatch after download; file removed", "ERROR")
            return 1
        runlog.log(f"{name}: downloaded and verified")
    (args.dest / "REVISION").write_text(f"{REPO}@{REVISION}\n", encoding="utf-8")
    runlog.log(f"SecureBERT ready in {args.dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
