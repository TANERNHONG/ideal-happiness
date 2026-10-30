"""Phase 4f for the pipeline runner: streams (step 1), routines (2) and the sequence detector (3).

  .venv/Scripts/python.exe pipeline/phase4f_sequences/run_sequences.py --source ossec
  .venv/Scripts/python.exe pipeline/phase4f_sequences/run_sequences.py --source auth --skip-streams

AUTH and OSSEC only. The AUTH streams take about 15 minutes; --skip-streams reuses the current store
when Phase 2 has not changed since (the run refuses if the Phase 2 store is newer than it).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mine  # noqa: E402
import score  # noqa: E402
import streams  # noqa: E402
from common import SOURCES, stream_folder  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))
import runlog  # noqa: E402  (console output: pipeline/STYLE_GUIDE.md)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, choices=sorted(SOURCES))
    parser.add_argument("--skip-streams", action="store_true", help="Reuse the existing step-1 store.")
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    if args.skip_streams:
        store = stream_folder(args.source) / "sequences.sqlite"
        if not store.is_file():
            raise SystemExit(f"No store to reuse at {store}")
        if SOURCES[args.source]["store"].stat().st_mtime > store.stat().st_mtime:
            raise SystemExit("Phase 2 changed after the sequence store was built; run without --skip-streams")
    else:
        code = streams.main(["--source", args.source])
        if code:
            return code
    return mine.main(["--source", args.source]) or score.main(["--source", args.source])


if __name__ == "__main__":
    raise SystemExit(runlog.main(main))
