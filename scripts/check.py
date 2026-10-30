"""Every automatic check, in one run: the console's tests, the pipeline's tests and the web build (type check
included). The pre-push hook runs it (scripts/git_guard.py); run it yourself before a release.

    python scripts/check.py            all three
    python scripts/check.py --skip-web the tests only (no Node.js)

Exit code 0 when everything passed; a failure prints the last lines of that check's output.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline" / "shared"))
import runlog  # noqa: E402  console output: pipeline/STYLE_GUIDE.md

LOGGER = runlog.LOGGER
TAIL = 40
PIPELINE_TESTS = ["pipeline/phase1_classify", "pipeline/phase4f_sequences", "pipeline/phase4_detection", "pipeline/phase7_alerts",
                  "pipeline/phase9_llm_triage", "scripts"]


def checks(skip_web: bool):
    python = sys.executable
    yield "Console tests", [python, "-m", "unittest", "discover", "tests", "-q"], ROOT / "triage-console"
    for folder in PIPELINE_TESTS:
        if any((ROOT / folder).glob("test_*.py")):
            yield f"Pipeline tests ({folder})", [python, "-m", "unittest", "discover", "-s", folder, "-p", "test_*.py", "-q"], ROOT
    if not skip_web:
        npm = "npm.cmd" if os.name == "nt" else "npm"
        yield "Web build and type check", [npm, "run", "build"], ROOT / "triage-console" / "web"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--skip-web", action="store_true", help="leave out the web build")
    runlog.add_arguments(parser)
    args = parser.parse_args(argv)
    failed = []
    with runlog.run(args) as outcome:
        for label, command, cwd in checks(args.skip_web):
            with runlog.stage(label):
                result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            if result.returncode:
                failed.append(label)
                for line in (result.stdout + result.stderr).splitlines()[-TAIL:]:
                    if line.strip():
                        LOGGER.error(f"{label}: {line}")
        LOGGER.info(f"Checks: {len(failed):,} failed" + (f" ({', '.join(failed)})" if failed else ""))
        if failed:
            outcome["status"] = "stopped"
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
