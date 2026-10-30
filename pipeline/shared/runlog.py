"""Console output for every pipeline script: one line format, one clock, one set of verbosity options.

The rules are in pipeline/STYLE_GUIDE.md ("Console output", "Command line"); this module is their only
implementation. Every line goes to stderr, flushed:

    2026-10-30 09:12:03 | runtime 00:01:23.4 | INFO    | DONE Reading events | stage elapsed 00:00:41.2

    LOGGER                    the logger every script writes through
    add_arguments(parser)     -v/--verbose, -q/--quiet, --progress-interval
    configure_from(args)      the level and interval from those options
    run(args)                 a heartbeat while it runs, and the end-of-run line on every exit
    main(func)                run(), with the options read from the command line, around an existing main()
    stage(label)              START, then DONE or FAILED with the stage's elapsed time
    Progress, progress_items  a count, share and rate, at most once every --progress-interval seconds
    format_duration(seconds)  HH:MM:SS.s, the only way a duration is written
    log(), emit(), Log        older call sites (log(message), log.write(message, "DONE")) on the same lines
"""
from __future__ import annotations

import argparse
import logging
import math
import os
import sys
import threading
import time
import warnings
from contextlib import contextmanager
from functools import wraps

LOGGER = logging.getLogger("pipeline")
DEFAULT_INTERVAL = 10.0
LINE_FORMAT = "%(asctime)s | runtime %(runtime)s | %(levelname)-7s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
# Older level words (log.write(message, "WARN")): the standard level, and for the stage words the message prefix
LEVELS = {"DEBUG": logging.DEBUG, "INFO": logging.INFO, "WARN": logging.WARNING, "WARNING": logging.WARNING,
          "ERROR": logging.ERROR, "FAILED": logging.ERROR, "INTERRUPTED": logging.ERROR, "CRITICAL": logging.ERROR}
KEYWORDS = ("START", "DONE", "FAILED", "SKIP", "RESUME")

_state = {"started": time.monotonic(), "interval": DEFAULT_INTERVAL, "configured": False, "depth": 0,
          "stage": None, "stage_started": 0.0, "detail": None}


def format_duration(seconds: float) -> str:
    """HH:MM:SS.s, the hours unbounded: 00:00:04.2, 27:00:00.0."""
    tenths = round(max(seconds, 0) * 10)
    hours, rest = divmod(tenths, 36000)
    minutes, rest = divmod(rest, 600)
    return f"{hours:02d}:{minutes:02d}:{rest / 10:04.1f}"


def interval() -> float:
    """Seconds between progress lines and heartbeats (--progress-interval)."""
    return _state["interval"]


class _Runtime(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.runtime = format_duration(time.monotonic() - _state["started"])
        return True


class _Stderr(logging.StreamHandler):
    """Writes to whatever sys.stderr is when a line is written, so a redirected stderr (a test) receives it."""

    def __init__(self):
        super().__init__(sys.stderr)

    @property
    def stream(self):
        return sys.stderr

    @stream.setter
    def stream(self, _value):
        pass


def _one_line_warning(message, category, filename, lineno, line=None) -> str:
    """A library's warning (numpy, scikit-learn) on one line: 'RuntimeWarning: <text> (<file>:<line>)'."""
    return f"{category.__name__}: {' '.join(str(message).split())} ({os.path.basename(filename)}:{lineno})"


def configure(verbose: bool = False, quiet: bool = False, progress_interval: float | None = None) -> None:
    """INFO by default, DEBUG with verbose, warnings and errors only with quiet. Python's warnings (from numpy,
    scikit-learn and the like) become WARNING lines of the same form."""
    if progress_interval is not None:
        _state["interval"] = float(progress_interval)
    handler = _Stderr()
    handler.addFilter(_Runtime())
    handler.setFormatter(logging.Formatter(LINE_FORMAT, DATE_FORMAT))
    LOGGER.handlers.clear()
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO)
    LOGGER.propagate = False
    warnings.formatwarning = _one_line_warning
    logging.captureWarnings(True)
    captured = logging.getLogger("py.warnings")
    captured.handlers.clear()
    captured.addHandler(handler)
    captured.propagate = False
    _state["configured"] = True


def configure_from(args) -> None:
    """configure() from parsed options (add_arguments' names, or the older debug and progress_seconds)."""
    configure(verbose=bool(getattr(args, "verbose", False) or getattr(args, "debug", False)),
              quiet=bool(getattr(args, "quiet", False)),
              progress_interval=getattr(args, "progress_interval", getattr(args, "progress_seconds", None)))


def _seconds(text: str) -> float:
    value = float(text)
    if not 0 < value < math.inf:
        raise argparse.ArgumentTypeError("must be a finite number above 0")
    return value


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """-v/--verbose (or --debug), -q/--quiet, --progress-interval (or --progress-seconds)."""
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-v", "--verbose", "--debug", dest="verbose", action="store_true",
                           help="also debug lines: every file, every skipped item")
    verbosity.add_argument("-q", "--quiet", action="store_true", help="only warnings and errors")
    parser.add_argument("--progress-interval", "--progress-seconds", dest="progress_interval", type=_seconds,
                        default=DEFAULT_INTERVAL, metavar="SECONDS",
                        help=f"seconds between progress lines and heartbeats (default: {DEFAULT_INTERVAL:g})")


def _options(argv) -> argparse.Namespace:
    """The three options alone, from a command line that holds others too."""
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("-v", "--verbose", "--debug", dest="verbose", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--progress-interval", "--progress-seconds", dest="progress_interval", type=float)
    return parser.parse_known_args(argv)[0]


# --- stages and the heartbeat ------------------------------------------------------------------------------------------

def working_on(label: str | None, detail=None) -> None:
    """What the heartbeat reports until the next label, without START and DONE lines."""
    _state.update(stage=label, stage_started=time.monotonic(), detail=detail)


@contextmanager
def stage(label: str, detail=None):
    """START, then DONE (or FAILED) with the stage's elapsed time; the heartbeat names it meanwhile. detail: an
    optional callable whose text the heartbeat adds (for example SQLite activity)."""
    previous = (_state["stage"], _state["stage_started"], _state["detail"])
    started = time.monotonic()
    _state.update(stage=label, stage_started=started, detail=detail)
    LOGGER.info("START %s", label)
    try:
        yield
    except BaseException:
        LOGGER.error("FAILED %s | stage elapsed %s", label, format_duration(time.monotonic() - started))
        raise
    else:
        LOGGER.info("DONE %s | stage elapsed %s", label, format_duration(time.monotonic() - started))
    finally:
        _state["stage"], _state["stage_started"], _state["detail"] = previous


def timed_stage(function):
    """A function run as a stage named after it (and its first argument, when that is text)."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        label = function.__name__.replace("_", " ")
        if args and isinstance(args[0], str):
            label += " [" + args[0] + "]"
        with stage(label):
            return function(*args, **kwargs)
    return wrapped


def _heartbeat_line() -> str:
    if _state["stage"] is None:
        return "Still running"
    text = f"Still running: {_state['stage']} | stage elapsed {format_duration(time.monotonic() - _state['stage_started'])}"
    if _state["detail"] is not None:
        try:
            text += f" | {_state['detail']()}"
        except Exception:                                   # a detail must never stop the heartbeat
            pass
    return text


@contextmanager
def run(args=None, heartbeat: bool = True):
    """The run: configured from args (else as already configured), a heartbeat every --progress-interval seconds,
    and the end-of-run line on every exit. Yields {"status": "completed"}; set "stopped" when returning non-zero.
    Inside another run (one script calling another's main) it only yields, so there is one heartbeat and one total."""
    if args is not None:
        configure_from(args)
    elif not _state["configured"]:
        configure()
    if _state["depth"]:
        _state["depth"] += 1
        try:
            yield {"status": "completed"}
        finally:
            _state["depth"] -= 1
        return
    _state.update(depth=1, started=time.monotonic(), stage=None, detail=None)
    outcome = {"status": "completed"}
    stop = threading.Event()

    def beat():
        while not stop.wait(_state["interval"]):
            LOGGER.info("%s", _heartbeat_line())

    reporter = threading.Thread(target=beat, name="heartbeat", daemon=True)
    if heartbeat and LOGGER.isEnabledFor(logging.INFO):
        reporter.start()
    try:
        yield outcome
    except KeyboardInterrupt:
        outcome["status"] = "interrupted"
        LOGGER.error("Interrupted by user")
        raise
    except SystemExit as exit_:
        if exit_.code not in (0, None):
            outcome["status"] = "stopped"
        raise
    except BaseException:
        outcome["status"] = "failed"
        raise
    finally:
        stop.set()
        if reporter.is_alive():
            reporter.join()
        _state["depth"] = 0
        elapsed = time.monotonic() - _state["started"]
        LOGGER.log(logging.INFO if outcome["status"] == "completed" else logging.ERROR,
                   "Run %s | total runtime %s (%.2f seconds)", outcome["status"], format_duration(elapsed), elapsed)


def main(func, argv=None, heartbeat: bool = True) -> int:
    """func() inside run(), with -v, -q and --progress-interval read from the command line: for a script whose
    main() parses its own arguments. Returns func's exit code (None counts as 0); 130 after Ctrl+C."""
    argv = sys.argv[1:] if argv is None else argv
    if "-h" in argv or "--help" in argv:
        return func() or 0
    try:
        with run(_options(argv), heartbeat=heartbeat) as outcome:
            code = func()
            if isinstance(code, int) and code:
                outcome["status"] = "stopped"
            return code if isinstance(code, int) else 0
    except KeyboardInterrupt:
        return 130


# --- progress ----------------------------------------------------------------------------------------------------------

class Progress:
    """How many items so far, the share done (given a total) and the rate, at most once every --progress-interval
    seconds. step(n) adds n; report(count) sets the count; force=True writes at once."""

    def __init__(self, label: str, total: int | None = None):
        self.label, self.total, self.count = label, total, 0
        self.started = self.last_report = time.monotonic()

    def step(self, n: int = 1) -> None:
        self.report(self.count + n)

    def report(self, count: int, force: bool = False) -> None:
        self.count = count
        now = time.monotonic()
        if not force and now - self.last_report < _state["interval"]:
            return
        elapsed = now - self.started
        share = f"/{self.total:,} ({count / self.total:.1%})" if self.total else ""
        rate = f"{count / elapsed:,.0f}" if elapsed > 0 else "0"
        LOGGER.info("%s: %s%s | elapsed %s | %s per second", self.label, f"{count:,}", share,
                    format_duration(elapsed), rate)
        self.last_report = now


def progress_items(items, label: str, total: int | None = None):
    """Yields items unchanged, with a progress line at most once every --progress-interval seconds."""
    progress = Progress(label, total)
    for item in items:
        yield item
        progress.step()
    LOGGER.debug("%s: %s in total | elapsed %s", label, f"{progress.count:,}",
                 format_duration(time.monotonic() - progress.started))


# --- older call sites --------------------------------------------------------------------------------------------------

def emit(message, level: str = "INFO", quiet: bool = False, always: bool = False) -> None:
    """One line at an older level word: DEBUG, INFO, WARN(ING), ERROR, FAILED, INTERRUPTED map to their level; START,
    DONE, FAILED, SKIP and RESUME also become the message's first word; any other word is INFO."""
    if quiet and not always:
        return
    if not _state["configured"]:
        configure()
    word = str(level).upper()
    text = str(message)
    if word in KEYWORDS and not text.startswith(word):
        text = f"{word} {text}"
    LOGGER.log(LEVELS.get(word, logging.INFO), "%s", text)


def log(message, quiet: bool = False) -> None:
    """log(message) or log(message, quiet): an INFO line unless quiet."""
    emit(message, quiet=quiet)


class Log:
    """The older Log object (write, say, debug, progress, phase, elapsed) on the standard lines. quiet, debug and
    progress_seconds configure the output only when nothing has yet."""

    def __init__(self, quiet: bool = False, debug: bool = False, progress_seconds: float | None = None):
        if not _state["configured"]:
            configure(verbose=debug, quiet=quiet, progress_interval=progress_seconds)
        self.quiet, self.debug_enabled = quiet, debug
        self.started = time.perf_counter()
        self.last_progress = 0.0

    @property
    def progress_seconds(self) -> float:
        return _state["interval"]

    def write(self, message, level: str = "INFO", always: bool = False) -> None:
        emit(message, level)

    say = write

    def debug(self, message) -> None:
        emit(message, "DEBUG")

    def progress(self, message, force: bool = False) -> None:
        now = time.perf_counter()
        if force or now - self.last_progress >= _state["interval"]:
            self.last_progress = now
            emit(message)

    def elapsed(self, started: float | None = None) -> str:
        """HH:MM:SS.s since started (a time.perf_counter() value), or since this Log was made."""
        return format_duration(time.perf_counter() - (self.started if started is None else started))

    @contextmanager
    def phase(self, label: str, connection=None):
        """A stage; given an SQLite connection, the heartbeat adds how many blocks of 100,000 instructions it has run
        (evidence of SQL activity, not rows or a share done)."""
        calls = [0]

        def counted():
            calls[0] += 1
            return 0

        if connection is not None:
            connection.set_progress_handler(counted, 100_000)
        try:
            with stage(label, (lambda: f"SQLite activity callbacks {calls[0]:,}") if connection is not None else None):
                yield
        finally:
            if connection is not None:
                connection.set_progress_handler(None, 0)
