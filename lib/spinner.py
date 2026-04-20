import sys
import threading
import time

_FRAMES = ['|', '/', '-', '\\']


class Spinner:
    def __init__(self, label="", delay=2.0):
        self._label  = label
        self._delay  = delay
        self._stop   = threading.Event()
        self._thread = None
        self._t0     = None
        self._shown  = False

    def _run(self):
        self._stop.wait(timeout=self._delay)
        if self._stop.is_set():
            return
        self._shown = True
        idx = 0
        while not self._stop.is_set():
            elapsed = time.time() - self._t0
            frame   = _FRAMES[idx % len(_FRAMES)]
            sys.stderr.write(f"\r  {frame}  {self._label}  {elapsed:.1f}s  ")
            sys.stderr.flush()
            idx += 1
            self._stop.wait(timeout=0.1)

    def __enter__(self):
        self._t0     = time.time()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()
        if self._shown:
            sys.stderr.write('\r' + ' ' * 60 + '\r')
            sys.stderr.flush()


class _NoOp:
    def __enter__(self): return self
    def __exit__(self, *_): pass


def spinner(label="", delay=2.0, enabled=True):
    """Return a Spinner if enabled and stderr is a TTY, otherwise a no-op."""
    if enabled and sys.stderr.isatty():
        return Spinner(label=label, delay=delay)
    return _NoOp()
