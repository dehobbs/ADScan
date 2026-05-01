import sys
import threading
import time
from contextlib import contextmanager

_FRAMES = ['|', '/', '-', '\\']


class Spinner:
    def __init__(self, label="", delay=2.0):
        self._label  = label
        self._delay  = delay
        self._stop   = threading.Event()
        self._paused = threading.Event()
        self._thread = None
        self._t0     = None
        self._shown  = False

    def _run(self):
        self._stop.wait(timeout=self._delay)
        if self._stop.is_set():
            return
        idx = 0
        while not self._stop.is_set():
            if not self._paused.is_set():
                self._shown = True
                elapsed = time.time() - self._t0
                frame   = _FRAMES[idx % len(_FRAMES)]
                sys.stderr.write(f"\r  {frame}  {self._label}  {elapsed:.1f}s  ")
                sys.stderr.flush()
                idx += 1
            self._stop.wait(timeout=0.1)

    def pause(self):
        """Stop drawing the spinner and clear the current line."""
        self._paused.set()
        if self._shown:
            sys.stderr.write('\r' + ' ' * 60 + '\r')
            sys.stderr.flush()
            self._shown = False

    def resume(self):
        """Resume drawing the spinner."""
        self._paused.clear()

    @contextmanager
    def suspended(self):
        """Context manager: pause the spinner for the duration of the block."""
        self.pause()
        try:
            yield
        finally:
            self.resume()

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
    def pause(self): pass
    def resume(self): pass
    @contextmanager
    def suspended(self):
        yield


def spinner(label="", delay=2.0, enabled=True):
    """Return a Spinner if enabled and stderr is a TTY, otherwise a no-op."""
    if enabled and sys.stderr.isatty():
        return Spinner(label=label, delay=delay)
    return _NoOp()
