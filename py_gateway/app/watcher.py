"""Debounced filesystem watcher.

Port of internal/watcher/watcher.go. Uses the ``watchdog`` library.

Watches one or more directories for ``.json`` file changes and calls the
configured sync callback after a quiet period (default 2 s), matching the
debouncer behaviour in the Go implementation.
"""

import logging
import threading
from pathlib import Path as FSPath
from typing import Callable, List, Optional

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError as _err:
    raise ImportError(
        "watchdog is required for file-change watching. "
        "Install it with: pip install 'watchdog>=3.0'"
    ) from _err

logger = logging.getLogger(__name__)


class _DebounceHandler(FileSystemEventHandler):
    """Debounce rapid filesystem events and call *callback* once they settle."""

    def __init__(self, callback: Callable, delay: float = 2.0) -> None:
        super().__init__()
        self._callback = callback
        self._delay = delay
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()

    def _arm(self) -> None:
        """(Re)start the debounce timer."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self._delay, self._callback)
            self._timer.daemon = True
            self._timer.start()

    # Only react to .json files (SCIM data / policy changes).
    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith(".json"):
            self._arm()

    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith(".json"):
            self._arm()

    def on_deleted(self, event):
        if not event.is_directory and event.src_path.endswith(".json"):
            self._arm()

    def on_moved(self, event):
        if not event.is_directory:
            self._arm()

    def cancel(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None


class FileWatcher:
    """Watch multiple directories and trigger *sync_callback* on JSON changes.

    Args:
        sync_callback:    Called (no arguments) after the debounce quiet period.
        health_refresher: Optional callback invoked after each triggered sync.
        debounce_delay:   Seconds of quiet time before the callback fires
                          (mirrors the 2 s Go debouncer).
    """

    def __init__(
        self,
        sync_callback: Callable,
        health_refresher: Optional[Callable] = None,
        debounce_delay: float = 2.0,
    ) -> None:
        self._sync_callback = sync_callback
        self._health_refresher = health_refresher
        self._observer = Observer()
        self._handler = _DebounceHandler(self._on_change, delay=debounce_delay)
        self._dirs: List[str] = []

    def _on_change(self) -> None:
        logger.info("File change detected – triggering SCIM → IAM sync")
        try:
            self._sync_callback()
        except Exception as exc:
            logger.error("Sync after file change failed: %s", exc)
        else:
            logger.info("Post file-change sync completed")
        if self._health_refresher:
            try:
                self._health_refresher()
            except Exception:
                pass

    def add_directory(self, path: str) -> None:
        """Watch *path* (non-recursive) for JSON file changes."""
        abs_path = str(FSPath(path).resolve())
        self._observer.schedule(self._handler, abs_path, recursive=False)
        self._dirs.append(abs_path)
        logger.info("Watching: %s", abs_path)

    def start(self) -> None:
        self._observer.start()
        logger.info("File watcher started (%d dir(s))", len(self._dirs))

    def close(self) -> None:
        self._handler.cancel()
        self._observer.stop()
        self._observer.join()
        logger.info("File watcher stopped")
