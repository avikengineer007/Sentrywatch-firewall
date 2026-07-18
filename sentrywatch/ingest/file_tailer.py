import time
from pathlib import Path
from typing import Callable, Optional
from sentrywatch.ingest.normalizer import EventNormalizer, LogEvent


class LogFileTailer:
    def __init__(self, filepath: Path, source_name: str = "logfile"):
        self.filepath = filepath
        self.source_name = source_name
        self._running = False

    def tail(self, callback: Callable[[LogEvent], None], poll_interval: float = 0.5) -> None:
        self._running = True
        if not self.filepath.exists():
            # Create file if it doesn't exist
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            self.filepath.touch()

        with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
            # Move to end of file initially
            f.seek(0, 2)
            while self._running:
                line = f.readline()
                if line:
                    event = EventNormalizer.normalize(line, source=self.source_name)
                    callback(event)
                else:
                    time.sleep(poll_interval)

    def stop(self) -> None:
        self._running = False
