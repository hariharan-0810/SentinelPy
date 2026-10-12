"""Follow a log file like `tail -F`: survives rotation/truncation, never emits partial
lines, and can resume from a stored offset after a restart."""
import os
from .database import get_tail_state

MAX_READ = 4 * 1024 * 1024


class FileTailer:
    def __init__(self, path, db=None, from_start=False, log=print):
        self.path, self.from_start, self.log = str(path), from_start, log
        saved = get_tail_state(db, self.path) if db is not None else None
        self.inode, self.offset = saved if saved else (None, 0)
        self._warned = False
        self._was_missing = False
        self.dirty = False

    def _warn_once(self, text):
        if not self._warned:
            self.log(f"[WARN] {text}: {self.path}")
            self._warned = True

    def poll(self):
        """Return new complete lines as [(unique_key, text)]."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            self._was_missing = True
            self._warn_once("Log file not found; waiting for it to appear")
            return []
        except PermissionError:
            self._warn_once("Permission denied reading log")
            return []
        except OSError as e:
            self._warn_once(f"Cannot stat log ({e})")
            return []

        if self.inode is None:                       # first time we have ever seen this file
            self.offset = 0 if (self.from_start or self._was_missing) else st.st_size
            self.inode = st.st_ino
            self.dirty = True
        elif st.st_ino != self.inode:                # rotated: new file, read it all
            self.inode, self.offset, self.dirty = st.st_ino, 0, True
        elif st.st_size < self.offset:               # truncated in place
            self.offset, self.dirty = 0, True
        self._warned = False
        if st.st_size == self.offset:
            return []

        try:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                data = f.read(MAX_READ)
        except PermissionError:
            self._warn_once("Permission denied reading log")
            return []
        except OSError as e:
            self._warn_once(f"Cannot read log ({e})")
            return []

        end = data.rfind(b"\n")
        if end == -1:
            if len(data) < MAX_READ:
                return []                            # wait for the rest of the line
            end = len(data) - 1                      # absurdly long line: don't stall forever
        out, pos = [], self.offset
        for raw in data[:end + 1].splitlines(keepends=True):
            out.append((f"{self.path}|{self.inode}|{pos}", raw.decode("utf-8", errors="replace")))
            pos += len(raw)
        self.offset, self.dirty = pos, True
        return out
