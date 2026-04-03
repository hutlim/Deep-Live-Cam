"""
Filter benign AVFoundation deprecation noise on macOS.

NSLog / system frameworks write to stderr *file descriptor 2*, bypassing
Python's sys.stderr. We dup fd 2 to a pipe and forward filtered lines to the
real terminal stderr.

Must be installed before ``import cv2`` (see ``modules.__init__``).
"""
from __future__ import annotations

import os
import platform
import threading

_INSTALLED = False


def _should_drop_line(line: str) -> bool:
    return "AVCaptureDeviceTypeExternal" in line and "Continuity" in line


def install() -> None:
    global _INSTALLED
    if platform.system() != "Darwin" or _INSTALLED:
        return
    _INSTALLED = True

    # Reduces framework noise on the terminal; set DLC_KEEP_ACTIVITY_LOG=1 to skip.
    if os.environ.get("DLC_KEEP_ACTIVITY_LOG", "").lower() not in ("1", "true", "yes"):
        os.environ.setdefault("OS_ACTIVITY_MODE", "disable")

    read_end, write_end = os.pipe()
    try:
        real_stderr_fd = os.dup(2)
    except OSError:
        os.close(read_end)
        os.close(write_end)
        _INSTALLED = False
        return

    os.set_inheritable(read_end, False)
    os.set_inheritable(write_end, False)

    try:
        os.dup2(write_end, 2)
    except OSError:
        os.close(read_end)
        os.close(write_end)
        os.close(real_stderr_fd)
        _INSTALLED = False
        return
    finally:
        os.close(write_end)

    def _reader() -> None:
        buf = b""
        try:
            while True:
                chunk = os.read(read_end, 65536)
                if not chunk:
                    break
                buf += chunk
                while True:
                    nl = buf.find(b"\n")
                    if nl == -1:
                        break
                    line = buf[: nl + 1]
                    buf = buf[nl + 1 :]
                    text = line.decode("utf-8", errors="replace")
                    if _should_drop_line(text):
                        continue
                    try:
                        os.write(real_stderr_fd, line)
                    except OSError:
                        break
                # NSLog sometimes omits a trailing newline; drop a complete one-line warning.
                if buf and b"\n" not in buf:
                    partial = buf.decode("utf-8", errors="replace")
                    if _should_drop_line(partial):
                        buf = b""
            if buf:
                text = buf.decode("utf-8", errors="replace")
                if not _should_drop_line(text):
                    try:
                        os.write(real_stderr_fd, buf)
                    except OSError:
                        pass
        finally:
            try:
                os.close(read_end)
            except OSError:
                pass

    threading.Thread(
        target=_reader,
        name="dlc-macos-stderr-filter",
        daemon=True,
    ).start()
