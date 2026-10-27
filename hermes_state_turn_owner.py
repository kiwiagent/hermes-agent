"""OS-held turn ownership survives PID reuse and is released on container death.

The SQLite TTL remains the fallback for old holders and unavailable lock files.
An unlocked proof file, unlike a foreign PID, proves that the owner is gone.
"""

from pathlib import Path
import re
import uuid
import logging

from hermes_platform.host.facts import os_family

logger = logging.getLogger(__name__)

_OWNER_TOKEN = re.compile(r"(?:^|:)owner=([0-9a-f]{32})(?::|$)")


def _lock(handle):
    handle.seek(0)
    if os_family() == "win32":
        import msvcrt
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _owner_path(db_path, token):
    return Path(str(db_path) + ".turn-owners") / token


class TurnLeaseOwner:
    """A per-turn, non-inheritable handle held until the SQLite lease is released."""

    def __init__(self, db_path):
        self.token = uuid.uuid4().hex
        self.path = _owner_path(db_path, self.token)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("x+b")
        try:
            self.handle.write(b"\0")
            self.handle.flush()
            _lock(self.handle)
        except BaseException:
            self.close()
            raise

    def close(self, *, remove=True):
        self.handle.close()
        if remove:
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Could not remove retired turn owner proof", exc_info=True)


def turn_owner_is_dead(db_path, holder):
    """Only a present, lockable proof permits reclaim; unknown ownership defers to TTL."""
    match = _OWNER_TOKEN.search(holder or "")
    if not match:
        return False
    try:
        with _owner_path(db_path, match[1]).open("r+b") as handle:
            _lock(handle)
            return True
    except OSError:
        return False


def discard_dead_turn_owner(db_path, holder):
    """After a successful replacement commit, retire only an unlocked old proof."""
    if not turn_owner_is_dead(db_path, holder):
        return
    token = _OWNER_TOKEN.search(holder)[1]
    try:
        _owner_path(db_path, token).unlink(missing_ok=True)
    except OSError:
        logger.warning("Could not remove crashed turn owner proof", exc_info=True)
