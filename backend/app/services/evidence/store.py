"""Filesystem-backed evidence storage.

One accepted upload is one immutable file on disk. This module is the only
place that writes those files, and it is deliberately a concrete class with no
protocol, no registry and no factory: there is one backend and no second one is
planned.

The layout is fixed by the approved architecture::

    <root>/
    |-- <aa>/<bb>/<uuid4-hex>.<ext>   the evidence files
    `-- .pending/                     temporary files during a write

``<aa>`` and ``<bb>`` are the first two bytes of the UUID hex, so a directory
listing reveals nothing. The file name is the UUID hex plus a restricted
extension. The extension carries no meaning - addressing is by the UUID.

Five layers of path safety apply, and they are not filters that can be
bypassed:

1. Every path is derived from a generated UUID. The client filename never
   reaches the filesystem, so a traversal string in a filename is structurally
   impossible rather than merely rejected.
2. The resolved path is checked for containment inside the resolved root.
3. Every path component is validated against a strict pattern.
4. Symlinks are never followed: ``O_NOFOLLOW`` on creation and on read,
   ``O_DIRECTORY | O_NOFOLLOW`` on the destination directory used for
   publication, ``lstat`` when inspecting an entry.
5. The original filename is never a path component, in any code path.

The write is atomic. The bytes are streamed into a temporary file, the
temporary file is closed, then re-read and re-hashed independently. Only when
the independent digest matches the streaming digest is the file made visible
at its final path with an atomic, no-overwrite hard link. The final path
therefore never holds bytes that have not been verified.

The architecture (Revision 5.2.1, §7.3 step 7) describes publication with
``os.replace``. That operation silently overwrites an existing destination and
cannot be anchored to a validated directory file descriptor. This
implementation uses ``os.link(..., dst_dir_fd=...)`` plus ``unlink`` instead:
same filesystem, atomic, fails if the destination already exists, and anchored
to an ``O_NOFOLLOW`` directory descriptor.

``os.link`` raises ``FileExistsError`` when the name already exists, which is
exactly the no-overwrite guarantee ``os.replace`` cannot give.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import re
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# The evidence file is always a raw RFC822 message. The extension is a fixed
# member of this set and is chosen by the store, never by the client.
ALLOWED_EXTENSIONS: frozenset[str] = frozenset({".eml"})
DEFAULT_EXTENSION = ".eml"

# The UUID hex is 32 lowercase hex characters. The two directory levels are
# the first two bytes of it, as two-character directory names.
_UUID_HEX_RE = re.compile(r"^[0-9a-f]{32}$")
_DIR_LEVEL_RE = re.compile(r"^[0-9a-f]{2}$")

# The storage id is the path relative to the evidence root. It is what the
# database stores, so it is short, opaque and strictly patterned.
_STORAGE_ID_RE = re.compile(
    r"^(?P<a>[0-9a-f]{2})/(?P<b>[0-9a-f]{2})/(?P<n>[0-9a-f]{32})(?P<x>\.[a-z0-9]+)$"
)

# The pending directory holds temporary files during a write. It is not
# addressable as evidence.
PENDING_DIRNAME = ".pending"

# Filesystem modes. Every directory level and the evidence root are 0700; every
# file, temporary or published, is 0600.
DIR_MODE = 0o700
FILE_MODE = 0o600

# Read size for the independent verification pass. The verification never holds
# the whole message in memory.
_VERIFY_CHUNK = 1024 * 1024


class EvidenceError(Exception):
    """Base class for evidence storage failures."""


class EvidenceNotFoundError(EvidenceError):
    """The requested storage id does not exist in the store."""


class InvalidStorageIdError(EvidenceError):
    """The storage id is malformed, unsafe, or points outside the root."""


class EvidenceTooLargeError(EvidenceError):
    """The upload exceeded the configured maximum size."""


class EvidenceStateError(EvidenceError):
    """The writer was used in a state that does not allow the operation."""


@dataclass(frozen=True, slots=True)
class StoredObject:
    """One published evidence object.

    ``storage_id`` is opaque and relative to the evidence root. ``sha256`` is
    the lowercase hex digest of the bytes. ``size_bytes`` is the exact number
    of bytes written.
    """

    storage_id: str
    sha256: str
    size_bytes: int


class EvidenceStore:
    """Filesystem-backed evidence storage.

    Deliberately a concrete class, not a protocol: there is one backend and no
    second one is planned.
    """

    def __init__(self, root: Path, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        # The root is resolved once. Every later containment check compares
        # against this resolved value, so a symlinked root cannot be used to
        # escape it.
        self._root = Path(root).expanduser().resolve()
        self._max_bytes = max_bytes

    @property
    def root(self) -> Path:
        """The resolved evidence root."""
        return self._root

    @property
    def max_bytes(self) -> int:
        """The maximum size of one evidence object, in bytes."""
        return self._max_bytes

    def open(self) -> EvidenceWriter:
        """Begin a new write.

        The destination identifier is generated here, from a fresh UUID. The
        client filename is never consulted.
        """
        identifier = uuid.uuid4().hex
        storage_id = f"{identifier[0:2]}/{identifier[2:4]}/{identifier}{DEFAULT_EXTENSION}"
        return EvidenceWriter(self, storage_id)

    # -- Paths -------------------------------------------------------------

    @staticmethod
    def _split_storage_id(storage_id: str) -> tuple[str, str, str, str]:
        """Split a storage id into its validated components."""
        match = _STORAGE_ID_RE.match(storage_id)
        if match is None:
            raise InvalidStorageIdError("malformed storage id")

        first = match.group("a")
        second = match.group("b")
        name = match.group("n")
        extension = match.group("x")

        # Strict per-component validation. Every component is a literal from a
        # fixed pattern, so no component can be "..", "/", or anything else.
        if not _DIR_LEVEL_RE.match(first) or not _DIR_LEVEL_RE.match(second):
            raise InvalidStorageIdError("malformed storage id")
        if not _UUID_HEX_RE.match(name):
            raise InvalidStorageIdError("malformed storage id")
        if extension not in ALLOWED_EXTENSIONS:
            raise InvalidStorageIdError("unsupported evidence extension")

        return first, second, name, extension

    def _resolve_storage_id(self, storage_id: str) -> Path:
        """Resolve a storage id to a path inside the root, or refuse it.

        This is the second and third path-safety layers: the components are
        validated against strict patterns, and the resolved path is checked
        for containment inside the resolved root.
        """
        first, second, name, extension = self._split_storage_id(storage_id)

        first_path = self._root / first
        second_path = first_path / second
        candidate = second_path / f"{name}{extension}"

        # Inspect every existing component without following symlinks. This
        # catches a symlinked directory before Path.resolve() turns it into an
        # apparently ordinary outside path.
        for component in (first_path, second_path, candidate):
            try:
                info = component.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode):
                raise InvalidStorageIdError("storage path contains a symlink")

        # Containment check on the resolved path. Resolving only after the
        # lstat checks prevents a symlinked directory from redirecting lookup.
        resolved = candidate.resolve()
        if not resolved.is_relative_to(self._root):
            raise InvalidStorageIdError("storage id escapes the evidence root")

        return resolved

    def _existing_path(self, storage_id: str) -> Path:
        """Resolve a storage id and require that it names an existing file.

        ``lstat`` is used rather than ``stat`` so a symlink is reported as a
        symlink and is never followed.
        """
        path = self._resolve_storage_id(storage_id)
        try:
            info = path.lstat()
        except OSError:
            raise EvidenceNotFoundError("evidence not found") from None
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceNotFoundError("evidence not found")
        return path

    def pending_path(self, storage_id: str) -> Path:
        """The temporary path a write of this storage id uses.

        The name is derived from the storage id, so it carries no client data
        and a collision is detectable rather than silent.
        """
        first, second, name, extension = self._split_storage_id(storage_id)
        flat = f"{first}{second}{name}{extension}"
        return self._root / PENDING_DIRNAME / f"{flat}.tmp"

    def _ensure_dir(self, directory: Path) -> None:
        """Create one contained, non-symlink directory with mode 0700.

        Missing parents are created because the configured default root has
        application-specific parents that do not exist on a fresh install.
        Only directories owned by PHISHGUARD are chmodded here - the root, its
        parents under the application namespace, ``.pending`` and the ``<aa>``
        and ``<bb>`` levels. A user-owned ancestor such as ``~/.local/share``
        or the XDG data directory itself is created by ``mkdir(parents=True)``
        and is never chmodded.

        Symlinks and non-directories are refused. The final mode is applied
        through ``fchmod`` on an ``O_DIRECTORY | O_NOFOLLOW`` descriptor, so a
        directory swapped for a symlink after ``lstat`` cannot redirect the
        chmod to an outside target.
        """
        resolved_parent = directory.parent.resolve()
        if not resolved_parent.is_relative_to(self._root) and resolved_parent != self._root.parent:
            raise EvidenceError("evidence directory escapes the root")

        if not directory.exists() and not directory.is_symlink():
            directory.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)

        try:
            info = directory.lstat()
        except OSError:
            raise EvidenceError("evidence directory is unsafe") from None
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise EvidenceError("evidence directory is unsafe")

        self._fchmod_dir(directory, DIR_MODE)

    def _ensure_root(self) -> None:
        """Create the evidence root and the pending directory, mode 0700."""
        self._ensure_dir(self._root)
        self._ensure_dir(self._root / PENDING_DIRNAME)

    @staticmethod
    def _open_dir(directory: Path) -> int:
        """Open a directory without following a symlink in the final component.

        ``O_DIRECTORY`` makes a non-directory fail; ``O_NOFOLLOW`` makes a
        symlink fail. The returned descriptor anchors subsequent operations to
        the directory that was validated, so a later rename of that path
        cannot redirect them.
        """
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        return os.open(directory, flags)

    @classmethod
    def _fchmod_dir(cls, directory: Path, mode: int) -> None:
        """Apply a mode through a no-follow directory descriptor."""
        descriptor = cls._open_dir(directory)
        try:
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)

    # -- Public operations -------------------------------------------------

    @classmethod
    def _open_file_nofollow(cls, path: Path) -> int:
        """Open an evidence file without following a symlink in the path.

        ``O_NOFOLLOW`` closes the read/verify time-of-check/time-of-use gap
        that ``lstat`` alone leaves open. Directory components were already
        validated by ``_resolve_storage_id``.
        """
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW)

    def read(self, storage_id: str) -> bytes:
        """Read the bytes of one evidence object."""
        path = self._existing_path(storage_id)
        try:
            descriptor = self._open_file_nofollow(path)
        except OSError:
            raise EvidenceNotFoundError("evidence not found") from None
        try:
            with os.fdopen(descriptor, "rb") as handle:
                return handle.read()
        except OSError:
            raise EvidenceNotFoundError("evidence not found") from None

    def verify(self, storage_id: str, expected_sha256: str) -> bool:
        """Re-read the evidence and re-hash it.

        Returns ``False`` when the digest does not match. A missing file is
        reported as an error rather than as a mismatch: "absent" and "present
        but altered" are different states and the caller needs to tell them
        apart.
        """
        path = self._existing_path(storage_id)
        digest = hashlib.sha256()
        try:
            descriptor = self._open_file_nofollow(path)
        except OSError:
            raise EvidenceNotFoundError("evidence not found") from None
        try:
            with os.fdopen(descriptor, "rb") as handle:
                while chunk := handle.read(_VERIFY_CHUNK):
                    digest.update(chunk)
        except OSError:
            return False
        return digest.hexdigest() == expected_sha256.lower()

    def delete(self, storage_id: str) -> None:
        """Remove one evidence object.

        Deleting an object that is already gone is not an error: the desired
        end state is "absent", and it holds.
        """
        path = self._resolve_storage_id(storage_id)
        try:
            path.unlink()
        except FileNotFoundError:
            return
        except OSError:
            raise EvidenceNotFoundError("evidence not found") from None


class EvidenceWriter:
    """One in-progress write. States: new -> open -> published | aborted.

    The bytes are streamed in and never held in memory in full. The digest is
    computed incrementally as the chunks arrive.
    """

    def __init__(self, store: EvidenceStore, storage_id: str) -> None:
        self._store = store
        self._storage_id = storage_id
        self._state = "new"
        self._digest = hashlib.sha256()
        self._size = 0
        self._handle = None
        self._temp_path: Path | None = None

    @property
    def storage_id(self) -> str:
        """The identifier this write will publish under."""
        return self._storage_id

    @property
    def state(self) -> str:
        """The current writer state: new, open, published or aborted."""
        return self._state

    @property
    def size_bytes(self) -> int:
        """How many bytes have been written so far."""
        return self._size

    def write(self, chunk: bytes) -> None:
        """Stream one chunk into the temporary file.

        The maximum size is enforced while streaming, not afterwards, so an
        oversized upload is stopped before the whole body has been written.
        """
        if self._state not in ("new", "open"):
            raise EvidenceStateError(f"cannot write in state {self._state!r}")

        if self._size + len(chunk) > self._store.max_bytes:
            # The limit is enforced before the bytes are written, so the
            # oversized tail never reaches the disk.
            self.abort()
            raise EvidenceTooLargeError("evidence exceeds the maximum allowed size")

        if self._state == "new":
            self._open_temp()

        handle = self._handle
        if handle is None:  # pragma: no cover - invariant
            raise EvidenceStateError("temporary evidence file is not open")

        try:
            handle.write(chunk)
        except OSError:
            self.abort()
            raise
        self._digest.update(chunk)
        self._size += len(chunk)

    def publish(self) -> StoredObject:
        """Verify the bytes independently and publish without overwriting.

        The temporary file is closed, re-read and re-hashed. Only when that
        independent digest matches the streaming digest is the file linked into
        its final directory with an atomic no-overwrite operation anchored to
        a validated directory descriptor.
        """
        if self._state == "published":
            raise EvidenceStateError("evidence is already published")
        if self._state == "aborted":
            raise EvidenceStateError("evidence was aborted")
        if self._state == "new":
            raise EvidenceStateError("evidence has no content to publish")
        handle = self._handle
        temp_path = self._temp_path
        if handle is None or temp_path is None:  # pragma: no cover - invariant
            raise EvidenceStateError("temporary evidence file is not open")

        # Flush and fsync the data before it is verified, so the verification
        # reads the bytes that will actually be published.
        try:
            handle.flush()
            os.fsync(handle.fileno())
        except OSError:
            self.abort()
            raise
        finally:
            handle.close()
            self._handle = None

        # The independent re-read. This is what makes the recorded digest
        # trustworthy: the final path never holds bytes that have not been
        # verified by a second, separate pass.
        try:
            verified = self._hash_file(temp_path)
        except OSError:
            self.abort()
            raise

        if verified != self._digest.hexdigest():
            # The bytes on disk are not the bytes that were written. The file
            # is removed and nothing is published.
            self.abort()
            raise EvidenceError("evidence digest verification failed")

        first, second, name, extension = self._store._split_storage_id(self._storage_id)
        first_dir = self._store.root / first
        second_dir = first_dir / second
        self._store._ensure_dir(first_dir)
        self._store._ensure_dir(second_dir)
        filename = f"{name}{extension}"

        # Hold the destination directory open through a no-follow descriptor.
        # Every later operation is descriptor-relative, so swapping the path
        # for a symlink cannot redirect the publication outside the root.
        try:
            directory_fd = self._store._open_dir(second_dir)
        except OSError:
            self.abort()
            raise EvidenceError("evidence directory is unsafe") from None

        try:
            # os.link is atomic and fails if the name already exists. Unlike
            # os.replace it cannot silently overwrite evidence that appeared
            # after any earlier check. Both paths live under the same root, so
            # hard linking cannot cross a filesystem boundary.
            try:
                os.link(temp_path, filename, dst_dir_fd=directory_fd, follow_symlinks=False)
            except FileExistsError:
                self.abort()
                raise EvidenceError("evidence already exists") from None
            except OSError:
                self.abort()
                raise

            self._fsync_fd(directory_fd)
        finally:
            os.close(directory_fd)

        # The temporary name is removed only after the destination is durable.
        # abort() after publication is a no-op, so this cleanup is safe.
        with contextlib.suppress(FileNotFoundError):
            temp_path.unlink()

        self._temp_path = None
        self._state = "published"

        return StoredObject(
            storage_id=self._storage_id,
            sha256=self._digest.hexdigest(),
            size_bytes=self._size,
        )

    def abort(self) -> None:
        """Discard the write and remove the temporary file.

        Idempotent, and safe after publishing: a published file is never
        removed by an abort.
        """
        if self._state == "published":
            return
        if self._state == "aborted":
            return

        if self._handle is not None:
            try:
                self._handle.close()
            except OSError:
                logger.debug("could not close the temporary evidence file")
            self._handle = None

        if self._temp_path is not None:
            try:
                self._temp_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                logger.debug("could not remove the temporary evidence file")
            self._temp_path = None

        self._state = "aborted"

    # -- Internals ---------------------------------------------------------

    def _open_temp(self) -> None:
        """Create the temporary file with exclusive, no-follow semantics."""
        self._store._ensure_root()
        temp_path = self._store.pending_path(self._storage_id)

        # O_EXCL makes a temporary-file collision impossible: the write is
        # refused rather than overwriting an existing file. O_NOFOLLOW refuses
        # a symlink at that path.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            descriptor = os.open(temp_path, flags, FILE_MODE)
        except FileExistsError:
            raise EvidenceError("temporary evidence file already exists") from None

        # The mode is set explicitly: the builtin open() would yield
        # 0o666 & ~umask, which on a typical host is world-readable evidence.
        try:
            os.fchmod(descriptor, FILE_MODE)
        except OSError:
            os.close(descriptor)
            temp_path.unlink(missing_ok=True)
            raise

        self._handle = os.fdopen(descriptor, "wb")
        self._temp_path = temp_path
        self._state = "open"

    @classmethod
    def _hash_file(cls, path: Path) -> str:
        """Re-read a file and return its SHA-256 hex digest.

        The file is read in chunks, so the whole message is never in memory.
        The open is no-follow, matching ``read()`` and ``verify()``.
        """
        digest = hashlib.sha256()
        descriptor = cls._store_open(path)
        with os.fdopen(descriptor, "rb") as handle:
            while chunk := handle.read(_VERIFY_CHUNK):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _store_open(path: Path) -> int:
        """Open a published or temporary file without following symlinks."""
        return os.open(path, os.O_RDONLY | os.O_NOFOLLOW)

    @staticmethod
    def _fsync_fd(descriptor: int) -> None:
        """fsync a directory descriptor so the link is durable."""
        try:
            os.fsync(descriptor)
        except OSError:
            logger.debug("could not fsync the evidence directory")
