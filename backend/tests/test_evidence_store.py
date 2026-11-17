"""Evidence storage tests.

These cover the architecture's T-32 to T-39 requirements, plus the writer
lifecycle and the configuration validator.

Every test uses a temporary directory. The real evidence directory is never
touched.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest
from app.core.config import Settings, default_evidence_root, validate_evidence_root
from app.services.evidence.store import (
    EvidenceError,
    EvidenceNotFoundError,
    EvidenceStateError,
    EvidenceStore,
    EvidenceTooLargeError,
    InvalidStorageIdError,
)

MAX_BYTES = 1024 * 1024


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """An empty evidence root for one test."""
    return tmp_path / "evidence"


@pytest.fixture
def store(root: Path) -> EvidenceStore:
    """A store bound to a temporary root."""
    return EvidenceStore(root, max_bytes=MAX_BYTES)


def _write(store: EvidenceStore, data: bytes):
    """Stream one message through the writer and publish it."""
    writer = store.open()
    writer.write(data)
    return writer, writer.publish()


# ---------------------------------------------------------------------------
# T-32: a path traversal filename cannot escape the root
# ---------------------------------------------------------------------------


def test_the_stored_path_stays_inside_the_root(store: EvidenceStore, root: Path) -> None:
    """The stored path is inside the root and holds no user string."""
    hostile = "../../../../etc/passwd"
    writer, published = _write(store, b"payload")

    resolved = (store.root / published.storage_id).resolve()
    assert resolved.is_relative_to(store.root)
    assert hostile not in published.storage_id
    assert published.storage_id == writer.storage_id

    # Every component of the storage id is a strict, generated pattern.
    parts = published.storage_id.split("/")
    assert len(parts) == 3
    assert parts[0].isalnum()
    assert parts[1].isalnum()
    assert parts[2].removesuffix(".eml").isalnum()
    assert not store.root.joinpath(published.storage_id).is_symlink()


def test_a_hostile_filename_is_never_a_path_component(store: EvidenceStore) -> None:
    """The client filename never reaches the filesystem.

    The store has no parameter for a filename at all, so the traversal is
    structurally impossible rather than filtered.
    """
    writer, published = _write(store, b"payload")

    assert ".." not in published.storage_id
    assert "/" not in published.storage_id.split("/")[2].replace(".eml", "")
    assert published.storage_id.endswith(".eml")


# ---------------------------------------------------------------------------
# T-33: a symlink at the target path is refused
# ---------------------------------------------------------------------------


def test_a_symlink_at_the_pending_path_is_refused(store: EvidenceStore, root: Path) -> None:
    """O_NOFOLLOW refuses a symlink where the temporary file would go."""
    store.root.mkdir(parents=True, exist_ok=True)
    pending = store.root / ".pending"
    pending.mkdir(parents=True, exist_ok=True)

    target = root / "outside.eml"
    target.write_bytes(b"not mine")

    writer = store.open()
    link = pending / f"{writer.storage_id.replace('/', '')}.tmp"
    link.symlink_to(target)

    with pytest.raises(EvidenceError):
        writer.write(b"payload")

    # The symlink target is untouched.
    assert target.read_bytes() == b"not mine"


def test_a_symlink_at_the_evidence_path_is_refused(store: EvidenceStore, root: Path) -> None:
    """A symlink planted at the destination is never followed or overwritten."""
    root.mkdir(parents=True, exist_ok=True)
    outside = root / "outside.eml"
    outside.write_bytes(b"not mine")

    writer = store.open()
    first, second, filename = writer.storage_id.split("/")
    directory = store.root / first / second
    directory.mkdir(parents=True, exist_ok=True)
    link = directory / filename
    link.symlink_to(outside)

    writer.write(b"payload")
    with pytest.raises(EvidenceError):
        writer.publish()

    assert outside.read_bytes() == b"not mine"


# ---------------------------------------------------------------------------
# T-34: a temporary-file collision is refused
# ---------------------------------------------------------------------------


def test_a_temporary_file_collision_is_refused(store: EvidenceStore) -> None:
    """O_EXCL refuses a write onto an existing temporary file."""
    writer = store.open()
    collision = store.pending_path(writer.storage_id)
    collision.parent.mkdir(parents=True, exist_ok=True)
    collision.write_bytes(b"someone else got here first")

    with pytest.raises(EvidenceError):
        writer.write(b"payload")

    # The existing file is not overwritten.
    assert collision.read_bytes() == b"someone else got here first"


# ---------------------------------------------------------------------------
# T-35 / T-36: permissions
# ---------------------------------------------------------------------------


def test_the_evidence_file_mode_is_0600(store: EvidenceStore) -> None:
    """The published file is 0600."""
    _, published = _write(store, b"payload")

    mode = (store.root / published.storage_id).stat().st_mode
    assert stat.S_IMODE(mode) == 0o600


def test_the_evidence_file_mode_is_0600_under_a_permissive_umask(
    store: EvidenceStore,
) -> None:
    """The mode does not depend on the umask."""
    previous = os.umask(0o000)
    try:
        _, published = _write(store, b"payload")
    finally:
        os.umask(previous)

    mode = (store.root / published.storage_id).stat().st_mode
    assert stat.S_IMODE(mode) == 0o600


def test_the_evidence_root_and_directory_modes_are_0700(store: EvidenceStore) -> None:
    """The root, the pending directory and the directory levels are 0700."""
    _, published = _write(store, b"payload")

    assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
    assert stat.S_IMODE((store.root / ".pending").stat().st_mode) == 0o700

    first, second, _ = published.storage_id.split("/")
    assert stat.S_IMODE((store.root / first).stat().st_mode) == 0o700
    assert stat.S_IMODE((store.root / first / second).stat().st_mode) == 0o700


# ---------------------------------------------------------------------------
# T-37 / T-38: the bytes and the digest
# ---------------------------------------------------------------------------


def test_the_written_bytes_round_trip_exactly(store: EvidenceStore) -> None:
    """The bytes are preserved, including embedded NUL bytes."""
    data = b"Subject: test\r\n\r\nbody with \x00 nul \x00 bytes\r\n"

    _, published = _write(store, data)

    assert store.read(published.storage_id) == data


def test_the_digest_matches_hashlib(store: EvidenceStore) -> None:
    """The recorded digest is the SHA-256 of the bytes."""
    data = b"Subject: digest\r\n\r\ncontent"

    _, published = _write(store, data)

    assert published.sha256 == hashlib.sha256(data).hexdigest()
    assert published.size_bytes == len(data)


def test_the_digest_is_computed_over_the_streamed_bytes(store: EvidenceStore) -> None:
    """A message split into chunks has the same digest as one written whole."""
    data = b"x" * 5000
    writer = store.open()
    for offset in range(0, len(data), 1000):
        writer.write(data[offset : offset + 1000])
    published = writer.publish()

    assert published.sha256 == hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# T-39: verification detects a modified byte
# ---------------------------------------------------------------------------


def test_verification_returns_false_after_a_stored_byte_is_modified(store: EvidenceStore) -> None:
    """A modified byte is detected."""
    data = b"Subject: integrity\r\n\r\noriginal content"
    _, published = _write(store, data)

    assert store.verify(published.storage_id, published.sha256) is True

    target = store.root / published.storage_id
    content = bytearray(target.read_bytes())
    content[0] = content[0] ^ 0xFF
    target.write_bytes(bytes(content))

    assert store.verify(published.storage_id, published.sha256) is False


def test_verification_returns_false_for_a_different_digest(store: EvidenceStore) -> None:
    """A digest that was never recorded does not verify."""
    _, published = _write(store, b"payload")

    assert store.verify(published.storage_id, "0" * 64) is False


# ---------------------------------------------------------------------------
# Sizes and empty evidence
# ---------------------------------------------------------------------------


def test_a_writer_with_no_content_cannot_publish(store: EvidenceStore) -> None:
    """Publishing from the `new` state is an invalid transition.

    No bytes were ever written, so there is nothing to hash, verify or
    publish. The empty-upload policy itself (422, nothing stored) belongs to
    the API layer, not to the byte sink.
    """
    writer = store.open()

    with pytest.raises(EvidenceStateError):
        writer.publish()


def test_an_explicitly_empty_write_is_stored_faithfully(store: EvidenceStore) -> None:
    """A zero-byte write round-trips with the digest of the empty string."""
    writer = store.open()
    writer.write(b"")
    published = writer.publish()

    assert published.size_bytes == 0
    assert published.sha256 == hashlib.sha256(b"").hexdigest()
    assert store.read(published.storage_id) == b""
    assert store.verify(published.storage_id, published.sha256) is True


def test_a_message_of_exactly_the_maximum_size_is_accepted(root: Path) -> None:
    """The limit is inclusive."""
    store = EvidenceStore(root, max_bytes=100)
    data = b"y" * 100

    _, published = _write(store, data)

    assert published.size_bytes == 100


def test_a_message_exceeding_the_maximum_size_is_refused(root: Path) -> None:
    """An oversized message is stopped while streaming."""
    store = EvidenceStore(root, max_bytes=100)
    writer = store.open()

    with pytest.raises(EvidenceTooLargeError):
        writer.write(b"z" * 101)

    # The failed write left no temporary file behind.
    pending = store.root / ".pending"
    assert not pending.exists() or list(pending.iterdir()) == []


def test_a_message_exceeding_the_maximum_size_in_chunks_is_refused(root: Path) -> None:
    """The limit is enforced across chunks, not only within one."""
    store = EvidenceStore(root, max_bytes=100)
    writer = store.open()

    writer.write(b"z" * 60)
    with pytest.raises(EvidenceTooLargeError):
        writer.write(b"z" * 60)

    assert writer.state == "aborted"
    assert list((store.root / ".pending").iterdir()) == []


# ---------------------------------------------------------------------------
# Invalid storage ids
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "storage_id",
    [
        "",
        "../../etc/passwd",
        "../ab/cd/" + "0" * 32 + ".eml",
        "ab/cd/" + "0" * 31 + ".eml",
        "ab/cd/" + "0" * 33 + ".eml",
        "ab/cd/" + "0" * 32 + ".txt",
        "ab/cd/" + "g" * 32 + ".eml",
        "ab/cd/" + "0" * 32,
        "ab/" + "0" * 32 + ".eml",
        "ab/cd/ef/" + "0" * 32 + ".eml",
        "/ab/cd/" + "0" * 32 + ".eml",
        "ab/cd/../../../../etc/passwd",
        "AB/CD/" + "0" * 32 + ".EML",
    ],
)
def test_an_invalid_storage_id_is_refused(store: EvidenceStore, storage_id: str) -> None:
    """Every malformed or unsafe identifier is refused."""
    with pytest.raises(InvalidStorageIdError):
        store.read(storage_id)
    with pytest.raises(InvalidStorageIdError):
        store.verify(storage_id, "0" * 64)
    with pytest.raises(InvalidStorageIdError):
        store.delete(storage_id)


def test_a_symlinked_directory_level_cannot_redirect_a_read(
    store: EvidenceStore, root: Path
) -> None:
    """A symlinked directory level is refused by the containment check."""
    outside = root / "outside"
    outside.mkdir(parents=True, exist_ok=True)
    secret = outside / "secret.eml"
    secret.write_bytes(b"not mine")

    first = store.root / "ab"
    first.parent.mkdir(parents=True, exist_ok=True)
    first.symlink_to(outside)

    storage_id = f"ab/cd/{'0' * 32}.eml"
    with pytest.raises(InvalidStorageIdError):
        store.read(storage_id)


# ---------------------------------------------------------------------------
# Missing evidence
# ---------------------------------------------------------------------------


def test_reading_missing_evidence_raises(store: EvidenceStore) -> None:
    """Absent evidence is an error, not an empty result."""
    with pytest.raises(EvidenceNotFoundError):
        store.read(f"ab/cd/{'0' * 32}.eml")


def test_verifying_missing_evidence_raises(store: EvidenceStore) -> None:
    """Absent evidence is distinct from altered evidence."""
    with pytest.raises(EvidenceNotFoundError):
        store.verify(f"ab/cd/{'0' * 32}.eml", "0" * 64)


def test_deleting_missing_evidence_is_not_an_error(store: EvidenceStore) -> None:
    """The desired end state is "absent", and it holds."""
    store.delete(f"ab/cd/{'0' * 32}.eml")


# ---------------------------------------------------------------------------
# Read, verify and delete
# ---------------------------------------------------------------------------


def test_read_returns_the_published_bytes(store: EvidenceStore) -> None:
    """The reader returns exactly what was written."""
    data = b"Subject: read\r\n\r\nbody"
    _, published = _write(store, data)

    assert store.read(published.storage_id) == data


def test_delete_removes_the_evidence(store: EvidenceStore) -> None:
    """The deleter removes the file."""
    _, published = _write(store, b"payload")

    store.delete(published.storage_id)

    with pytest.raises(EvidenceNotFoundError):
        store.read(published.storage_id)


def test_delete_is_idempotent(store: EvidenceStore) -> None:
    """Deleting twice is not an error."""
    _, published = _write(store, b"payload")

    store.delete(published.storage_id)
    store.delete(published.storage_id)


def test_delete_does_not_touch_a_neighbouring_file(store: EvidenceStore) -> None:
    """Deleting one object leaves the others alone."""
    _, first = _write(store, b"first")
    _, second = _write(store, b"second")

    store.delete(first.storage_id)

    assert store.read(second.storage_id) == b"second"


# ---------------------------------------------------------------------------
# Writer state transitions
# ---------------------------------------------------------------------------


def test_a_new_writer_has_no_content(store: EvidenceStore) -> None:
    """A fresh writer cannot publish."""
    writer = store.open()

    assert writer.state == "new"
    with pytest.raises(EvidenceStateError):
        writer.publish()


def test_writing_moves_the_writer_to_open(store: EvidenceStore) -> None:
    """The first chunk opens the temporary file."""
    writer = store.open()
    writer.write(b"payload")

    assert writer.state == "open"


def test_publishing_moves_the_writer_to_published(store: EvidenceStore) -> None:
    """A published writer is done."""
    writer = store.open()
    writer.write(b"payload")
    writer.publish()

    assert writer.state == "published"


def test_writing_after_publishing_is_refused(store: EvidenceStore) -> None:
    """A published writer accepts no more bytes."""
    writer = store.open()
    writer.write(b"payload")
    writer.publish()

    with pytest.raises(EvidenceStateError):
        writer.write(b"more")


def test_publishing_twice_is_refused(store: EvidenceStore) -> None:
    """A published writer cannot be published again."""
    writer = store.open()
    writer.write(b"payload")
    writer.publish()

    with pytest.raises(EvidenceStateError):
        writer.publish()


def test_writing_after_aborting_is_refused(store: EvidenceStore) -> None:
    """An aborted writer accepts no more bytes."""
    writer = store.open()
    writer.write(b"payload")
    writer.abort()

    with pytest.raises(EvidenceStateError):
        writer.write(b"more")


def test_publishing_after_aborting_is_refused(store: EvidenceStore) -> None:
    """An aborted writer cannot be published."""
    writer = store.open()
    writer.write(b"payload")
    writer.abort()

    with pytest.raises(EvidenceStateError):
        writer.publish()


# ---------------------------------------------------------------------------
# Abort behaviour
# ---------------------------------------------------------------------------


def test_abort_is_idempotent(store: EvidenceStore) -> None:
    """Aborting twice is not an error."""
    writer = store.open()
    writer.write(b"payload")

    writer.abort()
    writer.abort()

    assert writer.state == "aborted"


def test_abort_after_publication_does_not_delete_the_published_file(store: EvidenceStore) -> None:
    """A published file is never removed by an abort."""
    _, published = _write(store, b"payload")

    writer = store.open()
    writer.write(b"other")
    writer.publish()
    writer.abort()

    assert store.read(published.storage_id) == b"payload"


def test_abort_removes_the_temporary_file(store: EvidenceStore) -> None:
    """An aborted write leaves no temporary file behind."""
    writer = store.open()
    writer.write(b"payload")

    writer.abort()

    assert list((store.root / ".pending").iterdir()) == []


def test_abort_publishes_nothing(store: EvidenceStore) -> None:
    """An aborted write produces no evidence."""
    writer = store.open()
    writer.write(b"payload")
    writer.abort()

    with pytest.raises(EvidenceNotFoundError):
        store.read(writer.storage_id)


# ---------------------------------------------------------------------------
# Cleanup after a failed write
# ---------------------------------------------------------------------------


def test_a_failed_write_cleans_up_the_temporary_file(store: EvidenceStore) -> None:
    """A failure removes the temporary file."""
    writer = store.open()
    writer.write(b"payload")

    # Force a failure by making the digest disagree with the bytes on disk.
    writer._digest = hashlib.sha256(b"something else")
    with pytest.raises(EvidenceError):
        writer.publish()

    assert list((store.root / ".pending").iterdir()) == []


def test_an_oversized_write_cleans_up_the_temporary_file(root: Path) -> None:
    """An oversized upload leaves no temporary file behind."""
    store = EvidenceStore(root, max_bytes=10)
    writer = store.open()
    writer.write(b"z" * 6)

    with pytest.raises(EvidenceTooLargeError):
        writer.write(b"z" * 6)

    assert list((store.root / ".pending").iterdir()) == []


# ---------------------------------------------------------------------------
# The independent re-read
# ---------------------------------------------------------------------------


def test_a_digest_mismatch_aborts_publication(store: EvidenceStore) -> None:
    """The independent re-read decides whether the file is published.

    The streaming digest is deliberately corrupted here, so the independently
    computed digest disagrees. Nothing may be published.
    """
    writer = store.open()
    writer.write(b"payload")
    writer._digest = hashlib.sha256(b"a different message")

    with pytest.raises(EvidenceError):
        writer.publish()

    assert writer.state == "aborted"
    with pytest.raises(EvidenceNotFoundError):
        store.read(writer.storage_id)


def test_the_published_file_is_the_verified_file(store: EvidenceStore) -> None:
    """The published bytes are the ones that passed the independent check."""
    data = b"Subject: verified\r\n\r\ncontent"
    writer = store.open()
    writer.write(data)
    published = writer.publish()

    assert store.read(published.storage_id) == data
    assert store.verify(published.storage_id, hashlib.sha256(data).hexdigest()) is True


# ---------------------------------------------------------------------------
# The evidence root configuration
# ---------------------------------------------------------------------------


def test_the_filesystem_root_is_refused() -> None:
    """ "/" is never a valid evidence root."""
    with pytest.raises(ValueError, match="filesystem root"):
        validate_evidence_root(Path("/"))


def test_the_home_directory_is_refused() -> None:
    """A home directory is never a valid evidence root."""
    with pytest.raises(ValueError, match="home directory"):
        validate_evidence_root(Path.home())


def test_a_root_inside_the_project_tree_is_refused() -> None:
    """The project tree is never a valid evidence root."""
    from app.core.config import _project_root

    project = _project_root()
    with pytest.raises(ValueError, match="project tree"):
        validate_evidence_root(project / "data" / "evidence")


def test_the_project_root_itself_is_refused() -> None:
    """The project root is never a valid evidence root."""
    from app.core.config import _project_root

    with pytest.raises(ValueError, match="project tree"):
        validate_evidence_root(_project_root())


def test_a_safe_root_is_accepted(tmp_path: Path) -> None:
    """An ordinary directory is a valid evidence root."""
    resolved = validate_evidence_root(tmp_path / "evidence")

    assert resolved == (tmp_path / "evidence").resolve()


def test_the_default_root_is_outside_the_project_tree() -> None:
    """The default never points into the repository."""
    from app.core.config import _project_root

    default = default_evidence_root().resolve()
    project = _project_root().resolve()

    assert not default.is_relative_to(project)


def test_xdg_data_home_is_honoured(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """XDG_DATA_HOME changes the default root."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    default = default_evidence_root()

    assert default == tmp_path / "phishguard" / "evidence"


def test_the_settings_reject_a_dangerous_evidence_root() -> None:
    """The process refuses to start with an unsafe root."""
    with pytest.raises(ValueError, match="home directory"):
        Settings(
            _env_file=None,
            PHISHGUARD_SECRET_KEY="test-secret-key-value",
            PHISHGUARD_CORS_ORIGINS=[],
            PHISHGUARD_EVIDENCE_ROOT=str(Path.home()),
        )


def test_the_settings_accept_a_safe_evidence_root(tmp_path: Path) -> None:
    """An ordinary root is accepted."""
    settings = Settings(
        _env_file=None,
        PHISHGUARD_SECRET_KEY="test-secret-key-value",
        PHISHGUARD_CORS_ORIGINS=[],
        PHISHGUARD_EVIDENCE_ROOT=str(tmp_path / "evidence"),
    )

    assert settings.evidence_root == (tmp_path / "evidence").resolve()


# ---------------------------------------------------------------------------
# F-1: fresh-install directory creation
# ---------------------------------------------------------------------------


def test_a_fresh_nested_evidence_root_can_be_created_and_published(tmp_path: Path) -> None:
    """A write succeeds when the root and its application parents are absent.

    This is the regression for the default root shape:
    ``~/.local/share/phishguard/evidence``. The parent chain does not exist on
    a fresh install.
    """
    root = tmp_path / "fresh" / "phishguard" / "evidence"
    assert not root.exists()
    store = EvidenceStore(root, max_bytes=MAX_BYTES)

    _, published = _write(store, b"fresh install payload")

    assert store.read(published.storage_id) == b"fresh install payload"
    assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
    assert stat.S_IMODE((root / ".pending").stat().st_mode) == 0o700

    first, second, _ = published.storage_id.split("/")
    assert stat.S_IMODE((root / first).stat().st_mode) == 0o700
    assert stat.S_IMODE((root / first / second).stat().st_mode) == 0o700


def test_fresh_install_does_not_chmod_user_owned_ancestors(tmp_path: Path) -> None:
    """The store must not chmod a user-owned ancestor such as XDG_DATA_HOME."""
    xdg = tmp_path / "xdg-data-home"
    xdg.mkdir()
    original_mode = stat.S_IMODE(xdg.stat().st_mode)
    root = xdg / "phishguard" / "evidence"

    store = EvidenceStore(root, max_bytes=MAX_BYTES)
    _write(store, b"payload")

    assert stat.S_IMODE(xdg.stat().st_mode) == original_mode


# ---------------------------------------------------------------------------
# F-2: directory swap between validation and publication
# ---------------------------------------------------------------------------


def test_a_directory_swap_during_publication_cannot_escape_the_root(
    store: EvidenceStore, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Swapping <bb> for a symlink before os.link cannot redirect the write.

    The destination directory is held via an O_NOFOLLOW descriptor and the
    link is descriptor-relative, so the outside directory receives nothing.
    """
    outside = root.parent / "outside"
    outside.mkdir(exist_ok=True)
    writer = store.open()
    writer.write(b"payload")

    # Swap the validated <bb> directory to a symlink at the last possible
    # moment, right before the descriptor-relative link happens.
    first, second, _ = writer.storage_id.split("/")
    real_second = store.root / first / second
    real_link = os.link

    def swap_then_link(*args, **kwargs):
        real_second.rmdir()
        real_second.symlink_to(outside, target_is_directory=True)
        return real_link(*args, **kwargs)

    monkeypatch.setattr(os, "link", swap_then_link)

    with pytest.raises(OSError):
        writer.publish()

    # The outside directory receives nothing. The descriptor-relative link is
    # anchored to the validated inode; removing that directory makes the link
    # fail rather than follow the new symlink.
    assert list(outside.iterdir()) == []


# ---------------------------------------------------------------------------
# F-3: no-overwrite publication under a race
# ---------------------------------------------------------------------------


def test_a_destination_appearing_during_publication_is_not_overwritten(
    store: EvidenceStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file created just before os.link makes publication fail safely."""
    writer = store.open()
    writer.write(b"new bytes")
    first, second, filename = writer.storage_id.split("/")
    destination = store.root / first / second / filename

    real_link = os.link

    def create_then_link(*args, **kwargs):
        destination.write_bytes(b"PRE-EXISTING EVIDENCE")
        return real_link(*args, **kwargs)

    monkeypatch.setattr(os, "link", create_then_link)

    with pytest.raises(EvidenceError, match="already exists"):
        writer.publish()

    assert destination.read_bytes() == b"PRE-EXISTING EVIDENCE"


# ---------------------------------------------------------------------------
# F-4: symlink swap between validation and open
# ---------------------------------------------------------------------------


def test_a_symlink_swap_during_read_cannot_leak_outside_bytes(
    store: EvidenceStore, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file swapped to a symlink before open cannot redirect the read."""
    _, published = _write(store, b"real evidence")
    secret = root.parent / "secret.txt"
    secret.write_bytes(b"SECRET-OUTSIDE-ROOT")

    real_open = EvidenceStore._open_file_nofollow.__func__

    def swap_then_open(cls, path):
        path.unlink()
        path.symlink_to(secret)
        return real_open(cls, path)

    monkeypatch.setattr(EvidenceStore, "_open_file_nofollow", classmethod(swap_then_open))

    with pytest.raises(EvidenceNotFoundError):
        store.read(published.storage_id)


def test_a_symlink_swap_during_verify_cannot_hash_outside_bytes(
    store: EvidenceStore, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file swapped to a symlink before open cannot redirect verification."""
    _, published = _write(store, b"real evidence")
    secret = root.parent / "secret.txt"
    secret.write_bytes(b"SECRET-OUTSIDE-ROOT")
    secret_digest = hashlib.sha256(b"SECRET-OUTSIDE-ROOT").hexdigest()

    real_open = EvidenceStore._open_file_nofollow.__func__

    def swap_then_open(cls, path):
        path.unlink()
        path.symlink_to(secret)
        return real_open(cls, path)

    monkeypatch.setattr(EvidenceStore, "_open_file_nofollow", classmethod(swap_then_open))

    with pytest.raises(EvidenceNotFoundError):
        store.verify(published.storage_id, secret_digest)


# ---------------------------------------------------------------------------
# F-5: directory swap between lstat and chmod
# ---------------------------------------------------------------------------


def test_a_directory_swap_during_chmod_cannot_change_an_outside_target(
    store: EvidenceStore, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory swapped to a symlink inside _fchmod_dir is refused.

    fchmod is applied through an O_NOFOLLOW descriptor, so the outside target
    keeps its original mode and the operation raises.
    """
    outside = root.parent / "outside-dir"
    outside.mkdir(exist_ok=True)
    original_mode = stat.S_IMODE(outside.stat().st_mode)

    first = store.root / "ab"
    first.mkdir(parents=True, exist_ok=True)

    real_open = EvidenceStore.__dict__["_open_dir"]

    def swap_then_open(directory):
        if directory == first:
            directory.rmdir()
            directory.symlink_to(outside, target_is_directory=True)
        return real_open(directory)

    monkeypatch.setattr(EvidenceStore, "_open_dir", staticmethod(swap_then_open))

    with pytest.raises(OSError):
        store._ensure_dir(first)

    assert stat.S_IMODE(outside.stat().st_mode) == original_mode
