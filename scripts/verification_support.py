"""Bounded deterministic support for repository verification scripts."""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

MAX_TRUSTED_PATH_COMPONENTS = 64


class FileSizeLimitExceeded(ValueError):
    """A verification file exceeded its explicit read bound."""


class BoundedDiagnostics:
    """Count every mismatch while retaining only a finite deterministic sample."""

    def __init__(self, maximum_retained: int) -> None:
        if maximum_retained < 1:
            raise ValueError("maximum_retained must be positive")
        self._maximum_retained = maximum_retained
        self._messages: list[str] = []
        self._total = 0

    def add(self, message: str) -> None:
        self._total += 1
        if len(self._messages) < self._maximum_retained:
            self._messages.append(message)

    def extend(self, messages: Iterable[str]) -> None:
        for message in messages:
            self.add(message)

    @property
    def has_errors(self) -> bool:
        return self._total != 0

    @property
    def total(self) -> int:
        return self._total

    def rendered(self) -> tuple[str, ...]:
        lines = [f"error: {message}" for message in self._messages]
        omitted = self._total - len(self._messages)
        if omitted:
            lines.append(f"error: {omitted} additional verification mismatch(es) omitted")
        return tuple(lines)

    def emit(self) -> None:
        for line in self.rendered():
            print(line, file=sys.stderr)


@dataclass(frozen=True)
class DiscoveryResult:
    """Bounded relative file paths and whether the complete tree was inspected."""

    paths: frozenset[str]
    complete: bool


def _same_observable_state(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare Unix identity or a portable metadata snapshot."""
    if os.name == "posix":
        return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)
    return (
        stat.S_IFMT(left.st_mode),
        left.st_size,
        left.st_mtime_ns,
    ) == (
        stat.S_IFMT(right.st_mode),
        right.st_size,
        right.st_mtime_ns,
    )


def _relative_parts(relative_path: Path, *, allow_empty: bool) -> tuple[str, ...]:
    if relative_path.is_absolute() or relative_path.anchor:
        raise OSError(f"verification path must be relative to its trusted root: {relative_path}")
    parts = tuple(part for part in relative_path.parts if part != ".")
    if any(part in {"", ".."} for part in parts):
        raise OSError(f"verification path escapes its trusted root: {relative_path}")
    if not parts and not allow_empty:
        raise OSError("verification file path must not be empty")
    if len(parts) > MAX_TRUSTED_PATH_COMPONENTS:
        raise OSError(
            f"verification path exceeds {MAX_TRUSTED_PATH_COMPONENTS} components"
        )
    return parts


def _validate_component_chain(
    trusted_root: Path,
    parts: tuple[str, ...],
    *,
    final_directory: bool,
) -> tuple[os.stat_result, ...]:
    snapshots = []
    current = trusted_root
    root_metadata = current.lstat()
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise OSError(f"trusted verification root must be a non-symlink directory: {trusted_root}")
    snapshots.append(root_metadata)
    for index, part in enumerate(parts):
        current = current / part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise OSError(f"verification path component must not be a symlink: {current}")
        is_final = index + 1 == len(parts)
        if not is_final or final_directory:
            if not stat.S_ISDIR(metadata.st_mode):
                raise OSError(f"verification directory component is not a directory: {current}")
        elif not stat.S_ISREG(metadata.st_mode):
            raise OSError(f"verification path is not a regular file: {current}")
        snapshots.append(metadata)
    return tuple(snapshots)


def _validate_unchanged(
    before: tuple[os.stat_result, ...],
    after: tuple[os.stat_result, ...],
    path: Path,
) -> None:
    if len(before) != len(after) or any(
        not _same_observable_state(left, right) for left, right in zip(before, after)
    ):
        raise OSError(f"verification path changed while being accessed: {path}")


def _can_use_anchored_unix_open() -> bool:
    return (
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
    )


def _read_file_bounded_anchored(
    trusted_root: Path,
    parts: tuple[str, ...],
    maximum_bytes: int,
) -> bytes:
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | close_on_exec | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | close_on_exec | os.O_NOFOLLOW
    descriptors: list[int] = []
    snapshots: list[os.stat_result] = []
    try:
        root_metadata = trusted_root.lstat()
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
            raise OSError(
                f"trusted verification root must be a non-symlink directory: {trusted_root}"
            )
        current = os.open(trusted_root, directory_flags)
        descriptors.append(current)
        opened_root = os.fstat(current)
        if not _same_observable_state(root_metadata, opened_root):
            raise OSError(f"trusted verification root changed while being opened: {trusted_root}")
        snapshots.append(opened_root)

        for part in parts[:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
            metadata = os.fstat(current)
            if not stat.S_ISDIR(metadata.st_mode):
                raise OSError(f"verification path component is not a directory: {part}")
            snapshots.append(metadata)

        file_name = parts[-1]
        descriptor = os.open(file_name, file_flags, dir_fd=current)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise OSError("verification path is not a regular file")
        snapshots.append(metadata)
        with os.fdopen(descriptor, "rb") as source:
            data = source.read(maximum_bytes + 1)

        final_metadata = os.stat(file_name, dir_fd=current, follow_symlinks=False)
        if not stat.S_ISREG(final_metadata.st_mode) or not _same_observable_state(
            metadata, final_metadata
        ):
            raise OSError("verification file changed while being read")

        reopened: list[int] = []
        try:
            reopened_current = os.open(trusted_root, directory_flags)
            reopened.append(reopened_current)
            post_snapshots = [os.fstat(reopened_current)]
            for part in parts[:-1]:
                reopened_current = os.open(part, directory_flags, dir_fd=reopened_current)
                reopened.append(reopened_current)
                post_snapshots.append(os.fstat(reopened_current))
            post_snapshots.append(
                os.stat(file_name, dir_fd=reopened_current, follow_symlinks=False)
            )
            _validate_unchanged(
                tuple(snapshots),
                tuple(post_snapshots),
                trusted_root.joinpath(*parts),
            )
        finally:
            for reopened_descriptor in reversed(reopened):
                os.close(reopened_descriptor)
    finally:
        for directory_descriptor in reversed(descriptors):
            os.close(directory_descriptor)

    if len(data) > maximum_bytes:
        raise FileSizeLimitExceeded(f"file exceeds {maximum_bytes} bytes")
    return data


def _read_file_bounded_portable(
    trusted_root: Path,
    parts: tuple[str, ...],
    maximum_bytes: int,
) -> bytes:
    path = trusted_root.joinpath(*parts)
    before = _validate_component_chain(trusted_root, parts, final_directory=False)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not _same_observable_state(
            before[-1], metadata
        ):
            raise OSError(f"verification path changed while being opened: {path}")
        source = os.fdopen(descriptor, "rb")
        descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    with source:
        data = source.read(maximum_bytes + 1)
    after = _validate_component_chain(trusted_root, parts, final_directory=False)
    _validate_unchanged(before, after, path)
    if len(data) > maximum_bytes:
        raise FileSizeLimitExceeded(f"file exceeds {maximum_bytes} bytes")
    return data


def read_file_bounded(trusted_root: Path, relative_path: Path, maximum_bytes: int) -> bytes:
    """Read a bounded canonical file beneath an explicit trusted root."""
    if maximum_bytes < 0:
        raise ValueError("maximum_bytes must not be negative")
    parts = _relative_parts(relative_path, allow_empty=False)
    if _can_use_anchored_unix_open():
        return _read_file_bounded_anchored(trusted_root, parts, maximum_bytes)
    return _read_file_bounded_portable(trusted_root, parts, maximum_bytes)


def discover_files(
    trusted_root: Path,
    relative_root: Path,
    include: Callable[[Path], bool],
    diagnostics: BoundedDiagnostics,
    *,
    maximum_entries: int,
    maximum_files: int,
    maximum_depth: int,
    label: str,
) -> DiscoveryResult:
    """Discover matching regular files without unbounded traversal or retention."""
    if maximum_entries < 1 or maximum_files < 1 or maximum_depth < 0:
        raise ValueError("discovery entry/file limits must be positive and depth non-negative")
    try:
        root_parts = _relative_parts(relative_root, allow_empty=True)
        root_snapshots = _validate_component_chain(
            trusted_root, root_parts, final_directory=True
        )
    except OSError as error:
        diagnostics.add(f"cannot inspect {label} root beneath {trusted_root}: {error}")
        return DiscoveryResult(frozenset(), False)
    root = trusted_root.joinpath(*root_parts)

    paths: set[str] = set()
    entries_seen = 0
    complete = True

    def scan(directory: Path, depth: int) -> bool:
        nonlocal entries_seen, complete
        try:
            before = directory.lstat()
        except OSError as error:
            diagnostics.add(f"cannot inspect {label} directory {directory}: {error}")
            complete = False
            return True
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            diagnostics.add(f"{label} directory changed or is not regular: {directory}")
            complete = False
            return True
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    entries_seen += 1
                    if entries_seen > maximum_entries:
                        diagnostics.add(
                            f"{label} discovery exceeded {maximum_entries} filesystem entries; additional entries omitted"
                        )
                        complete = False
                        return False
                    path = Path(entry.path)
                    relative = path.relative_to(root)
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError as error:
                        diagnostics.add(f"cannot inspect {label} entry {entry.path}: {error}")
                        complete = False
                        continue
                    if stat.S_ISLNK(metadata.st_mode):
                        diagnostics.add(
                            f"{label} verification path must not be a symlink: {relative.as_posix()}"
                        )
                        complete = False
                    elif stat.S_ISDIR(metadata.st_mode):
                        child_depth = depth + 1
                        if child_depth > maximum_depth:
                            diagnostics.add(
                                f"{label} discovery exceeded maximum depth {maximum_depth}: {relative.as_posix()}"
                            )
                            complete = False
                        elif not scan(path, child_depth):
                            return False
                    elif stat.S_ISREG(metadata.st_mode):
                        if include(relative):
                            if len(paths) >= maximum_files:
                                diagnostics.add(
                                    f"{label} discovery exceeded {maximum_files} matching files; additional files omitted"
                                )
                                complete = False
                                return False
                            paths.add(relative.as_posix())
                    else:
                        diagnostics.add(
                            f"{label} verification path is not a regular file or directory: {relative.as_posix()}"
                        )
                        complete = False
        except OSError as error:
            diagnostics.add(f"cannot read {label} directory {directory}: {error}")
            complete = False
            return True
        try:
            after = directory.lstat()
        except OSError as error:
            diagnostics.add(f"cannot re-inspect {label} directory {directory}: {error}")
            complete = False
            return True
        if (
            stat.S_ISLNK(after.st_mode)
            or not stat.S_ISDIR(after.st_mode)
            or not _same_observable_state(before, after)
        ):
            diagnostics.add(f"{label} directory changed while being scanned: {directory}")
            complete = False
        return True

    scan(root, 0)

    try:
        final_root_snapshots = _validate_component_chain(
            trusted_root, root_parts, final_directory=True
        )
        _validate_unchanged(root_snapshots, final_root_snapshots, root)
    except OSError as error:
        diagnostics.add(f"{label} root changed while being scanned: {error}")
        complete = False

    return DiscoveryResult(frozenset(paths), complete)
