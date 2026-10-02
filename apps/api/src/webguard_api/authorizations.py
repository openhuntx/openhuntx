"""Server-side owned-target authorization lookup."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from webguard_contracts import (
    OwnedTargetAuthorization,
    OwnedTargetContractError,
    load_owned_target_authorization_file,
)


MAXIMUM_AUTHORIZATION_FILES = 1000


class AuthorizationRepositoryError(ValueError):
    """Controlled authorization repository failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class AuthorizationRepository:
    """Read validated authorizations from one private local directory."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory).expanduser()

    def _entries(self) -> tuple[Path, ...]:
        try:
            metadata = self.directory.lstat()
        except OSError as exc:
            raise AuthorizationRepositoryError(
                "authorization_directory_unavailable",
                "Unable to inspect the authorization directory.",
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise AuthorizationRepositoryError(
                "authorization_directory_symlink_not_allowed",
                "Authorization directory cannot be a symbolic link.",
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise AuthorizationRepositoryError(
                "authorization_directory_invalid",
                "Authorization path must be a directory.",
            )
        try:
            entries = tuple(
                sorted(
                    (
                        path
                        for path in self.directory.iterdir()
                        if path.name.endswith(".json")
                    ),
                    key=lambda path: path.name,
                )
            )
        except OSError as exc:
            raise AuthorizationRepositoryError(
                "authorization_directory_read_failed",
                "Unable to enumerate authorization documents.",
            ) from exc
        if len(entries) > MAXIMUM_AUTHORIZATION_FILES:
            raise AuthorizationRepositoryError(
                "authorization_repository_too_large",
                "Authorization directory exceeds the 1000-document limit.",
            )
        return entries

    def get(self, authorization_id: str) -> OwnedTargetAuthorization:
        # Every tenant's authorization document lives in this one shared
        # directory (tenant scoping happens one layer up, by matching the
        # authorization's own organization field); _entries() enumerates
        # all of them, sorted by filename, regardless of which tenant's
        # authorization_id this call is actually looking for. A message
        # naming this directory, another tenant's filename, or another
        # tenant's own validation-error text (which can itself embed that
        # tenant's canonical target URL) would disclose it to a caller
        # whose own lookup had nothing to do with that file, purely
        # because that file happened to sort earlier and fail first.
        # Every error below keeps its stable code but drops that detail.
        matches: list[OwnedTargetAuthorization] = []
        for path in self._entries():
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise AuthorizationRepositoryError(
                    "authorization_file_inspection_failed",
                    "Unable to inspect an authorization document.",
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise AuthorizationRepositoryError(
                    "authorization_file_symlink_not_allowed",
                    "An authorization document cannot be a symbolic link.",
                )
            if not stat.S_ISREG(metadata.st_mode):
                continue
            if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise AuthorizationRepositoryError(
                    "authorization_file_permissions_insecure",
                    "An authorization document must use owner-only permissions.",
                )
            try:
                authorization = load_owned_target_authorization_file(path)
            except OwnedTargetContractError as exc:
                raise AuthorizationRepositoryError(
                    exc.code,
                    "An authorization document is invalid.",
                ) from exc
            if authorization.authorization_id == authorization_id:
                matches.append(authorization)
        if not matches:
            raise AuthorizationRepositoryError(
                "authorization_not_found",
                "No server-side authorization matches the requested authorization ID.",
            )
        if len(matches) > 1:
            raise AuthorizationRepositoryError(
                "authorization_duplicate_id",
                "Multiple authorization documents use the same authorization ID.",
            )
        return matches[0]


__all__ = [
    "MAXIMUM_AUTHORIZATION_FILES",
    "AuthorizationRepository",
    "AuthorizationRepositoryError",
]
