#!/usr/bin/env python3
"""Checks the publish jobs run around the PyPI upload step.

Three subcommands, all stdlib only:

stage   Verify the downloaded release artifact (exact file listing, the
        SHA256SUMS manifest, and the checksums the build job reported through
        its job outputs) and copy only the one wheel this job is responsible
        for into an otherwise empty directory.

plan    Ask PyPI what it has for one project and version. Prints "absent"
        when nothing is there. Prints "verified" when PyPI holds exactly the
        expected filename with exactly the expected SHA-256 and no other
        file. Anything else (a different hash, an extra or missing file, an
        unexpected HTTP status, a network error) is an error: the release
        stops, and nothing is ever uploaded over an existing file.

await   Like plan, but polls until PyPI reports the file as verified, to
        cover the delay between an upload finishing and the JSON API
        showing it.

A file already on PyPI counts as done only through the "verified" state.
Nothing here uses --skip-existing semantics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

CONTRACTS_PROJECT = "openhuntx-webguard-contracts"
WEBGUARD_PROJECT = "openhuntx-webguard"
PROJECTS = {"contracts": CONTRACTS_PROJECT, "webguard": WEBGUARD_PROJECT}

WHEEL = re.compile(
    r"^(?P<name>openhuntx_webguard(?:_contracts)?)-(?P<version>[0-9]+(?:\.[0-9]+)*)-py3-none-any\.whl$"
)
MANIFEST_LINE = re.compile(r"^(?P<digest>[0-9a-f]{64})  (?P<name>[^/\s]+)$")

Fetch = Callable[[str], "tuple[int, bytes]"]


class ReleaseStateError(Exception):
    """The release must stop."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_manifest(release_dir: Path) -> dict[str, tuple[str, str]]:
    """Return {"contracts"|"webguard": (filename, sha256)} from SHA256SUMS."""

    manifest = release_dir / "SHA256SUMS"
    entries: dict[str, tuple[str, str]] = {}
    lines = manifest.read_text(encoding="utf-8").splitlines()
    if len(lines) != 2:
        raise ReleaseStateError(f"SHA256SUMS must have exactly 2 lines, found {len(lines)}")
    versions = set()
    for line in lines:
        match = MANIFEST_LINE.match(line)
        wheel = WHEEL.match(match["name"]) if match else None
        if not match or not wheel:
            raise ReleaseStateError(f"unexpected SHA256SUMS line: {line!r}")
        kind = "contracts" if wheel["name"].endswith("_contracts") else "webguard"
        if kind in entries:
            raise ReleaseStateError(f"SHA256SUMS lists {kind} twice")
        entries[kind] = (match["name"], match["digest"])
        versions.add(wheel["version"])
    if set(entries) != set(PROJECTS) or len(versions) != 1:
        raise ReleaseStateError("SHA256SUMS must list one contracts wheel and one webguard wheel at one version")
    return entries


def stage(
    release_dir: Path,
    distribution: str,
    stage_dir: Path,
    *,
    expect_version: str,
    expect_contracts_sha256: str,
    expect_webguard_sha256: str,
) -> dict[str, str]:
    entries = read_manifest(release_dir)
    version = WHEEL.match(entries["webguard"][0])["version"]  # type: ignore[index]
    if version != expect_version:
        raise ReleaseStateError(f"artifact version {version} differs from the build job's {expect_version}")

    expected_listing = sorted(
        ["SHA256SUMS", "dist", *(f"dist/{name}" for name, _ in entries.values())]
    )
    actual_listing = sorted(
        path.relative_to(release_dir).as_posix() for path in release_dir.rglob("*")
    )
    if actual_listing != expected_listing:
        raise ReleaseStateError(f"unexpected artifact contents: {actual_listing}")

    for kind, (name, digest) in entries.items():
        path = release_dir / "dist" / name
        if path.is_symlink() or not path.is_file():
            raise ReleaseStateError(f"{name} is not a regular file")
        if sha256_of(path) != digest:
            raise ReleaseStateError(f"{name} does not match SHA256SUMS")
    if entries["contracts"][1] != expect_contracts_sha256:
        raise ReleaseStateError("contracts checksum differs from the build job's output")
    if entries["webguard"][1] != expect_webguard_sha256:
        raise ReleaseStateError("webguard checksum differs from the build job's output")

    if stage_dir.exists() and any(stage_dir.iterdir()):
        raise ReleaseStateError(f"{stage_dir} is not empty")
    stage_dir.mkdir(parents=True, exist_ok=True)
    name, digest = entries[distribution]
    shutil.copyfile(release_dir / "dist" / name, stage_dir / name)
    if sha256_of(stage_dir / name) != digest or [p.name for p in stage_dir.iterdir()] != [name]:
        raise ReleaseStateError("the staged copy does not match the verified file")

    return {
        "version": version,
        "filename": name,
        "sha256": digest,
        "contracts_filename": entries["contracts"][0],
        "contracts_sha256": entries["contracts"][1],
    }


def fetch_pypi(url: str) -> tuple[int, bytes]:
    request = urllib.request.Request(url, headers={"User-Agent": "openhuntx-release-check"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - https URL built below
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, b""
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ReleaseStateError(f"could not reach PyPI: {error}") from error


def classify(project: str, version: str, filename: str, sha256: str, fetch: Fetch = fetch_pypi) -> str:
    """Return "absent" or "verified"; raise ReleaseStateError for anything else."""

    status, body = fetch(f"https://pypi.org/pypi/{project}/{version}/json")
    if status == 404:
        return "absent"
    if status != 200:
        raise ReleaseStateError(f"PyPI answered HTTP {status} for {project} {version}; refusing to guess")
    try:
        files = json.loads(body)["urls"]
    except (ValueError, KeyError, TypeError) as error:
        raise ReleaseStateError(f"PyPI returned an unreadable record for {project} {version}") from error
    if not isinstance(files, list) or not all(isinstance(entry, dict) for entry in files):
        raise ReleaseStateError(f"PyPI returned an unreadable record for {project} {version}")

    published = {entry.get("filename"): entry for entry in files}
    extra = sorted(name for name in published if name != filename)
    if extra:
        raise ReleaseStateError(f"{project} {version} on PyPI has unexpected files: {extra}")
    if filename not in published:
        raise ReleaseStateError(f"{project} {version} exists on PyPI without {filename}")
    remote = (published[filename].get("digests") or {}).get("sha256")
    if remote != sha256:
        raise ReleaseStateError(
            f"{filename} on PyPI has sha256 {remote}, expected {sha256}. "
            "A published file cannot be replaced; stop and choose a new version."
        )
    return "verified"


def await_verified(
    project: str,
    version: str,
    filename: str,
    sha256: str,
    *,
    timeout: float,
    interval: float,
    fetch: Fetch = fetch_pypi,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    deadline = clock() + timeout
    while True:
        if classify(project, version, filename, sha256, fetch) == "verified":
            return
        if clock() >= deadline:
            raise ReleaseStateError(f"{filename} did not appear on PyPI within {timeout:.0f}s")
        sleep(interval)


def write_outputs(path: Path | None, values: dict[str, str]) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)

    stage_parser = commands.add_parser("stage")
    stage_parser.add_argument("--release-dir", type=Path, required=True)
    stage_parser.add_argument("--distribution", choices=sorted(PROJECTS), required=True)
    stage_parser.add_argument("--stage-dir", type=Path, required=True)
    stage_parser.add_argument("--expect-version", required=True)
    stage_parser.add_argument("--expect-contracts-sha256", required=True)
    stage_parser.add_argument("--expect-webguard-sha256", required=True)

    for name in ("plan", "await"):
        sub = commands.add_parser(name)
        sub.add_argument("--project", choices=sorted(PROJECTS.values()), required=True)
        sub.add_argument("--version", required=True)
        sub.add_argument("--filename", required=True)
        sub.add_argument("--sha256", required=True)
        if name == "await":
            sub.add_argument("--timeout", type=float, default=300.0)
            sub.add_argument("--interval", type=float, default=10.0)

    for sub in commands.choices.values():
        sub.add_argument("--github-output", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "stage":
            values = stage(
                args.release_dir,
                args.distribution,
                args.stage_dir,
                expect_version=args.expect_version,
                expect_contracts_sha256=args.expect_contracts_sha256,
                expect_webguard_sha256=args.expect_webguard_sha256,
            )
            print(f"Staged {values['filename']} ({values['sha256']}) in {args.stage_dir}")
            write_outputs(args.github_output, values)
        elif args.command == "plan":
            state = classify(args.project, args.version, args.filename, args.sha256)
            print(f"{args.project} {args.version}: {state}")
            write_outputs(args.github_output, {"state": state})
        else:
            await_verified(
                args.project, args.version, args.filename, args.sha256,
                timeout=args.timeout, interval=args.interval,
            )
            print(f"{args.project} {args.version}: verified on PyPI")
    except ReleaseStateError as error:
        print(f"release-publish: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
