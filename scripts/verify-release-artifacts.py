#!/usr/bin/env python3
"""Validate the exact files a release would upload, then prove they work.

Run against a directory of freshly built wheels. In order, it:

1. requires the directory to hold exactly the two intended wheels and
   nothing else (no sdist, no checksum file, no subdirectory, no symlink);
2. opens each wheel and checks its own METADATA: distribution name, a
   version that matches the filename and the other wheel, and the one
   dependency openhuntx-webguard is allowed to have, pinned to that same
   version of openhuntx-webguard-contracts;
3. checks the wheel contents against an allowlist (package modules and
   dist-info only), and that the webguard console script is declared;
4. installs openhuntx-webguard into a fresh virtual environment from those
   files only (no index), runs pip check, confirms the imports resolve
   inside that environment and not in this checkout, and drives the
   installed CLI through a synthetic local scan from a directory outside
   the repository;
5. confirms the files are byte-for-byte unchanged by all of that, and
   writes their SHA-256 checksums.

Stdlib only, so it runs the same locally, in the packaging CI job, and in
the publish workflow.
"""

from __future__ import annotations

import argparse
import email
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import venv
import zipfile
from dataclasses import dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_SERVER = REPOSITORY_ROOT / "examples" / "synthetic_target" / "server.py"

CONTRACTS = "openhuntx-webguard-contracts"
WEBGUARD = "openhuntx-webguard"
EXPECTED_DISTRIBUTIONS = (CONTRACTS, WEBGUARD)
IMPORT_ROOTS = {CONTRACTS: "webguard_contracts", WEBGUARD: "webguard_scanner"}
CONSOLE_SCRIPT = "webguard = webguard_scanner.cli:main"

WHEEL_FILENAME = re.compile(
    r"^(?P<name>[A-Za-z0-9_]+)-(?P<version>[0-9]+(?:\.[0-9]+)*)-py3-none-any\.whl$"
)
DIST_INFO_FILES = {"METADATA", "WHEEL", "RECORD", "top_level.txt", "entry_points.txt"}


class ReleaseCheckError(Exception):
    """A release artifact failed validation."""


@dataclass(frozen=True)
class WheelInfo:
    path: Path
    name: str
    version: str
    requires_dist: tuple[str, ...]


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_filename_prefix(distribution: str) -> str:
    return distribution.replace("-", "_")


def check_directory_contents(dist_dir: Path) -> dict[str, Path]:
    """Return {distribution: wheel path}, or raise unless dist_dir holds only the two wheels."""

    if dist_dir.is_symlink() or not dist_dir.is_dir():
        raise ReleaseCheckError(f"{dist_dir} is not a plain directory")

    found: dict[str, Path] = {}
    unexpected: list[str] = []
    for entry in sorted(dist_dir.iterdir(), key=lambda item: item.name):
        match = WHEEL_FILENAME.match(entry.name)
        distribution = None
        if match and entry.is_file() and not entry.is_symlink():
            for candidate in EXPECTED_DISTRIBUTIONS:
                if match["name"] == expected_filename_prefix(candidate):
                    distribution = candidate
        if distribution is None or distribution in found:
            unexpected.append(entry.name)
        else:
            found[distribution] = entry

    if unexpected:
        raise ReleaseCheckError(
            "unexpected entries in " f"{dist_dir}: {', '.join(unexpected)}"
        )
    missing = [name for name in EXPECTED_DISTRIBUTIONS if name not in found]
    if missing:
        raise ReleaseCheckError(f"missing wheel for: {', '.join(missing)}")
    return found


def read_wheel(distribution: str, path: Path) -> WheelInfo:
    prefix = expected_filename_prefix(distribution)
    filename_version = WHEEL_FILENAME.match(path.name)["version"]  # type: ignore[index]
    package_root = IMPORT_ROOTS[distribution]
    dist_info = f"{prefix}-{filename_version}.dist-info"

    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise ReleaseCheckError(f"{path.name} is not a valid wheel archive") from exc

    with archive:
        bad_member = archive.testzip()
        if bad_member is not None:
            raise ReleaseCheckError(f"{path.name} has a corrupt member: {bad_member}")
        names = archive.namelist()

        for member in names:
            parts = member.split("/")
            if member.startswith("/") or ".." in parts:
                raise ReleaseCheckError(f"{path.name} contains unsafe path {member!r}")
            top = parts[0]
            if top == package_root:
                if not member.endswith(".py") or "__pycache__" in parts:
                    raise ReleaseCheckError(
                        f"{path.name} contains unexpected package file {member!r}"
                    )
            elif top == dist_info:
                inner = parts[1:]
                allowed = (len(inner) == 1 and inner[0] in DIST_INFO_FILES) or (
                    len(inner) >= 2 and inner[0] == "licenses"
                )
                if not allowed:
                    raise ReleaseCheckError(
                        f"{path.name} contains unexpected dist-info file {member!r}"
                    )
            else:
                raise ReleaseCheckError(
                    f"{path.name} contains content outside {package_root}/ "
                    f"and {dist_info}/: {member!r}"
                )

        metadata_name = f"{dist_info}/METADATA"
        if metadata_name not in names:
            raise ReleaseCheckError(f"{path.name} has no {metadata_name}")
        metadata = email.message_from_string(
            archive.read(metadata_name).decode("utf-8")
        )
        entry_points = (
            archive.read(f"{dist_info}/entry_points.txt").decode("utf-8")
            if f"{dist_info}/entry_points.txt" in names
            else ""
        )

    if normalize(metadata.get("Name", "")) != normalize(distribution):
        raise ReleaseCheckError(
            f"{path.name}: METADATA Name is {metadata.get('Name')!r}, "
            f"expected {distribution!r}"
        )
    if metadata.get("Version") != filename_version:
        raise ReleaseCheckError(
            f"{path.name}: METADATA Version {metadata.get('Version')!r} does "
            f"not match the filename version {filename_version!r}"
        )
    if not metadata.get("Requires-Python"):
        raise ReleaseCheckError(f"{path.name}: METADATA has no Requires-Python")

    console_scripts = [line.strip() for line in entry_points.splitlines() if "=" in line]
    if distribution == WEBGUARD and console_scripts != [CONSOLE_SCRIPT]:
        raise ReleaseCheckError(
            f"{path.name}: console scripts are {console_scripts!r}, "
            f"expected exactly [{CONSOLE_SCRIPT!r}]"
        )
    if distribution == CONTRACTS and console_scripts:
        raise ReleaseCheckError(f"{path.name}: unexpected console scripts")

    return WheelInfo(
        path=path,
        name=normalize(distribution),
        version=filename_version,
        requires_dist=tuple(metadata.get_all("Requires-Dist") or ()),
    )


def validate_distributions(dist_dir: Path) -> dict[str, WheelInfo]:
    found = check_directory_contents(dist_dir)
    infos = {name: read_wheel(name, path) for name, path in found.items()}

    versions = {info.version for info in infos.values()}
    if len(versions) != 1:
        raise ReleaseCheckError(
            "the two wheels disagree on version: "
            + ", ".join(f"{name}={info.version}" for name, info in infos.items())
        )
    version = versions.pop()

    if infos[CONTRACTS].requires_dist:
        raise ReleaseCheckError(
            f"{CONTRACTS} must have no dependencies, found {infos[CONTRACTS].requires_dist!r}"
        )
    pins = [re.sub(r"\s+", "", requirement) for requirement in infos[WEBGUARD].requires_dist]
    if pins != [f"{CONTRACTS}=={version}"]:
        raise ReleaseCheckError(
            f"{WEBGUARD} must depend on exactly {CONTRACTS}=={version}, "
            f"found {infos[WEBGUARD].requires_dist!r}"
        )
    return infos


def snapshot(dist_dir: Path) -> dict[str, str]:
    return {entry.name: sha256_of(entry) for entry in sorted(dist_dir.iterdir())}


def run(
    command: list[str], *, cwd: Path, env: dict[str, str], check: bool = True
) -> subprocess.CompletedProcess[str]:
    print(f"$ {' '.join(command)}", flush=True)
    result = subprocess.run(  # noqa: S603 - fixed argument vectors, no shell
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(result.stderr, end="" if result.stderr.endswith("\n") else "\n", file=sys.stderr)
    if check and result.returncode != 0:
        raise ReleaseCheckError(f"command failed ({result.returncode}): {' '.join(command)}")
    return result


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for_port(port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise ReleaseCheckError("the synthetic target server did not start")


def clean_environment() -> dict[str, str]:
    keep = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def install_and_smoke_test(dist_dir: Path, version: str) -> None:
    with tempfile.TemporaryDirectory(prefix="webguard-release-check-") as scratch_name:
        scratch = Path(scratch_name)
        environment_dir = scratch / "venv"
        workdir = scratch / "work"
        workdir.mkdir()
        venv.EnvBuilder(with_pip=True).create(environment_dir)
        bin_dir = environment_dir / ("Scripts" if os.name == "nt" else "bin")
        python = str(bin_dir / "python")
        webguard = str(bin_dir / "webguard")
        env = clean_environment()

        run(
            [
                python, "-m", "pip", "install", "--isolated", "--no-index",
                "--find-links", str(dist_dir), f"{WEBGUARD}=={version}",
            ],
            cwd=workdir,
            env=env,
        )
        run([python, "-m", "pip", "check"], cwd=workdir, env=env)

        located = run(
            [
                python, "-c",
                "import webguard_contracts, webguard_scanner; "
                "print(webguard_contracts.__file__); print(webguard_scanner.__file__); "
                "print(webguard_contracts.__version__); print(webguard_scanner.__version__)",
            ],
            cwd=workdir,
            env=env,
        ).stdout.split()
        for module_path in located[:2]:
            if not Path(module_path).resolve().is_relative_to(environment_dir.resolve()):
                raise ReleaseCheckError(
                    f"{module_path} was imported from outside the clean environment"
                )
        if located[2:] != [version, version]:
            raise ReleaseCheckError(
                f"packages report __version__ {located[2:]} but the wheels are {version}"
            )

        reported = run([webguard, "--version"], cwd=workdir, env=env).stdout.strip()
        if reported != f"webguard {version}":
            raise ReleaseCheckError(
                f"`webguard --version` printed {reported!r}, expected 'webguard {version}'"
            )
        run([webguard, "doctor", "--directory", str(workdir)], cwd=workdir, env=env)
        run([webguard, "init", "--directory", str(workdir)], cwd=workdir, env=env)

        port = free_port()
        server = subprocess.Popen(  # noqa: S603 - fixed argument vector, no shell
            [sys.executable, str(SYNTHETIC_SERVER), str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wait_for_port(port)
            scan = run(
                [
                    webguard, "scan", f"http://127.0.0.1:{port}/", "--lab",
                    "--allow-host", "127.0.0.1", "--output", "scan-results/release-check.json",
                ],
                cwd=workdir,
                env=env,
            )
        finally:
            server.terminate()
            server.wait(timeout=10)

        for expected in ("Status: completed", "web.headers.csp.missing"):
            if expected not in scan.stdout:
                raise ReleaseCheckError(f"scan output did not contain {expected!r}")

        listing = run(
            [webguard, "results", "list", "--json"], cwd=workdir, env=env
        ).stdout
        rows = json.loads(listing)
        if len(rows) != 1 or not rows[0]["readable"]:
            raise ReleaseCheckError(f"results list returned {rows!r}")
        run(
            [
                webguard, "report", "render", "scan-results/release-check.json",
                "--output", "reports/release-check.html", "--organization", "Release check",
            ],
            cwd=workdir,
            env=env,
        )
        if not (workdir / "reports" / "release-check.html").is_file():
            raise ReleaseCheckError("report render did not write its HTML file")
        run([webguard, "results", "clean", "--yes"], cwd=workdir, env=env)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--checksums-out", type=Path, required=True)
    parser.add_argument(
        "--github-output",
        type=Path,
        help="Append version and per-wheel SHA-256 as GitHub Actions step outputs.",
    )
    args = parser.parse_args(argv)

    try:
        infos = validate_distributions(args.dist)
        version = infos[WEBGUARD].version
        before = snapshot(args.dist)
        print(f"Validated {len(infos)} distributions at version {version}.")

        # pip and the CLI run from a scratch directory, so a relative --dist
        # must be made absolute before they see it.
        install_and_smoke_test(args.dist.resolve(), version)

        if snapshot(args.dist) != before:
            raise ReleaseCheckError("the artifacts changed while they were being tested")
    except ReleaseCheckError as exc:
        print(f"Release artifact check failed: {exc}", file=sys.stderr)
        return 1

    args.checksums_out.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(before.items())),
        encoding="utf-8",
    )
    print(args.checksums_out.read_text(encoding="utf-8"), end="")

    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(f"version={version}\n")
            for distribution, info in infos.items():
                key = IMPORT_ROOTS[distribution].removeprefix("webguard_")
                handle.write(f"{key}_sha256={before[info.path.name]}\n")

    print("Release artifact check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
