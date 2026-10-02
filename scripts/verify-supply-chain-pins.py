#!/usr/bin/env python3
"""Fail closed when reviewed CI/dependency pins drift."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED = {
    "pip": "26.2.1",
    "setuptools": "83.0.0",
    "cryptography": "50.0.0",
    "cffi": "2.1.0",
    "pycparser": "3.0",
    "ruff": "0.16.2",
    "psycopg": "3.2.10",
    "psycopg-binary": "3.2.10",
    "psycopg-pool": "3.2.6",
    "typing-extensions": "4.15.0",
    "argon2-cffi": "25.1.0",
    "argon2-cffi-bindings": "26.1.0",
    "dnspython": "2.8.0",
}

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "ece7cb06caefa5fff74198d8649806c4678c61a1"
SETUP_NODE_SHA = "820762786026740c76f36085b0efc47a31fe5020"  # v7.0.0
UPLOAD_ARTIFACT_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"  # v7.0.1
SETUP_TERRAFORM_SHA = "dfe3c3f87815947d99a8997f908cb6525fc44e9e"  # v4.0.1
PYPI_PUBLISH_SHA = "dc37677b2e1c63e2034f94d8a5b11f265b73ba33"  # release/v1, v1.14.2
DOWNLOAD_ARTIFACT_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"  # v8.0.1
TRIVY_VERSION = "0.74.0"
TRIVY_LINUX_AMD64_SHA256 = (
    "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
)

EXPECTED_PYTHON_VERSIONS = ("3.11.15", "3.12.13", "3.13.14", "3.14.6")
EXPECTED_PYTHON_REQUIRES = ">=3.11,<3.15"
EXPECTED_RUNNER = "ubuntu-24.04"
JUICE_SHOP_INDEX_DIGEST = (
    "sha256:cd58d79c5cb4d82f22fbaf616f9ff43bbd04ba630cd6b448a9ed99cf652fcebf"
)
RUFF_WHEEL_HASHES = {
    "ab3d62dde0b19facdd632008cc4827fc28ada7736c6bd35ab6f1050f0bfed53f",
    "a2c0d14fcbb26c91f0f867a6dc9bd71bbc30b1b6151829c884f23faeab2e5700",
}


def fail(message: str) -> None:
    raise SystemExit(f"Supply-chain pin verification failed: {message}")


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def logical_requirements(path: str) -> list[str]:
    records: list[str] = []
    current = ""
    for raw in read(path).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        continuation = line.endswith("\\")
        if continuation:
            line = line[:-1].rstrip()
        current = f"{current} {line}".strip()
        if not continuation:
            records.append(current)
            current = ""
    if current:
        fail(f"unterminated continuation in {path}")
    return records


def parse_locked(path: str) -> dict[str, tuple[str, tuple[str, ...]]]:
    parsed: dict[str, tuple[str, tuple[str, ...]]] = {}
    for record in logical_requirements(path):
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s]+)(?:\s+(.+))?$", record)
        if not match:
            fail(f"{path} contains a non-exact requirement: {record}")
        name, version, options = match.groups()
        hashes = tuple(re.findall(r"--hash=sha256:([0-9a-f]{64})", options or ""))
        if not hashes:
            fail(f"{path} requirement {name} has no SHA-256 hash")
        parsed[name.lower()] = (version, hashes)
    return parsed


bootstrap = parse_locked("requirements-bootstrap.lock")
if set(bootstrap) != {"pip"} or bootstrap["pip"][0] != EXPECTED["pip"]:
    fail("bootstrap lock does not contain only the reviewed pip version")

locked = parse_locked("requirements-ci.lock")
expected_runtime = {
    "setuptools",
    "cryptography",
    "cffi",
    "pycparser",
    "psycopg",
    "psycopg-binary",
    "psycopg-pool",
    "typing-extensions",
    "argon2-cffi",
    "argon2-cffi-bindings",
    "dnspython",
}
if set(locked) != expected_runtime:
    fail(f"runtime lock package set changed: {sorted(locked)}")
for name in expected_runtime:
    if locked[name][0] != EXPECTED[name]:
        fail(f"{name} lock version is {locked[name][0]}, expected {EXPECTED[name]}")

security_locked = parse_locked("requirements-security.lock")
if set(security_locked) != {"ruff"}:
    fail(f"security lock package set changed: {sorted(security_locked)}")
if security_locked["ruff"][0] != EXPECTED["ruff"]:
    fail(
        f"ruff lock version is {security_locked['ruff'][0]}, expected {EXPECTED['ruff']}"
    )
if set(security_locked["ruff"][1]) != RUFF_WHEEL_HASHES:
    fail("Ruff security-tool wheel hashes changed from the reviewed platform set")

for path in (
    "packages/contracts/python/pyproject.toml",
    "workers/scanner/pyproject.toml",
    "apps/api/pyproject.toml",
):
    with (ROOT / path).open("rb") as handle:
        document = tomllib.load(handle)
    requires = document["build-system"]["requires"]
    if requires != [f"setuptools=={EXPECTED['setuptools']}"]:
        fail(f"{path} build backend is not exactly pinned")
    if document["project"].get("requires-python") != EXPECTED_PYTHON_REQUIRES:
        fail(f"{path} Python support range is not {EXPECTED_PYTHON_REQUIRES}")

with (ROOT / "apps/api/pyproject.toml").open("rb") as handle:
    api = tomllib.load(handle)
if f"cryptography=={EXPECTED['cryptography']}" not in api["project"]["dependencies"]:
    fail("API cryptography dependency is not exactly pinned")
if f"psycopg[binary]=={EXPECTED['psycopg']}" not in api["project"]["dependencies"]:
    fail("API psycopg dependency is not exactly pinned")
if f"psycopg-pool=={EXPECTED['psycopg-pool']}" not in api["project"]["dependencies"]:
    fail("API psycopg-pool dependency is not exactly pinned")
if f"argon2-cffi=={EXPECTED['argon2-cffi']}" not in api["project"]["dependencies"]:
    fail("API argon2-cffi dependency is not exactly pinned")
if f"dnspython=={EXPECTED['dnspython']}" not in api["project"]["dependencies"]:
    fail("API dnspython dependency is not exactly pinned")
if "version" in api["project"]:
    fail("API pyproject must not define a second static version authority")
if api["project"].get("dynamic") != ["version"]:
    fail("API pyproject must declare version as dynamic")
try:
    version_attr = api["tool"]["setuptools"]["dynamic"]["version"]["attr"]
except (KeyError, TypeError):
    fail("API setuptools dynamic version configuration is missing")
if version_attr != "webguard_api._version.__version__":
    fail("API package metadata does not use the canonical version module")
version_source = read("apps/api/src/webguard_api/_version.py")
version_matches = re.findall(r'^__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', version_source, re.MULTILINE)
if len(version_matches) != 1:
    fail("canonical API version module must contain exactly one semantic version literal")
api_init = read("apps/api/src/webguard_api/__init__.py")
if "from ._version import __version__" not in api_init:
    fail("API package does not re-export the canonical version")
if re.search(r'^__version__\s*=\s*', api_init, re.MULTILINE):
    fail("API package __init__ contains a duplicate version authority")

dev_records = logical_requirements("requirements-dev.txt")
if not dev_records or any(not record.startswith("-e ") for record in dev_records):
    fail("requirements-dev.txt must contain repository-local editable packages only")

workflow = read(".github/workflows/ci.yml")
if f"actions/checkout@{CHECKOUT_SHA}" not in workflow:
    fail("actions/checkout is not pinned to the reviewed immutable SHA")
if f"actions/setup-python@{SETUP_PYTHON_SHA}" not in workflow:
    fail("actions/setup-python is not pinned to the reviewed immutable SHA")
if re.search(r"uses:\s+actions/(?:checkout|setup-python)@v", workflow):
    fail("a moving GitHub Action major-version tag remains in CI")
# Slice 18 added terraform, frontend, and frontend-e2e to the original
# four jobs (unit-tests, security-gates, authorised-lab-integration,
# postgresql-integration). The CLI release pass added cli-packaging on
# top of that -- a deliberately reviewed count, bumped as part of this
# change rather than left silently unenforced.
if workflow.count(f"runs-on: {EXPECTED_RUNNER}") != 8:
    fail("CI runner count or reviewed Ubuntu runner pin changed")
if "runs-on: ubuntu-latest" in workflow:
    fail("CI still uses the moving ubuntu-latest runner label")
for version in EXPECTED_PYTHON_VERSIONS:
    if f'python-version: "{version}"' not in workflow and f'- "{version}"' not in workflow:
        fail(f"CI does not pin reviewed Python {version}")
for floating in ("3.11", "3.12", "3.13", "3.14"):
    if re.search(rf'python-version:\s+"{re.escape(floating)}"', workflow):
        fail(f"CI still uses floating Python {floating}")
    if re.search(rf'^\s*-\s+"{re.escape(floating)}"\s*$', workflow, re.MULTILINE):
        fail(f"CI matrix still uses floating Python {floating}")
if f'pip-version: "{EXPECTED["pip"]}"' not in workflow:
    fail("CI does not request the reviewed pip version")
if "./scripts/install-locked-dependencies.sh" not in workflow:
    fail("CI bypasses the locked dependency installer")
if "pip install --upgrade" in workflow:
    fail("CI still performs an unconstrained packaging-tool upgrade")

USES_LINE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)")


def uses_references(text: str) -> list[str]:
    """Every action reference in the workflow, whether on a `uses:` or `- uses:` line."""

    return [
        match[1]
        for line in text.splitlines()
        if not line.lstrip().startswith("#") and (match := USES_LINE.match(line))
    ]


uses_lines = uses_references(workflow)
reviewed_actions = {
    f"actions/checkout@{CHECKOUT_SHA}",
    f"actions/setup-python@{SETUP_PYTHON_SHA}",
    f"actions/setup-node@{SETUP_NODE_SHA}",
    f"actions/upload-artifact@{UPLOAD_ARTIFACT_SHA}",
    f"hashicorp/setup-terraform@{SETUP_TERRAFORM_SHA}",
}
for action_ref in uses_lines:
    if action_ref not in reviewed_actions:
        fail(f"CI uses an unreviewed GitHub Action: {action_ref}")

# publish.yml is manual-dispatch-only and cannot succeed without PyPI
# trusted-publisher setup. Its actions go through the same reviewed-SHA
# discipline as ci.yml, and its structure is checked job by job so that a
# later edit cannot quietly widen who holds the OIDC publishing permission,
# let a dry run upload, or point both projects at the same environment.
publish_workflow = read(".github/workflows/publish.yml")
publish_reviewed_actions = reviewed_actions | {
    f"pypa/gh-action-pypi-publish@{PYPI_PUBLISH_SHA}",
    f"actions/download-artifact@{DOWNLOAD_ARTIFACT_SHA}",
}
for action_ref in uses_references(publish_workflow):
    if action_ref not in publish_reviewed_actions:
        fail(f"publish.yml uses an unreviewed GitHub Action: {action_ref}")

# Structural checks look at active YAML only, so prose in comments (which
# does mention id-token and the triggers) cannot satisfy or trip them.
publish_active = "\n".join(
    line for line in publish_workflow.splitlines() if not line.lstrip().startswith("#")
)
if re.search(r"\b(write-all|read-all)\b", publish_active):
    fail("publish.yml must not use write-all or read-all permissions")

trigger_block = publish_active.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
if re.findall(r"^  (\w+):", trigger_block, re.MULTILINE) != ["workflow_dispatch"]:
    fail("publish.yml must be triggered by workflow_dispatch only")
mode_lines = publish_active.splitlines()
for required in ("          - dry-run", "          - publish", "        default: dry-run"):
    if required not in mode_lines:
        fail(f"publish.yml's mode input must contain the line {required.strip()!r}")
if re.search(r"^          - (?!dry-run$|publish$)\S", trigger_block, re.MULTILINE):
    fail("publish.yml's mode input must offer exactly dry-run and publish")

top_permissions = publish_active.split("\npermissions:\n", 1)[1].split("\n\n", 1)[0]
if top_permissions != "  contents: read":
    fail("publish.yml's workflow-level permissions must be exactly contents: read")

jobs_section = publish_active.split("\njobs:\n", 1)[1]
job_starts = list(re.finditer(r"^  ([A-Za-z0-9_-]+):\s*$", jobs_section, re.MULTILINE))
publish_jobs = {
    match[1]: jobs_section[match.end() : job_starts[i + 1].start() if i + 1 < len(job_starts) else len(jobs_section)]
    for i, match in enumerate(job_starts)
}
if set(publish_jobs) != {"build-and-verify", "publish-contracts", "publish-webguard"}:
    fail(f"publish.yml must have exactly the build, contracts, and webguard jobs, found {sorted(publish_jobs)}")


def job_lines(name: str) -> list[str]:
    return publish_jobs[name].splitlines()


def block_after(lines: list[str], header: str) -> list[str]:
    """The lines indented deeper than `header`, up to the next line that is not."""

    start = lines.index(header) + 1
    block = []
    for line in lines[start:]:
        if not line.startswith(header[: len(header) - len(header.lstrip())] + "  "):
            break
        block.append(line)
    return block


def require_job_line(name: str, line: str, why: str) -> None:
    if line not in job_lines(name):
        fail(f"publish.yml job {name}: {why} (expected the line {line.strip()!r})")


build_job = publish_jobs["build-and-verify"]
require_job_line("build-and-verify", "    if: github.ref == 'refs/heads/main'", "the build job must only run from main")
if "id-token" in build_job or "environment:" in build_job:
    fail("publish.yml's build job must have no id-token permission and no environment")
if block_after(job_lines("build-and-verify"), "    permissions:") != ["      contents: read"]:
    fail("publish.yml's build job permissions must be exactly contents: read")
if "scripts/verify-release-artifacts.py" not in build_job:
    fail("publish.yml's build job must run the release artifact verification")
if not any(ref.startswith("actions/upload-artifact@") for ref in uses_references(build_job)):
    fail("publish.yml's build job must hand the artifacts to the publish jobs")

PUBLISH_JOBS = {
    "publish-contracts": ("pypi-contracts", "contracts", "openhuntx-webguard-contracts"),
    "publish-webguard": ("pypi-webguard", "webguard", "openhuntx-webguard"),
}
publish_upload_guard = (
    "        if: github.event.inputs.mode == 'publish' && steps.plan.outputs.state == 'absent'"
)
for job_name, (environment, distribution, project) in PUBLISH_JOBS.items():
    text = publish_jobs[job_name]
    require_job_line(job_name, f"    environment: {environment}", "wrong or missing environment")
    require_job_line(
        job_name,
        "    needs: build-and-verify" if job_name == "publish-contracts" else "      - publish-contracts",
        "wrong job ordering",
    )
    if block_after(job_lines(job_name), "    permissions:") != ["      contents: read", "      id-token: write"]:
        fail(f"publish.yml job {job_name} must grant exactly contents: read and id-token: write")
    if f"--distribution {distribution}" not in text:
        fail(f"publish.yml job {job_name} must stage only the {distribution} distribution")
    if re.search(r"\bpip(?:3)?\s+wheel\b|-m pip wheel", text):
        fail(f"publish.yml job {job_name} must not rebuild the artifacts it uploads")
    pypa_steps = [ref for ref in uses_references(text) if ref.startswith("pypa/gh-action-pypi-publish@")]
    if len(pypa_steps) != 1:
        fail(f"publish.yml job {job_name} must have exactly one PyPI upload step")
    if text.count(publish_upload_guard) != 1:
        fail(f"publish.yml job {job_name}: the upload step must be guarded by publish mode and an absent file")
    for required, why in (
        ("          packages-dir: stage/", "upload only the staged directory"),
        ("          skip-existing: false", "never skip or overwrite existing files"),
        ("          attestations: true", "publish attestations"),
        ("          digest-mismatch: error", "treat an artifact digest mismatch as a hard error"),
        (f"            --project {project} \\", "check and await its own PyPI project"),
    ):
        if required not in text.splitlines():
            fail(f"publish.yml job {job_name} must {why} (expected the line {required.strip()!r})")
    if "release-publish.py await" not in text:
        fail(f"publish.yml job {job_name} must confirm the upload against PyPI by name and checksum")

if publish_active.count("id-token: write") != 2:
    fail("publish.yml must grant id-token: write to exactly the two publish jobs")
if re.search(r"environment:\s*pypi-publish\b", publish_active):
    fail("publish.yml must not reference the retired shared pypi-publish environment")

if "  terraform:" not in workflow:
    fail("CI terraform validation/IaC scan job is missing")
if f"trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz" not in workflow:
    fail("CI does not reference the reviewed Trivy release")
if TRIVY_LINUX_AMD64_SHA256 not in workflow:
    fail("CI does not pin the reviewed Trivy release checksum")

if "  security-gates:" not in workflow:
    fail("CI security-gates job is missing")
if "name: Security gates" not in workflow:
    fail("CI security-gates job has no stable display name")
if "requirements-security.lock" not in workflow:
    fail("CI security tooling lock is not part of the cache/install inputs")
if "./scripts/install-security-tools.sh" not in workflow:
    fail("CI does not install reviewed security tooling")
if "./scripts/run-security-gates.sh" not in workflow:
    fail("CI does not execute the security gates")
if "      - security-gates" not in workflow:
    fail("authorised integration is not gated on the security job")

security_installer = read("scripts/install-security-tools.sh")
if "--require-hashes" not in security_installer:
    fail("security-tool installer does not require reviewed hashes")
if "--only-binary=:all:" not in security_installer:
    fail("security-tool installer permits an unreviewed source build")
if "ruff 0.16.2" not in security_installer:
    fail("security-tool installer does not verify the reviewed Ruff version")

security_runner = read("scripts/run-security-gates.sh")
for required in (
    "python scripts/scan-secrets.py",
    "--select S",
    "--ignore S101",
    "python scripts/audit-dependencies.py",
):
    if required not in security_runner:
        fail(f"security-gate runner is missing reviewed control: {required}")

compose = read("infra/compose/compose.lab.yml")
expected_image = f"bkimminich/juice-shop:v20.1.1@{JUICE_SHOP_INDEX_DIGEST}"
if expected_image not in compose:
    fail("Juice Shop is not pinned to the reviewed multi-platform index digest")

print("Supply-chain pins verified.")
