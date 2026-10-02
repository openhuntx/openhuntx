# Contributing

This is currently a solo-maintained project. Issues and PRs are welcome, but response times are best-effort and there's no formal governance beyond "the maintainer reviews and merges."

## Scope

The active product is the `webguard` CLI: `packages/contracts/python` and `workers/scanner`. `apps/web`, `apps/api`, and `infra/` are archived (see [`docs/LEGACY_PLATFORM.md`](docs/LEGACY_PLATFORM.md)) and are not accepting feature work. Bug reports against them are still useful for historical accuracy, but new functionality there is out of scope.

Before adding a feature to the CLI, check whether it belongs: if it needs a server, a database, an account, or any external service to work, it's very likely out of scope for a local, zero-infrastructure tool. Open an issue to discuss first rather than sending a large PR.

## Development setup

```bash
git clone <this-repository-url>
cd openhuntx-webguard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt   # editable installs of contracts + scanner + api
```

## Running checks locally

```bash
./scripts/verify.sh
```

This compiles every package, then runs the unit, contract, and integration test suites via `python -m unittest` (no `pytest` dependency). CI (`.github/workflows/ci.yml`) runs the same gate across Python 3.11–3.14 on Linux, plus a `cli-packaging` job that builds the CLI's wheels and installs them into a clean virtual environment to make sure the *packaged* tool, not just the editable install, actually works.

If you change anything under `workers/scanner/src/webguard_scanner/cli.py`, add or update a test in `tests/unit/test_cli*.py` following the existing pattern (`cli.main([...])` with stdout/stderr captured; see `tests/unit/test_cli_workspace.py` for the newest example).

## Pull requests

- Keep PRs scoped to one change. A bug fix doesn't need an accompanying refactor.
- Add a test for behavior you add or fix.
- Run `./scripts/verify.sh` before opening the PR; CI will run it again, but a red CI run on a draft slows everyone down.
- If your change touches `pyproject.toml` files or packaging, build the wheels and run `python scripts/verify-release-artifacts.py --dist <dir> --checksums-out <file>` (the `cli-packaging` CI job does the same).
- If your change touches `.github/workflows/ci.yml`, also run `python scripts/verify-supply-chain-pins.py`. It enforces pinned, reviewed action SHAs and an exact count of CI jobs/runners, and will fail loudly (correctly) if you add a job without updating it.

## Security issues

Do not open a public issue for a security vulnerability. See [`SECURITY.md`](SECURITY.md).

## Reporting issues against authorized-use targets

If you find a real-world issue in a target you scanned with WebGuard, that's between you and that target's owner: this project has no involvement in, and no visibility into, what you scan. Only use WebGuard against systems you own or are explicitly authorized to assess.
