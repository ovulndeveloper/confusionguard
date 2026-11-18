# ConfusionGuard

**A dependency-confusion and typosquat risk scanner for npm and PyPI manifests.**

Most scanners check dependencies for known CVEs. ConfusionGuard checks the
*names themselves* — because a package you think is `axios` but is actually
`axois` is a supply-chain compromise waiting to happen.

```
$ python3 confusionguard.py sample
LEVEL    ECO   PACKAGE                     SCORE  DETAILS
---------------------------------------------------------
CRITICAL pypi  reqeusts                      100  not found in public registry (dependency-confusion risk); name resembles popular package 'requests'
HIGH     npm   axois                          50  name resembles popular package 'axios'
INFO     npm   lodash                          5  single maintainer
INFO     npm   express                         0  no risk signals
INFO     pypi  flask                           0  no risk signals
INFO     npm   jest                            0  no risk signals

6 dependencies scanned — critical=1, high=1, info=4
```

## Why

Two attacks are cheap and common:

- **Typosquatting** — publish `axois` / `reqeusts` and wait for a typo.
- **Dependency confusion** — publish a public package with the same name as
  your private/internal dependency. The package manager may resolve the public
  one, and install attacker code.

ConfusionGuard flags both before you install anything.

## What it checks

| Signal | Weight | Why it matters |
| --- | --- | --- |
| Not found in the public registry | +70 | Classic dependency-confusion setup |
| Name is 1 edit from a popular package | +50 | Typosquat / lookalike |
| Published < 90 days ago | +25 | Fresh impersonation accounts |
| Published < 1 year ago | +10 | Lower confidence, still notable |
| < 100 downloads/week (npm) | +15 | Unused package impersonating a real one |
| Single maintainer (npm) | +5 | Weak account, easier to hijack |
| No repository/homepage | +5 | Throwaway package |

Levels: `info` → `low` (≥10) → `medium` (≥25) → `high` (≥45) → `critical` (≥70).

## Supported manifests

- `package.json` — `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`
- `requirements.txt` (and `requirements-*.txt`)
- `pyproject.toml` — `[project].dependencies`, optional dependencies, Poetry deps

Scoped npm names (`@scope/pkg`) are understood.

## Install

No dependencies. Python 3.11+.

```bash
git clone https://github.com/ovulndeveloper/confusionguard.git
cd confusionguard
python3 confusionguard.py --help
```

Optionally install it on your `PATH`:

```bash
install -m 0755 confusionguard.py ~/.local/bin/confusionguard
```

## Usage

```bash
# scan a repository directory
python3 confusionguard.py /path/to/repo

# scan one manifest
python3 confusionguard.py ./package.json

# static checks only (no registry calls)
python3 confusionguard.py . --offline

# machine-readable output
python3 confusionguard.py . --json

# fail CI when something is high or worse
python3 confusionguard.py . --fail-on high
```

Exit codes: `0` clean (or below threshold), `1` bad input, `2` finding at or
above `--fail-on`.

### CI example

```yaml
- name: Dependency-confusion check
  run: python3 confusionguard.py . --fail-on high
```

## How it works

1. Parse the manifests into `(ecosystem, name, spec)` tuples.
2. Score static signals: edit distance to a built-in list of popular packages,
   separator tricks (`req-ue-sts` → `requests`), direct-match exclusion.
3. Query the public registry for existence, age, downloads (npm), maintainers,
   and linked repository.
4. Combine signals into a 0–100 score with human-readable reasons.

No dependency is installed, imported, or executed. Network access is read-only
(`registry.npmjs.org`, `api.npmjs.org`, `pypi.org`).

## Limitations

- Heuristics, not proof. A flagged name can be legitimate; review before acting.
- Private/internal packages are *expected* to be missing publicly — use
  `--offline`, or treat "not found" as informational for those names.
- PyPI does not expose weekly downloads here, so npm-only signals are skipped.
- Popular-package baseline is a curated list; extend `POPULAR` for your stack.
- Not a replacement for lockfiles, provenance attestations, or an SBOM scanner.
  Use it alongside them.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
