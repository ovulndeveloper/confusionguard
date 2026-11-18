#!/usr/bin/env python3
"""ConfusionGuard — dependency-confusion and typosquat risk scanner.

Defensive supply-chain tooling. It reads your dependency manifests, compares
each dependency against the public registry, and flags names that look like
typosquats of popular packages or that do not exist publicly (a classic
dependency-confusion setup).

No packages are installed and no code from dependencies is executed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

USER_AGENT = "confusionguard/1.0 (defensive supply-chain scanner)"
REGISTRY_TIMEOUT = 8.0

POPULAR = {
    "npm": [
        "express", "react", "react-dom", "lodash", "axios", "moment", "chalk",
        "commander", "debug", "async", "bluebird", "underscore", "vue", "next",
        "webpack", "eslint", "typescript", "jest", "mongoose", "dotenv",
        "body-parser", "cors", "uuid", "yargs", "glob", "minimist", "semver",
        "jsonwebtoken", "bcrypt", "passport", "sequelize", "knex", "redis",
        "zod", "prisma", "vite", "svelte", "tailwindcss", "socket.io",
    ],
    "pypi": [
        "requests", "numpy", "pandas", "flask", "django", "boto3", "pytest",
        "setuptools", "wheel", "pip", "urllib3", "six", "python-dateutil",
        "pyyaml", "cryptography", "beautifulsoup4", "scrapy", "selenium",
        "sqlalchemy", "pydantic", "fastapi", "uvicorn", "scipy", "matplotlib",
        "scikit-learn", "tensorflow", "torch", "keras", "pillow",
        "opencv-python", "paramiko", "psycopg2", "celery", "gunicorn",
        "click", "rich", "typer", "httpx", "aiohttp", "jinja2", "certifi",
    ],
}

LEVEL_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class RegistryError(RuntimeError):
    """Transient registry failure — do not treat as 'package missing'."""


def osa_distance(a: str, b: str) -> int:
    """Optimal string alignment distance (Levenshtein + adjacent swaps)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    rows = len(a) + 1
    cols = len(b) + 1
    d = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        d[i][0] = i
    for j in range(cols):
        d[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def base_name(name: str) -> str:
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


def strip_separators(name: str) -> str:
    return re.sub(r"[-_.]", "", name).lower()


def find_typosquat(name: str, ecosystem: str) -> str | None:
    """Return the popular package this name imitates, if any."""
    popular = POPULAR.get(ecosystem, [])
    low = name.lower()
    if low in popular:
        return None
    base = base_name(low)
    if base in popular:
        return None
    for candidate in popular:
        if len(base) < 4:
            continue
        if strip_separators(base) == strip_separators(candidate):
            return candidate
        if abs(len(base) - len(candidate)) <= 1 and osa_distance(base, candidate) == 1:
            return candidate
    return None


def _clean_requirement(raw: str) -> str | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith(("-", "git+", "http:", "https:", "file:", ".")):
        return None
    line = line.split(";", 1)[0].strip()
    line = line.split(" --", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
    if not match:
        return None
    name = match.group(1)
    rest = line[len(name):]
    spec = rest.strip() or "*"
    return f"{name}{' ' + spec if spec != '*' else ''}"


def parse_requirements(text: str) -> list[tuple[str, str]]:
    out = []
    for raw in text.splitlines():
        cleaned = _clean_requirement(raw)
        if not cleaned:
            continue
        parts = cleaned.split(" ", 1)
        out.append((parts[0], parts[1] if len(parts) > 1 else "*"))
    return out


def parse_package_json(data: dict) -> list[tuple[str, str]]:
    out = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section) or {}
        if isinstance(deps, dict):
            for name, spec in deps.items():
                out.append((name, str(spec)))
    return out


def parse_pyproject(data: dict) -> list[tuple[str, str]]:
    out = []
    project = data.get("project") or {}
    for spec in project.get("dependencies") or []:
        parsed = _clean_requirement(str(spec))
        if parsed:
            name, _, ver = parsed.partition(" ")
            out.append((name, ver or "*"))
    for group in (project.get("optional-dependencies") or {}).values():
        for spec in group or []:
            parsed = _clean_requirement(str(spec))
            if parsed:
                name, _, ver = parsed.partition(" ")
                out.append((name, ver or "*"))
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for section in ("dependencies", "dev-dependencies"):
        for name, spec in (poetry.get(section) or {}).items():
            if name.lower() == "python":
                continue
            out.append((name, str(spec)))
    return out


def collect_dependencies(path: Path) -> list[dict]:
    """Return [{'ecosystem','name','spec','source'}] for a file or directory."""
    def kind_for(manifest: Path) -> str:
        if manifest.name == "package.json":
            return "npm"
        if manifest.name == "pyproject.toml" or re.fullmatch(r"requirements.*\.txt", manifest.name):
            return "pypi"
        raise ValueError(f"Unsupported manifest: {manifest} (expected package.json, requirements*.txt or pyproject.toml)")

    found: list[dict] = []
    manifests: list[tuple[Path, str]] = []
    if path.is_file():
        manifests.append((path, kind_for(path)))
    elif path.is_dir():
        for name in ("package.json", "requirements.txt", "pyproject.toml"):
            candidate = path / name
            if candidate.is_file():
                manifests.append((candidate, kind_for(candidate)))
    else:
        raise FileNotFoundError(f"No such file or directory: {path}")

    for manifest, kind in manifests:
        try:
            if kind == "npm":
                data = json.loads(manifest.read_text(encoding="utf-8"))
                pairs, eco = parse_package_json(data), "npm"
            elif manifest.name == "requirements.txt":
                pairs, eco = parse_requirements(manifest.read_text(encoding="utf-8")), "pypi"
            else:
                pairs, eco = parse_pyproject(tomllib.loads(manifest.read_text(encoding="utf-8"))), "pypi"
        except (json.JSONDecodeError, tomllib.TOMLDecodeError, OSError) as exc:
            raise ValueError(f"Could not parse {manifest}: {exc}") from exc
        for name, spec in pairs:
            found.append({"ecosystem": eco, "name": name, "spec": spec, "source": str(manifest)})

    dedup: dict[tuple[str, str], dict] = {}
    for dep in found:
        dedup.setdefault((dep["ecosystem"], dep["name"].lower()), dep)
    return sorted(dedup.values(), key=lambda d: (d["ecosystem"], d["name"].lower()))


def _fetch_json(url: str, timeout: float) -> dict | None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "ignore"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise RegistryError(f"HTTP {exc.code} for {url}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RegistryError(f"{type(exc).__name__} for {url}") from exc


def _age_days(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        stamp = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - stamp).days)
    except ValueError:
        return None


def fetch_npm(name: str, timeout: float) -> dict | None:
    quoted = urllib.parse.quote(name, safe="")
    meta = _fetch_json(f"https://registry.npmjs.org/{quoted}", timeout)
    if meta is None:
        return {"exists": False}
    created = ((meta.get("time") or {}).get("created"))
    downloads = None
    try:
        dl = _fetch_json(f"https://api.npmjs.org/downloads/point/last-week/{quoted}", timeout)
        if dl and isinstance(dl.get("downloads"), int):
            downloads = dl["downloads"]
    except RegistryError:
        pass
    maintainers = meta.get("maintainers")
    return {
        "exists": True,
        "created": created,
        "age_days": _age_days(created),
        "week_downloads": downloads,
        "maintainers": len(maintainers) if isinstance(maintainers, list) else None,
        "has_repo": bool(meta.get("repository")),
        "latest": (meta.get("dist-tags") or {}).get("latest"),
    }


def fetch_pypi(name: str, timeout: float) -> dict | None:
    quoted = urllib.parse.quote(name, safe="")
    meta = _fetch_json(f"https://pypi.org/pypi/{quoted}/json", timeout)
    if meta is None:
        return {"exists": False}
    info = meta.get("info") or {}
    uploads = []
    for files in (meta.get("releases") or {}).values():
        for f in files or []:
            stamp = f.get("upload_time_iso_8601") or f.get("upload_time")
            if stamp:
                uploads.append(stamp)
    created = min(uploads) if uploads else None
    return {
        "exists": True,
        "created": created,
        "age_days": _age_days(created),
        "week_downloads": None,
        "maintainers": None,
        "has_repo": bool(info.get("project_urls") or info.get("home_page")),
        "latest": info.get("version"),
    }


def assess(meta: dict | None, typo: str | None, lookup_failed: bool = False) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if lookup_failed:
        reasons.append("registry lookup failed (skipped metadata checks)")
    if meta is not None and not meta.get("exists", True):
        score += 70
        reasons.append("not found in public registry (dependency-confusion risk)")
    if typo:
        score += 50
        reasons.append(f"name resembles popular package '{typo}'")
    if meta and meta.get("age_days") is not None:
        age = meta["age_days"]
        if age < 90:
            score += 25
            reasons.append(f"published only {age} days ago")
        elif age < 365:
            score += 10
            reasons.append("published less than a year ago")
    if meta and meta.get("week_downloads") is not None and meta["week_downloads"] < 100:
        score += 15
        reasons.append(f"low usage ({meta['week_downloads']} downloads/week)")
    if meta and meta.get("maintainers") == 1:
        score += 5
        reasons.append("single maintainer")
    if meta and meta.get("exists") and not meta.get("has_repo"):
        score += 5
        reasons.append("no repository or homepage linked")
    return min(score, 100), reasons


def level_for(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 25:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


def scan(path: Path, offline: bool = False, timeout: float = REGISTRY_TIMEOUT) -> list[dict]:
    deps = collect_dependencies(path)
    findings = []
    fetched: dict[str, dict | None] = {}
    for dep in deps:
        eco, name = dep["ecosystem"], dep["name"]
        typo = find_typosquat(name, eco)
        meta = None
        lookup_failed = False
        if not offline:
            key = f"{eco}:{name.lower()}"
            if key not in fetched:
                try:
                    fetched[key] = fetch_npm(name, timeout) if eco == "npm" else fetch_pypi(name, timeout)
                except RegistryError:
                    fetched[key] = None
            meta = fetched[key]
            lookup_failed = meta is None
        score, reasons = assess(meta, typo, lookup_failed)
        findings.append({
            "ecosystem": eco,
            "name": name,
            "spec": dep["spec"],
            "level": level_for(score),
            "score": score,
            "reasons": reasons,
            "latest": (meta or {}).get("latest"),
            "source": dep["source"],
        })
    findings.sort(key=lambda f: (-f["score"], f["name"].lower()))
    return findings


def render_table(findings: list[dict]) -> str:
    if not findings:
        return "No dependencies found."
    header = f"{'LEVEL':<9}{'ECO':<6}{'PACKAGE':<28}{'SCORE':>5}  DETAILS"
    lines = [header, "-" * len(header)]
    for f in findings:
        details = "; ".join(f["reasons"]) or "no risk signals"
        lines.append(f"{f['level'].upper():<9}{f['ecosystem']:<6}{f['name'][:27]:<28}{f['score']:>5}  {details}")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["level"]] = counts.get(f["level"], 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda kv: LEVEL_ORDER[kv[0]], reverse=True))
    lines += ["", f"{len(findings)} dependencies scanned — {summary}"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="confusionguard",
        description="Scan dependency manifests for dependency-confusion and typosquat risk.",
    )
    parser.add_argument("path", help="Repository directory or manifest file (package.json, requirements.txt, pyproject.toml).")
    parser.add_argument("--json", action="store_true", help="Output JSON.")
    parser.add_argument("--offline", action="store_true", help="Static checks only; do not query registries.")
    parser.add_argument("--timeout", type=float, default=REGISTRY_TIMEOUT, help="Per-request timeout in seconds.")
    parser.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="none",
                        help="Exit with status 2 when a finding reaches this level (for CI).")
    args = parser.parse_args(argv)

    try:
        findings = scan(Path(args.path).expanduser(), offline=args.offline, timeout=args.timeout)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print(render_table(findings))

    threshold = 0 if args.fail_on == "none" else LEVEL_ORDER[args.fail_on]
    if threshold > 0:
        worst = max((LEVEL_ORDER[f["level"]] for f in findings), default=0)
        if worst >= threshold:
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
