#!/usr/bin/env python3
"""Package the Hallpass bridge into the downloads set served to installers.

Inputs are a directory of staged runtime jars (sbt `bridge/stageRuntimeClasspath`
writes bridge/target/bridge-dist/lib), the repository's bridge/bin, and the
source metadata the caller knows. The output directory receives exactly:

    bridge.tar.gz   the bridge archive (top-level directory `bridge/`)
    SHA256SUMS      `sha256sum` format, covering bridge.tar.gz
    VERSION         the release label, one line
    install.sh      a copy of bridge/install.sh

The archive layout is what `bridge/bin/hallpass` verifies, installs, upgrades and
uninstalls, so keep them in step:

    bridge/bin/*            every regular file in bridge/bin (found by glob)
    bridge/lib/*.jar
    bridge/VERSION
    bridge/manifest.json    schemaVersion 1; per-file size and sha256
    bridge/SHA256SUMS       every file except manifest.json and SHA256SUMS

Source state. `--commit` is the full commit the jars were built from, or
`unknown`. `--dirty` is `true`, `false`, or `unknown`; `unknown` is recorded as
JSON null and means the builder could not tell (for example a Docker build with
no .git), which is different from a clean checkout. Only `true` marks the
manifest `diagnostic-dirty-checkout`. A build never claims `dirty: true` merely
because git is missing.

The release label is `<build.sbt version>-build.<12-character commit>`. With an
unknown commit it is `<version>-build.local.<12 hex of the content digest>`, so
two different unlabelled builds do not compare equal during an upgrade.

Output is deterministic for the same inputs: entries are sorted, ownership is
zeroed, and timestamps come from SOURCE_DATE_EPOCH (default 0).

Python standard library only (it also runs inside the build image).
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile

ARCHIVE_NAME = "bridge.tar.gz"
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPO_ROOT = Path(__file__).resolve().parents[1]


class PackagingError(Exception):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_version(build_sbt: Path) -> str:
    match = re.search(r'(?m)^\s*ThisBuild\s*/\s*version\s*:=\s*"([^"]+)"', build_sbt.read_text(encoding="utf-8"))
    if match is None:
        raise PackagingError(f"could not read ThisBuild / version from {build_sbt}")
    return match.group(1)


def tri_state(value: str) -> bool | None:
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in ("unknown", ""):
        return None
    raise argparse.ArgumentTypeError("expected true, false, or unknown")


def regular_files(directory: Path, description: str) -> list[Path]:
    """Every regular, non-symlink file directly inside `directory`, sorted by name."""
    if not directory.is_dir() or directory.is_symlink():
        raise PackagingError(f"{description} is not a directory: {directory}")
    found = []
    for entry in sorted(directory.iterdir(), key=lambda p: p.name):
        if entry.is_symlink():
            raise PackagingError(f"{description} contains a symlink: {entry.name}")
        if entry.is_dir():
            if entry.name == "__pycache__":
                continue
            raise PackagingError(f"{description} contains a subdirectory: {entry.name}")
        if entry.suffix == ".pyc":
            continue
        if not entry.is_file():
            raise PackagingError(f"{description} contains a non-regular file: {entry.name}")
        found.append(entry)
    return found


def stage(bin_dir: Path, lib_dir: Path, root: Path) -> None:
    """Copy the runtime into `root` with normalized modes."""
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir()
    scripts = regular_files(bin_dir, "bridge/bin")
    if not any(path.name == "hallpass-bridge" for path in scripts) or not any(path.name == "hallpass" for path in scripts):
        raise PackagingError("bridge/bin must contain hallpass and hallpass-bridge")
    for source in scripts:
        target = root / "bin" / source.name
        shutil.copyfile(source, target)
        # Launchers (no suffix, or any executable source) are 755; helper modules are 644.
        executable = source.suffix == "" or bool(source.stat().st_mode & stat.S_IXUSR)
        target.chmod(0o755 if executable else 0o644)
    jars = [path for path in regular_files(lib_dir, "staged lib directory") if path.suffix == ".jar"]
    if not jars:
        raise PackagingError(f"no runtime jars in {lib_dir}; run sbt bridge/stageRuntimeClasspath first")
    for source in jars:
        target = root / "lib" / source.name
        shutil.copyfile(source, target)
        target.chmod(0o644)


def file_records(root: Path) -> list[dict[str, object]]:
    records = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name not in {"manifest.json", "SHA256SUMS"}):
        records.append({
            "path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    return records


def content_digest(root: Path) -> str:
    """Digest of the runtime files, independent of the label (which is not yet known)."""
    digest = hashlib.sha256()
    for record in file_records(root):
        digest.update(f"{record['sha256']}  {record['path']}\n".encode())
    return digest.hexdigest()


def write_checksums(root: Path, records: list[dict[str, object]]) -> None:
    (root / "SHA256SUMS").write_text("".join(f"{r['sha256']}  {r['path']}\n" for r in records), encoding="utf-8")


def add_tar_entries(archive: tarfile.TarFile, root: Path, mtime: int) -> None:
    def normalized(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = mtime
        return info

    archive.add(root, arcname=root.name, recursive=False, filter=normalized)
    for path in sorted(root.rglob("*")):
        archive.add(path, arcname=f"{root.name}/{path.relative_to(root).as_posix()}", recursive=False, filter=normalized)


def build(args: argparse.Namespace) -> None:
    output = args.output.resolve()
    if output.exists() and not output.is_dir():
        raise PackagingError(f"output is not a directory: {output}")
    install_sh = args.install_sh.resolve()
    if not install_sh.is_file():
        raise PackagingError(f"install script not found: {install_sh}")

    commit = args.commit.strip().lower()
    if commit != "unknown" and not COMMIT_PATTERN.match(commit):
        raise PackagingError("--commit must be a full 40-character lowercase hex commit or 'unknown'")
    base_version = project_version(args.build_sbt.resolve())
    mtime = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))

    with tempfile.TemporaryDirectory(prefix="hallpass-package-bridge.") as work_name:
        work = Path(work_name)
        root = work / "bridge"
        stage(args.bin_dir.resolve(), args.lib_dir.resolve(), root)

        if args.label:
            label = args.label
        elif commit == "unknown":
            label = f"{base_version}-build.local.{content_digest(root)[:12]}"
        else:
            label = f"{base_version}-build.{commit[:12]}"
        if not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", label):
            raise PackagingError(f"unsafe release label: {label!r}")
        (root / "VERSION").write_text(label + "\n", encoding="utf-8")

        dirty: bool | None = args.dirty
        manifest = {
            "schemaVersion": 1,
            "release": {"name": "hallpass", "version": label},
            "source": {
                "repository": "hallpass",
                "commit": None if commit == "unknown" else commit,
                "tag": args.tag or None,
                # null means the builder could not tell; it is not a claim of cleanliness.
                "dirty": dirty,
            },
            # JVM jars and POSIX sh/python launchers: not tied to the build host.
            "platform": {"os": "any", "architecture": "any"},
            "artifacts": [],
            "files": file_records(root),
            "verification": {
                "status": "diagnostic-dirty-checkout" if dirty is True else "candidate-build-only",
                "commands": [{"command": "sbt -batch bridge/stageRuntimeClasspath", "status": "passed"}],
            },
        }
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        # Manifest and SHA256SUMS are excluded from their own records, so one pass is stable.
        write_checksums(root, file_records(root))

        archive_path = work / ARCHIVE_NAME
        with archive_path.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=mtime, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    add_tar_entries(archive, root, mtime)

        output.mkdir(parents=True, exist_ok=True)
        for name in (ARCHIVE_NAME, "SHA256SUMS", "VERSION", "install.sh"):
            target = output / name
            if target.is_symlink():
                raise PackagingError(f"refusing to overwrite symlink: {target}")
        shutil.copyfile(archive_path, output / ARCHIVE_NAME)
        (output / "SHA256SUMS").write_text(f"{sha256_file(archive_path)}  {ARCHIVE_NAME}\n", encoding="utf-8")
        (output / "VERSION").write_text(label + "\n", encoding="utf-8")
        shutil.copyfile(install_sh, output / "install.sh")
        for name in (ARCHIVE_NAME, "SHA256SUMS", "VERSION"):
            (output / name).chmod(0o644)
        (output / "install.sh").chmod(0o755)

    print(f"Bridge downloads written to {output}")
    print(f"  version: {label}")
    print(f"  commit:  {commit}   dirty: {'unknown' if dirty is None else str(dirty).lower()}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Package the Hallpass bridge downloads set.")
    parser.add_argument("--lib-dir", type=Path, default=REPO_ROOT / "bridge/target/bridge-dist/lib",
                        help="staged runtime jars (default: bridge/target/bridge-dist/lib)")
    parser.add_argument("--bin-dir", type=Path, default=REPO_ROOT / "bridge/bin")
    parser.add_argument("--install-sh", type=Path, default=REPO_ROOT / "bridge/install.sh")
    parser.add_argument("--build-sbt", type=Path, default=REPO_ROOT / "build.sbt")
    parser.add_argument("--output", type=Path, required=True, help="directory to receive the downloads set")
    parser.add_argument("--commit", default="unknown", help="full source commit, or 'unknown' (default)")
    parser.add_argument("--tag", default="", help="exact tag of the source commit, if any")
    parser.add_argument("--dirty", type=tri_state, default=None, metavar="true|false|unknown",
                        help="whether the source tree had uncommitted changes (default: unknown)")
    parser.add_argument("--label", default="", help="override the derived release label")
    args = parser.parse_args(argv)
    try:
        build(args)
    except PackagingError as error:
        print(f"package-bridge: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
