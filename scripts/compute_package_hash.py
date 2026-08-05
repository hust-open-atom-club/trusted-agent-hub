"""Compute the deterministic package tree hash used by examples/real-world manifests.

Usage:
    python scripts/compute_package_hash.py examples/real-world/skills/skill-creator

The hash covers every file under the directory (sorted by relative POSIX path):
    sha256( path + "\\0" + file_bytes + "\\0" for each file )

`manifest.json` is excluded from the digest so the manifest can reference its own
package content without creating a self-reference.
"""

from __future__ import annotations

import hashlib
import os
import sys


def tree_hash(directory: str) -> str:
    digest = hashlib.sha256()
    entries: list[tuple[str, str]] = []
    for base, dirs, files in os.walk(directory):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(base, name)
            rel = os.path.relpath(path, directory).replace("\\", "/")
            if rel == "manifest.json":
                continue
            entries.append((rel, path))
    for rel, path in sorted(entries):
        with open(path, "rb") as fh:
            data = fh.read()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    directory = sys.argv[1]
    if not os.path.isdir(directory):
        print(f"Not a directory: {directory}", file=sys.stderr)
        sys.exit(1)
    print(tree_hash(directory))


if __name__ == "__main__":
    main()
