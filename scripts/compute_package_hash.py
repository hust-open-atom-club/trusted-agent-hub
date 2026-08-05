"""Compute the deterministic package tree hash used by examples/real-world manifests.

Usage:
    python scripts/compute_package_hash.py examples/real-world/skills/skill-creator

The hash covers every file under the directory (sorted by relative POSIX path):
    sha256( path + "\\0" + file_bytes + "\\0" for each file )

`manifest.json` is excluded from the digest so the manifest can reference its own
package content without creating a self-reference.

Line endings are canonicalized: text files (no NUL byte) have CRLF/CR normalized
to LF before hashing, so the digest is identical on Windows and Linux checkouts.
Binary files are hashed as-is.
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
        if b"\0" not in data:
            data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
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
