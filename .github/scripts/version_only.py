#!/usr/bin/env python3
"""Tell whether a diff is only a netcidr version bump (a release-plz PR).

A release PR changes the package version in Cargo.toml, netcidr's own entry
in Cargo.lock, and Markdown (CHANGELOG.md). The code it ships already passed
CI on main, so CI and the image scan skip it. This compares file contents,
not branch names: a release PR that also changes a dependency still runs
everything.

Usage: version_only.py <base-sha> <head-sha>
Exit codes: 0 version-only, 1 anything else, 2 error.
"""
import re
import subprocess
import sys

PACKAGE = 'netcidr'
# Regular files, or absent on one side (added/deleted). Symlinks (120000) and
# submodules (160000) never count as version-only.
REGULAR_MODES = {'000000', '100644', '100755'}
VERSION_LINE = re.compile(r'^version\s*=\s*"[^"]*"\s*$')


def normalize_manifest(text):
    """Cargo.toml with the [package] version line blanked."""
    out, section = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('['):
            section = stripped
        if section == '[package]' and VERSION_LINE.match(stripped):
            line = 'version = <ignored>'
        out.append(line)
    return '\n'.join(out)


def normalize_lock(text, package=PACKAGE):
    """Cargo.lock with the version line of `package`'s own entry blanked."""
    out, current = [], None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == '[[package]]':
            current = None
        elif stripped.startswith('name = '):
            current = stripped
        elif current == f'name = "{package}"' and VERSION_LINE.match(stripped):
            line = 'version = <ignored>'
        out.append(line)
    return '\n'.join(out)


NORMALIZERS = {'Cargo.toml': normalize_manifest, 'Cargo.lock': normalize_lock}


def is_version_only(changes):
    """`changes` maps each changed path to (base_text, head_text); None
    means the file doesn't exist on that side."""
    if not changes:
        return False
    for path, (base, head) in changes.items():
        if path.endswith('.md'):
            continue
        normalize = NORMALIZERS.get(path)
        if normalize is None or base is None or head is None:
            return False
        if normalize(base) != normalize(head):
            return False
    return True


def changed_paths(base, head):
    """Changed paths, or None if any entry isn't a regular file.

    Rename detection is off so a rename appears as a deletion plus an
    addition: otherwise `src/main.rs -> notes.md` would list only the
    Markdown path. NUL-separated so unusual file names survive intact.
    """
    raw = subprocess.run(['git', 'diff', '--raw', '--no-renames', '-z', base, head],
                         capture_output=True, text=True, check=True).stdout
    fields = raw.split('\0')
    paths = []
    # Each entry is ":<old mode> <new mode> <old sha> <new sha> <status>" then the path.
    for meta, path in zip(fields[0::2], fields[1::2]):
        old_mode, new_mode = meta.lstrip(':').split()[:2]
        if old_mode not in REGULAR_MODES or new_mode not in REGULAR_MODES:
            return None
        paths.append(path)
    return paths


def show(rev, path):
    result = subprocess.run(['git', 'show', f'{rev}:{path}'], capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else None


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    base, head = argv[1], argv[2]
    try:
        names = changed_paths(base, head)
    except subprocess.CalledProcessError as error:
        print(f'git diff failed: {error.stderr.strip()}', file=sys.stderr)
        return 2
    if names is None:
        print('not version-only: non-regular file changed')
        return 1
    changes = {path: (show(base, path), show(head, path)) for path in names}
    if is_version_only(changes):
        print(f'version-only: {", ".join(names)}')
        return 0
    print('not version-only')
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
