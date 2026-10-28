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


def show(rev, path):
    result = subprocess.run(['git', 'show', f'{rev}:{path}'], capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else None


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    base, head = argv[1], argv[2]
    try:
        names = subprocess.run(['git', 'diff', '--name-only', base, head],
                               capture_output=True, text=True, check=True).stdout.split()
    except subprocess.CalledProcessError as error:
        print(f'git diff failed: {error.stderr.strip()}', file=sys.stderr)
        return 2
    changes = {path: (show(base, path), show(head, path)) for path in names}
    if is_version_only(changes):
        print(f'version-only: {", ".join(names)}')
        return 0
    print('not version-only')
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
