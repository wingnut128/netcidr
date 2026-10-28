import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'version_only.py'
spec = importlib.util.spec_from_file_location('version_only', SCRIPT)
version_only = importlib.util.module_from_spec(spec)
spec.loader.exec_module(version_only)

MANIFEST = '''[package]
name = "netcidr"
version = "{version}"
edition = "2024"

[dependencies]
serde = {{ version = "{serde}" }}
'''

LOCK = '''[[package]]
name = "netcidr"
version = "{version}"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "{serde}"
'''


def manifest(version='0.34.0', serde='1.0'):
    return MANIFEST.format(version=version, serde=serde)


def lock(version='0.34.0', serde='1.0.200'):
    return LOCK.format(version=version, serde=serde)


class VersionOnlyTest(unittest.TestCase):
    def test_release_pr_is_version_only(self):
        changes = {
            'Cargo.toml': (manifest('0.34.0'), manifest('0.34.1')),
            'Cargo.lock': (lock('0.34.0'), lock('0.34.1')),
            'CHANGELOG.md': ('old', 'new'),
        }
        self.assertTrue(version_only.is_version_only(changes))

    def test_dependency_change_is_not_version_only(self):
        changes = {
            'Cargo.toml': (manifest('0.34.0'), manifest('0.34.1', serde='2.0')),
            'Cargo.lock': (lock('0.34.0'), lock('0.34.1')),
        }
        self.assertFalse(version_only.is_version_only(changes))

    def test_other_package_version_in_lock_is_not_version_only(self):
        changes = {'Cargo.lock': (lock(serde='1.0.200'), lock(serde='1.0.201'))}
        self.assertFalse(version_only.is_version_only(changes))

    def test_dependency_version_key_in_manifest_is_not_ignored(self):
        before = manifest() + '\n[dependencies.foo]\nversion = "1"\n'
        after = manifest() + '\n[dependencies.foo]\nversion = "2"\n'
        self.assertFalse(version_only.is_version_only({'Cargo.toml': (before, after)}))

    def test_source_change_is_not_version_only(self):
        changes = {
            'Cargo.toml': (manifest('0.34.0'), manifest('0.34.1')),
            'src/main.rs': ('fn main() {}', 'fn main() { panic!() }'),
        }
        self.assertFalse(version_only.is_version_only(changes))

    def test_added_or_removed_manifest_is_not_version_only(self):
        self.assertFalse(version_only.is_version_only({'Cargo.toml': (None, manifest())}))
        self.assertFalse(version_only.is_version_only({'Cargo.lock': (lock(), None)}))

    def test_markdown_only_is_version_only(self):
        self.assertTrue(version_only.is_version_only({'CHANGELOG.md': ('a', 'b')}))

    def test_empty_diff_is_not_version_only(self):
        self.assertFalse(version_only.is_version_only({}))


if __name__ == '__main__':
    unittest.main()
