import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'image_updates.py'
OLD = 'sha256:' + '1' * 64
NEW = 'sha256:' + '2' * 64


class ImageUpdatesTest(unittest.TestCase):
    def audit(self, dockerfile, response=None, error=None):
        self.assertTrue(SCRIPT.exists(), 'Independent image audit is missing')
        spec = importlib.util.spec_from_file_location('image_updates', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module.subprocess, 'run', side_effect=error,
                          return_value=subprocess.CompletedProcess([], 0, json.dumps(response), '')):
            return module.audit(dockerfile)

    def test_stale_pin_is_reported_even_without_advisories(self):
        result = self.audit(f'FROM cgr.dev/chainguard/static:latest@{OLD}', {'digest': NEW})
        self.assertEqual(result['status'], 'stale')
        self.assertEqual(result['images'][0]['latest'], NEW)
        self.assertEqual(result['images'][0]['pinned'], OLD)

    def test_equal_index_digest_is_current(self):
        result = self.audit(f'FROM --platform=linux/arm64 cgr.dev/chainguard/static:latest@{OLD} AS runtime', {'digest': OLD})
        self.assertEqual(result['status'], 'current')

    def test_registry_failure_is_not_clean(self):
        result = self.audit(f'FROM cgr.dev/chainguard/static:latest@{OLD}', error=subprocess.TimeoutExpired('docker', 60))
        self.assertEqual(result['status'], 'error')
        self.assertTrue(result['errors'])

    def test_invalid_registry_digest_is_not_clean(self):
        for response in ({}, {'digest': 'garbage'}, {'digest': None}):
            with self.subTest(response=response):
                self.assertEqual(self.audit(f'FROM cgr.dev/chainguard/static:latest@{OLD}', response)['status'], 'error')

    def test_missing_pin_or_tag_is_not_clean(self):
        for reference in ('cgr.dev/chainguard/static:latest', f'cgr.dev/chainguard/static@{OLD}'):
            self.assertEqual(self.audit('FROM ' + reference)['status'], 'error')

    def test_no_chainguard_images_is_explicit(self):
        result = self.audit('FROM rust:alpine\n# FROM cgr.dev/chainguard/static:latest')
        self.assertEqual(result['status'], 'not-applicable')

    def test_duplicate_and_multiline_stages(self):
        line = f'from cgr.dev/chainguard/static:latest@{OLD}'
        result = self.audit(line + ' AS first\nFROM \\\n cgr.dev/chainguard/static:latest@' + OLD, {'digest': NEW})
        self.assertEqual(result['status'], 'stale')
        self.assertEqual(len(result['images']), 1)


if __name__ == '__main__':
    unittest.main()
