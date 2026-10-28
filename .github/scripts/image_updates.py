#!/usr/bin/env python3
"""Compare literal Chainguard FROM pins with registry index digests.

Uses Buildx's registry inspection (no image build or Docker daemon required).
Exit codes: 0 current/not applicable, 1 stale, 2 incomplete/error.
"""
import json
from pathlib import Path
import re
import subprocess
import sys

DIGEST = r'sha256:[0-9a-f]{64}'
REFERENCE = re.compile(r'(cgr\.dev/chainguard/[a-z0-9._/-]+:[A-Za-z0-9_][A-Za-z0-9_.-]*)@(' + DIGEST + r')')


def audit(dockerfile):
    images, errors, seen = [], [], set()
    # Dockerfile continuation lines may contain intervening comments.
    lines = '\n'.join(line for line in dockerfile.splitlines() if not line.lstrip().startswith('#'))
    lines = re.sub(r'\\\s*\n', ' ', lines)
    for line in lines.splitlines():
        match = re.match(r'\s*FROM\s+(?:--\S+\s+)*(\S+)', line, re.IGNORECASE)
        if not match:
            continue
        reference = match[1]
        if not reference.startswith('cgr.dev/chainguard/') or reference in seen:
            continue
        seen.add(reference)
        pin = REFERENCE.fullmatch(reference)
        if not pin:
            errors.append(f'Expected a literal tag and SHA-256 pin: {reference}')
            continue
        tag, pinned = pin.groups()
        try:
            result = subprocess.run(
                ['docker', 'buildx', 'imagetools', 'inspect', tag, '--format', '{{json .Manifest}}'],
                check=True, capture_output=True, text=True, timeout=60,
            )
            manifest = json.loads(result.stdout)
            latest = manifest.get('digest') if isinstance(manifest, dict) else None
            if not isinstance(latest, str) or not re.fullmatch(DIGEST, latest):
                raise ValueError('registry response has no valid SHA-256 digest')
            images.append({'image': tag, 'pinned': pinned, 'latest': latest})
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            errors.append(f'{tag}: {error}')
    status = ('error' if errors else 'stale' if any(i['pinned'] != i['latest'] for i in images)
              else 'current' if images else 'not-applicable')
    return {'status': status, 'images': images, 'errors': errors}


if __name__ == '__main__':
    try:
        report = audit(Path(sys.argv[1] if len(sys.argv) > 1 else 'Dockerfile').read_text())
    except OSError as error:
        report = {'status': 'error', 'images': [], 'errors': [str(error)]}
    print(json.dumps(report, indent=2, sort_keys=True))
    sys.exit({'stale': 1, 'error': 2}.get(report['status'], 0))
