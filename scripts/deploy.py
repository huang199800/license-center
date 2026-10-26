#!/usr/bin/env python3
"""Default to native systemd; preserve the backend of existing installations."""
import json
import os
import sys
from pathlib import Path


def select(argv):
    args = list(argv)
    mode = None
    if '--mode' in args:
        i = args.index('--mode')
        if i + 1 >= len(args):
            raise ValueError('MODE_REQUIRED')
        mode = args[i + 1]
        del args[i:i + 2]
    root = '/opt/license-center'
    if '--root' in args:
        root = args[args.index('--root') + 1]
    meta = Path(root)/'deployment.json'
    existing = json.loads(meta.read_text()).get('backend', 'docker') if meta.exists() else None
    mode = mode or existing or os.environ.get('LC_DEPLOY_MODE', 'native')
    if mode not in ['native', 'docker']:
        raise ValueError('MODE_MUST_BE_NATIVE_OR_DOCKER')
    if existing and existing != mode:
        raise ValueError('BACKEND_CHANGE_REQUIRES_BACKUP_RESTORE_TO_NEW_ROOT')
    return mode, args


if __name__ == '__main__':
    try:
        mode, args = select(sys.argv[1:])
    except (ValueError, IndexError):
        print(json.dumps({'error': 'INVALID_MODE_OR_EXISTING_BACKEND_MISMATCH'}))
        raise SystemExit(1)
    target = Path(__file__).with_name('native_ops.py' if mode == 'native' else 'ops.py')
    os.execv(sys.executable, [sys.executable, str(target), *args])
