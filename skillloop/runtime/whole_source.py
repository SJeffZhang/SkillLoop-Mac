"""Versioned source inventory for a new formal Mac whole round.

The historical M6/M7 source_index is intentionally unchanged. This inventory
also binds the runtime image recipe, dependency locks and Mac deployment
profile that affect a whole round without changing a Python module.
"""
import hashlib
import os
from pathlib import Path

from skillloop.runtime.archive_files import open_original, require_unchanged


DIRECTORIES = ('skillloop', 'scripts', 'deploy/scanner', 'deploy/runtime',
               'specs/v2.2', 'specs/mac')
SUFFIXES = {'.py', '.sql', '.yaml', '.yml', '.json', '.txt', '.toml'}
REQUIRED = ('pyproject.toml', 'deploy/runtime/Dockerfile.whole-flow',
            'deploy/runtime/archive-requirements.txt',
            'deploy/runtime/archive-wheel-artifacts.json',
            'specs/mac/runtime-profile.json')


def whole_source_index(source):
    root = Path(source)
    if not root.is_absolute() or '..' in root.parts or not root.is_dir():
        raise ValueError('whole_source_absolute_repository_required')
    candidates = {root / name for name in REQUIRED}
    for directory in DIRECTORIES:
        parent = root / directory
        if not parent.is_dir() or parent.is_symlink():
            raise ValueError('whole_source_required_directory_missing')
        for path in parent.rglob('*'):
            if path.is_symlink():
                raise PermissionError('whole_source_symlink_forbidden')
            if path.is_file() and (path.suffix in SUFFIXES or path.name.startswith('Dockerfile')):
                candidates.add(path)
    result = {}
    for path in sorted(candidates):
        fd = open_original(path)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            checksum = hashlib.sha256()
            for block in iter(lambda: stream.read(1048576), b''):
                checksum.update(block)
            require_unchanged(path, before, os.fstat(stream.fileno()))
        result[path.relative_to(root).as_posix()] = 'sha256:' + checksum.hexdigest()
    if not set(REQUIRED) <= set(result):
        raise ValueError('whole_source_complete_deployment_files_required')
    return result
