"""Bind the offline console-entry wheel to the source copied into the image."""
from pathlib import Path, PurePosixPath
import stat
import sys
from zipfile import ZipFile


def verify(wheel_path, source_directory):
    wheel = Path(wheel_path)
    source = Path(source_directory)
    if (wheel.name != 'skillloop-0.1.0.dev1-py3-none-any.whl' or not wheel.is_file()
            or not source.is_dir() or source.is_symlink()):
        raise ValueError('runtime_wheel_frozen_inputs')
    expected = {path.relative_to(source).as_posix() for package in ('skillloop', 'scripts')
                for path in (source / package).rglob('*.py')
                if '__pycache__' not in path.parts}
    actual = set()
    with ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('runtime_wheel_duplicate_member')
        for member in archive.infolist():
            name = member.filename
            path = PurePosixPath(name)
            if (path.is_absolute() or '..' in path.parts or str(path) != name
                    or member.is_dir() or member.file_size > 16777216
                    or stat.S_IFMT(member.external_attr >> 16) == stat.S_IFLNK):
                raise ValueError('runtime_wheel_unsafe_member')
            if path.parts[0] in {'skillloop', 'scripts', 'specs'}:
                original = source / name
                if original.is_symlink() or not original.is_file():
                    raise ValueError('runtime_wheel_unmatched_source')
                if archive.read(member) != original.read_bytes():
                    raise ValueError('runtime_wheel_source_bytes_changed')
                if name.endswith('.py') and path.parts[0] in {'skillloop', 'scripts'}:
                    actual.add(name)
        if actual != expected:
            raise ValueError('runtime_wheel_incomplete_python_source')
        if archive.read('skillloop-0.1.0.dev1.dist-info/entry_points.txt').strip() != (
                b'[console_scripts]\nskillloop = skillloop.cli:main'):
            raise ValueError('runtime_wheel_formal_console_entry')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('expected wheel and source directory')
    verify(*sys.argv[1:])
