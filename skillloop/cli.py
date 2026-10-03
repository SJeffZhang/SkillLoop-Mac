"""API4 operator CLI. Currently implements the frozen import command only."""
from __future__ import annotations
import argparse
import os
import sqlite3
import sys
import subprocess
from pathlib import Path
from .protocol import ProtocolError, canonical_json_line, decode_json, digest_jcs
from .source import import_git_package

class SyntaxError64(ValueError):
    pass

class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SyntaxError64("invalid_arguments")


def _operation_result(operation_id: str, parameters: dict, produce) -> dict:
    # This is a control-owned journal, never a path supplied by the Skill package.
    state = os.environ.get("SKILLLOOP_CONTROL_DIR")
    if not state or not operation_id or len(operation_id) > 256:
        raise PermissionError("operation_control_directory_required")
    root = Path(state)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    stat = root.lstat()
    if root.is_symlink() or stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
        raise PermissionError("operation_control_directory_private_owner_required")
    path = root / "import-operations.sqlite"
    if path.is_symlink():
        raise PermissionError("operation_journal_symlink")
    prior = os.umask(0o077)
    try:
        with sqlite3.connect(path, timeout=5) as db:
            db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, parameters TEXT NOT NULL, result BLOB NOT NULL)")
            db.execute("BEGIN IMMEDIATE")
            fingerprint = digest_jcs(parameters)
            row = db.execute("SELECT parameters,result FROM operations WHERE id=?", (operation_id,)).fetchone()
            if row:
                if row[0] != fingerprint:
                    raise ProtocolError("operation_id_parameter_conflict")
                return decode_json(row[1])
            result = produce()
            db.execute("INSERT INTO operations VALUES (?,?,?)", (operation_id, fingerprint, canonical_json_line(result)))
            return result
    finally:
        os.umask(prior)


def main(argv=None) -> int:
    parser = Parser(prog="skillloop")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    imp = commands.add_parser("import", help="Import exact Git objects as data")
    imp.add_argument("--git-repo", required=True, type=Path)
    imp.add_argument("--commit", required=True)
    imp.add_argument("--skill-path", required=True)
    imp.add_argument("--operation-id")
    try:
        args = parser.parse_args(argv)
        def produce():
            return import_git_package(args.git_repo, args.commit, args.skill_path)[0]
        if args.operation_id is not None:
            snapshot = _operation_result(args.operation_id,
                {"git_repo": str(args.git_repo.absolute()), "commit": args.commit, "skill_path": args.skill_path}, produce)
        else:
            snapshot = produce()
        sys.stdout.buffer.write(canonical_json_line(snapshot))
        return 0
    except (SyntaxError64, ProtocolError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 64
    except PermissionError:
        print("permission_denied", file=sys.stderr)
        return 77
    except (TimeoutError, subprocess.TimeoutExpired):
        print("temporary_busy", file=sys.stderr)
        return 75
    except sqlite3.OperationalError as exc:
        code = 75 if "locked" in str(exc) else 74
        print("operation_store_busy" if code == 75 else "operation_store_io", file=sys.stderr)
        return code
    except OSError:
        print("io_error", file=sys.stderr)
        return 74
