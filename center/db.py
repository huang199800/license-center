import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def connect(path):
    c = sqlite3.connect(path, timeout=30, isolation_level=None, factory=ClosingConnection)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA synchronous=FULL')
    return c


@contextmanager
def transaction(path):
    c = connect(path)
    try:
        c.execute('BEGIN IMMEDIATE')
        yield c
        c.commit()
    except BaseException:
        c.rollback()
        raise
    finally:
        c.close()


def migrate(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    c = connect(path)
    try:
        current = c.execute('PRAGMA user_version').fetchone()[0]
        if current > 1:
            raise RuntimeError('DATABASE_NEWER_THAN_APPLICATION')
        if current == 0:
            script = (Path(__file__).parent / 'migrations/001.sql').read_text()
            c.executescript('BEGIN IMMEDIATE;\n' + script + '\nPRAGMA user_version=1;\nCOMMIT;')
    finally:
        c.close()


def dump(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def audit(c, now, actor, action, product=None, target=None, detail=None):
    c.execute('INSERT INTO audit(at,actor,action,product,target,detail) VALUES(?,?,?,?,?,?)',
              (now, actor, action, product, target, dump(detail or {})))
