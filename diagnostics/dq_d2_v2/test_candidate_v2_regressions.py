"""Review-only synthetic regression proposal; no direct execution authority.
No native calls, file opens, subprocesses, or original-module imports.
An approved external in-memory runner must supply exact source bytes later.
"""
import ast
import hashlib
import stat
import unittest
from types import SimpleNamespace

CANDIDATE_SHA = "139AEE6B2140206FAACE28F2F5B30048F26E3313BD057FAFEE1B4516825024BB"
PROJECTION = ('LIMIT', 'digest', 'reparse', 'checked_hash', 'GUARD_FIELDS', 'OBS_FIELDS', 'snapshot', 'differences', 'differential')
PAYLOAD = b"fixture"
LIMIT = 64 * 1024 * 1024
FIELDS = ("st_dev", "st_ino", "st_size", "st_nlink", "st_mtime_ns", "st_mode")


def observation(**changes):
    data = dict(st_dev=1, st_ino=2, st_size=len(PAYLOAD), st_nlink=1,
                st_mtime_ns=100, st_mode=stat.S_IFREG | 0o444,
                st_ctime_ns=100, st_atime_ns=100, st_birthtime_ns=50,
                st_file_attributes=0, st_reparse_tag=0)
    data.update(changes)
    return SimpleNamespace(**data)


def native():
    return dict(errors={}, basic=dict(attributes=0, volume=11, size_high=0,
                size_low=len(PAYLOAD), links=1, index_high=0, index_low=22),
                standard=dict(allocation=4096, eof=len(PAYLOAD), links=1,
                delete_pending=0, directory=0), stream_count=1)


class FakeFile:
    def __init__(self, events):
        self.events = events
        self.closed = False
        self.reads = 0

    def __enter__(self):
        self.events.append(("enter", 17))
        return self

    def __exit__(self, *unused):
        self.closed = True
        self.events.append(("close", 17))

    def fileno(self):
        if self.closed:
            raise AssertionError("closed descriptor")
        return 17

    def read(self, n):
        if self.closed:
            raise AssertionError("read after close")
        self.reads += 1
        self.events.append(("read", self.fileno(), n))
        return PAYLOAD


class FakePath:
    name = "synthetic.exe"

    def __init__(self, f, events):
        self.f, self.events = f, events
        self.opens = 0

    def __str__(self):
        return "SYNTHETIC_ONLY/synthetic.exe"

    def open(self, mode):
        self.opens += 1
        self.events.append(("open", mode))
        if mode != "rb" or self.opens != 1:
            raise AssertionError("unexpected open/reopen")
        return self.f


def project(source_bytes, path_values, handle_values, native_values):
    if hashlib.sha256(source_bytes).hexdigest().upper() != CANDIDATE_SHA:
        raise ValueError("CANDIDATE_DIGEST_MISMATCH")
    def node_name(n):
        if isinstance(n, ast.FunctionDef):
            return n.name
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            return n.targets[0].id
        return None
    nodes = [n for n in ast.parse(source_bytes).body if node_name(n) in PROJECTION]
    if tuple(map(node_name, nodes)) != PROJECTION:
        raise ValueError("PROJECTION_MISMATCH")
    events = []
    f = FakeFile(events)
    path = FakePath(f, events)
    paths, handles, natives = map(iter, (path_values, handle_values, native_values))
    def guarded(p):
        if p is not path:
            raise AssertionError("unexpected path")
        events.append(("path",))
        return next(paths)
    def checked_fd(label, fd, values):
        if fd != f.fileno():
            raise AssertionError("descriptor mismatch")
        events.append((label, fd))
        return next(values)
    def fstat(fd): return checked_fd("fstat", fd, handles)
    def native_snapshot(fd): return checked_fd("native", fd, natives)
    ns = dict(__builtins__={"getattr": getattr, "bool": bool, "len": len,
              "any": any, "all": all, "ValueError": ValueError, "str": str,
              "type": type, "int": int}, hashlib=hashlib, stat=stat,
              os=SimpleNamespace(fstat=fstat), guarded=guarded,
              native_snapshot=native_snapshot)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<candidate-v2-projection>", "exec"), ns)
    return ns, path, f, events


def build_suite(source_bytes):
    """Only a future explicitly authorized runner may invoke this function."""
    class CandidateV2Regressions(unittest.TestCase):
        def test_R01_zero_read_on_identity_mismatch(self):
            changes = dict(st_dev=9, st_ino=9, st_size=8, st_nlink=2,
                           st_mtime_ns=101, st_mode=stat.S_IFREG | 0o400)
            for field, value in changes.items():
                for target in ("differential", "checked_hash"):
                    with self.subTest(field=field, target=target):
                        ns, p, f, events = project(source_bytes,
                            [observation(), observation()], [observation(**{field:value})], [])
                        out = {}
                        with self.assertRaisesRegex(ValueError, "^FILE_CHANGED$"):
                            if target == "differential":
                                ns[target](p, out)
                            else:
                                ns[target](p, single=False)
                        self.assertEqual(f.reads, 0)
                        self.assertEqual(p.opens, 1)
                        self.assertTrue(f.closed)
                        self.assertFalse(any(e[0] == "native" for e in events))
                        self.assertNotIn("sha256_observed_not_admitted", out)
                        if target == "differential":
                            self.assertIsNone(out["byte_count"])
                            self.assertIn(field, out["guard_deltas"]["S_A"])
            ns, p, f, events = project(source_bytes,
                [observation(st_ino=9), observation()], [], [])
            with self.assertRaisesRegex(ValueError, "^INITIAL_METADATA_DRIFT$"):
                ns["differential"](p, {})
            self.assertEqual((p.opens, f.reads), (0, 0))

        def test_R02_cross_field_inconsistency(self):
            for group, field, value in (("basic", "size_low", 8),
                    ("standard", "eof", 8), ("basic", "links", 2),
                    ("standard", "links", 2), ("basic", "attributes", 0x400)):
                with self.subTest(group=group, field=field):
                    n = native(); n[group][field] = value
                    ns, p, f, events = project(source_bytes,
                        [observation(), observation()], [observation()], [n])
                    out = {}
                    with self.assertRaisesRegex(ValueError, "^UNSAFE_HANDLE_INPUT$"):
                        ns["differential"](p, out)
                    self.assertEqual(f.reads, 0)
                    self.assertTrue(f.closed)
                    self.assertNotIn("sha256_observed_not_admitted", out)
            n = native(); del n["basic"]["links"]
            ns, p, f, events = project(source_bytes,
                [observation(), observation()], [observation()], [n])
            with self.assertRaisesRegex(ValueError, "^NATIVE_METADATA_INCOMPLETE$"):
                ns["differential"](p, {})
            self.assertEqual(f.reads, 0)
            self.assertTrue(f.closed)

        def test_R03_same_descriptor_no_reopen(self):
            expected_hash = hashlib.sha256(PAYLOAD).hexdigest().upper()
            for target in ("differential", "checked_hash"):
                with self.subTest(target=target):
                    ns, p, f, events = project(source_bytes,
                        [observation() for _ in range(3)],
                        [observation(), observation()], [native(), native()])
                    out = {}
                    if target == "differential":
                        ns[target](p, out)
                        self.assertEqual(out["sha256_observed_not_admitted"], expected_hash)
                        expected = [("open", "rb"), ("enter", 17), ("fstat", 17),
                            ("native", 17), ("read", 17, LIMIT+1), ("fstat", 17),
                            ("native", 17), ("close", 17)]
                    else:
                        self.assertEqual(ns[target](p), expected_hash)
                        expected = [("open", "rb"), ("enter", 17), ("fstat", 17),
                            ("read", 17, LIMIT+1), ("fstat", 17), ("close", 17)]
                    self.assertEqual([e for e in events if e[0] != "path"], expected)
                    self.assertEqual((p.opens, f.reads, f.closed), (1, 1, True))
    return unittest.TestSuite(CandidateV2Regressions(n) for n in (
        "test_R01_zero_read_on_identity_mismatch", "test_R02_cross_field_inconsistency",
        "test_R03_same_descriptor_no_reopen"))


if __name__ == "__main__":
    raise SystemExit("REVIEW_ONLY_EXECUTION_LOCKED")
