"""REVIEW ONLY. No tests or candidate code may execute without a separate admission.
Versioned V2 review proposal. Future authorized runner must supply exact Candidate V2 bytes in memory.
This module has no candidate import, filesystem read, native API, or launch path.
"""
import ast
import hashlib
import stat
import unittest
from copy import deepcopy
from types import SimpleNamespace

CANDIDATE_SHA = '139AEE6B2140206FAACE28F2F5B30048F26E3313BD057FAFEE1B4516825024BB'
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_nlink', 'st_mtime_ns', 'st_mode')
LIMIT = 64 * 1024 * 1024
PAYLOAD = b'fixture'


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


class CountOnly:
    """Bounded synthetic representation; no oversized byte allocation."""
    def __len__(self):
        return LIMIT + 1


class FakeFile:
    def __init__(self, data):
        self.data = data
        self.closed = False
        self.reads = []
    def __enter__(self): return self
    def __exit__(self, *unused): self.closed = True
    def fileno(self): return 17
    def read(self, n):
        self.reads.append(n)
        return self.data


class FakePath:
    name = 'synthetic.exe'
    def __init__(self, f): self.f = f; self.opens = []
    def __str__(self): return 'SYNTHETIC_ONLY/synthetic.exe'
    def open(self, mode):
        self.opens.append(mode)
        if mode != 'rb': raise AssertionError('non-read mode')
        return self.f


def _future_namespace(source_bytes, path_values, handle_values, native_values, data):
    """Future approved execution only: project exact selected AST nodes, not module import.
    This is not an OS sandbox and is intentionally not invoked at assembly time.
    """
    if hashlib.sha256(source_bytes).hexdigest().upper() != CANDIDATE_SHA:
        raise ValueError('CANDIDATE_DIGEST_MISMATCH')
    tree = ast.parse(source_bytes)
    names = {'digest', 'reparse', 'snapshot', 'differences', 'differential'}
    constants = {'LIMIT', 'GUARD_FIELDS', 'OBS_FIELDS'}
    nodes = [n for n in tree.body if (isinstance(n, ast.FunctionDef) and n.name in names)
             or (isinstance(n, ast.Assign) and len(n.targets) == 1 and
                 isinstance(n.targets[0], ast.Name) and n.targets[0].id in constants)]
    if tuple(n.name if isinstance(n, ast.FunctionDef) else n.targets[0].id for n in nodes) != (
            'LIMIT', 'digest', 'reparse', 'GUARD_FIELDS', 'OBS_FIELDS', 'snapshot', 'differences', 'differential'):
        raise ValueError('PROJECTION_SHAPE_MISMATCH')
    path_iter, handle_iter, native_iter = map(iter, (path_values, handle_values, native_values))
    calls = []
    def take(label, sequence):
        calls.append(label)
        item = next(sequence)
        if isinstance(item, Exception): raise item
        return item
    def guarded(p): return take('path', path_iter)
    def fstat(fd):
        if fd != 17: raise AssertionError('wrong synthetic descriptor')
        return take('fstat', handle_iter)
    def native_snapshot(fd):
        if fd != 17: raise AssertionError('wrong synthetic descriptor')
        return take('native', native_iter)
    ns = dict(__builtins__={'getattr':getattr,'bool':bool,'len':len,'any':any,'all':all,
                            'ValueError':ValueError,'str':str,'type':type,'int':int}, hashlib=hashlib, stat=stat,
              os=SimpleNamespace(fstat=fstat), guarded=guarded, native_snapshot=native_snapshot)
    exec(compile(ast.Module(body=nodes,type_ignores=[]), '<admitted-D2-projection>', 'exec'), ns)
    f = FakeFile(data)
    return ns, FakePath(f), f, calls


def build_suite(source_bytes):
    """No direct CLI. Call only through a separately approved offline supervisor."""
    if hashlib.sha256(source_bytes).hexdigest().upper() != CANDIDATE_SHA:
        raise ValueError('CANDIDATE_DIGEST_MISMATCH')
    class D2Synthetic(unittest.TestCase):
        def case(self, path=None, handle=None, natives=None, data=PAYLOAD, blocker=None):
            ns,p,f,calls = _future_namespace(source_bytes,
                path if path is not None else [observation() for _ in range(3)],
                handle if handle is not None else [observation(),observation()],
                natives if natives is not None else [native(),native()],data)
            out = {}
            if blocker is None:
                ns['differential'](p,out)
            else:
                with self.assertRaisesRegex(ValueError, '^'+blocker+'$'):
                    ns['differential'](p,out)
                self.assertNotIn('sha256_observed_not_admitted',out)
            self.assertTrue(all(x == 'rb' for x in p.opens))
            self.assertLessEqual(len(p.opens),1)
            self.assertLessEqual(len(f.reads),1)
            if not f.closed:
                self.assertEqual(p.opens,[])
            self.assertTrue(not p.opens or f.closed)
            return out,f,calls

        def test_stable_synthetic_observation(self):
            out,f,_ = self.case()
            self.assertTrue(out['d1_predicate_pass'])
            self.assertEqual(out['sha256_observed_not_admitted'],hashlib.sha256(PAYLOAD).hexdigest().upper())
            self.assertEqual(f.reads,[LIMIT+1])
        def test_each_guard_field_S_A(self):
            changes = dict(st_dev=9,st_ino=9,st_size=8,st_nlink=2,st_mtime_ns=101,st_mode=stat.S_IFREG|0o400)
            for key,value in changes.items():
                with self.subTest(field=key):
                    out,f,calls=self.case(path=[observation(),observation()],
                        handle=[observation(**{key:value})],natives=[],blocker='FILE_CHANGED')
                    self.assertIn(key,out['guard_deltas']['S_A'])
                    self.assertIs(out['d1_predicate_pass'],False)
                    self.assertIsNone(out['byte_count'])
                    self.assertIsNone(out['byte_limit_pass'])
                    self.assertIsNone(out['byte_count_matches_S'])
                    self.assertEqual(f.reads,[])
                    self.assertEqual(calls,['path','path','fstat'])
        def test_A_Z_drift(self):
            out,_,_=self.case(handle=[observation(),observation(st_mtime_ns=101)],blocker='FILE_CHANGED')
            self.assertIn('st_mtime_ns',out['guard_deltas']['A_Z'])
        def test_Z_F_drift(self):
            out,_,_=self.case(path=[observation(),observation(),observation(st_ino=99)],blocker='FILE_CHANGED')
            self.assertIn('st_ino',out['guard_deltas']['Z_F'])
        def test_initial_S_drift(self):
            out,f,calls=self.case(path=[observation(st_ino=99),observation()],
                handle=[],natives=[],blocker='INITIAL_METADATA_DRIFT')
            self.assertIsNone(out['d1_predicate_pass'])
            self.assertIsNone(out['byte_count'])
            self.assertNotIn('A',out['checkpoints'])
            self.assertEqual(f.reads,[])
            self.assertFalse(f.closed)  # no stream entered
            self.assertEqual(calls,['path','path'])
        def test_short_read(self):
            out,_,_=self.case(data=b'x',blocker='FILE_CHANGED')
            self.assertFalse(out['byte_count_matches_S']);self.assertTrue(out['byte_limit_pass'])
        def test_oversize_count(self):
            out,_,_=self.case(data=CountOnly(),blocker='FILE_CHANGED')
            self.assertFalse(out['byte_limit_pass'])
        def test_informational_timestamps(self):
            out,_,_=self.case(handle=[observation(st_ctime_ns=110,st_atime_ns=120),observation()])
            self.assertTrue(out['d1_predicate_pass']); self.assertIn('st_atime_ns',out['informational_deltas']['S_A'])
        def test_informational_attributes(self):
            out,_,_=self.case(handle=[observation(st_file_attributes=1),observation()])
            self.assertTrue(out['d1_predicate_pass']); self.assertIn('st_file_attributes',out['informational_deltas']['S_A'])
        def test_nonregular_path(self):
            out,f,_=self.case(path=[observation(st_mode=stat.S_IFDIR)],blocker='UNSAFE_HASH_INPUT')
            self.assertFalse(out['original_type_guard_pass']);self.assertEqual(f.reads,[])
        def test_guarded_reparse_rejection(self):
            _,f,_=self.case(path=[ValueError('REPARSE_OR_LINK')],blocker='REPARSE_OR_LINK')
            self.assertEqual(f.reads,[])
        def test_size_guard(self):
            _,f,_=self.case(path=[observation(),observation(st_size=LIMIT+1)],blocker='UNSAFE_HASH_INPUT')
            self.assertEqual(f.reads,[])
        def test_handle_reparse(self):
            _,f,_=self.case(handle=[observation(st_file_attributes=0x400)],blocker='UNSAFE_HANDLE_INPUT')
            self.assertEqual(f.reads,[])
        def test_delete_pending(self):
            n=native();n['standard']['delete_pending']=1
            _,f,_=self.case(natives=[n],blocker='UNSAFE_HANDLE_INPUT');self.assertEqual(f.reads,[])
        def test_initial_type_guard_preserved_on_later_rejection(self):
            out,f,calls=self.case(path=[observation(st_nlink=2),observation()],
                handle=[],natives=[],data=b'x',blocker='INITIAL_METADATA_DRIFT')
            self.assertFalse(out['original_type_guard_pass'])
            self.assertIsNone(out['d1_predicate_pass'])
            self.assertIsNone(out['byte_count'])
            self.assertEqual(f.reads,[])
            self.assertFalse(f.closed)
            self.assertEqual(calls,['path','path'])
        def test_native_A_error(self):
            n=native();n['errors']['basic']=5
            _,f,_=self.case(natives=[n],blocker='NATIVE_METADATA_INCOMPLETE');self.assertEqual(f.reads,[])
        def test_native_Z_error(self):
            n=native();n['errors']['streams']='INVALID_NEXT_OFFSET'
            self.case(natives=[native(),n],blocker='NATIVE_METADATA_INCOMPLETE')
        def test_native_identity_drift(self):
            n=native();n['basic']['index_low']=23
            out,_,_=self.case(natives=[native(),n],blocker='NATIVE_METADATA_DRIFT')
            self.assertIn('basic',out['native_handle_delta'])
        def test_native_stream_count_drift(self):
            n=native();n['stream_count']=2
            out,_,_=self.case(natives=[native(),n],blocker='NATIVE_METADATA_DRIFT')
            self.assertIn('stream_count',out['native_handle_delta'])
        def test_stable_multilink_is_not_admission(self):
            n=native();n['basic']['links']=2;n['standard']['links']=2
            out,_,_=self.case(path=[observation(st_nlink=2) for _ in range(3)],handle=[observation(st_nlink=2) for _ in range(2)],natives=[n,deepcopy(n)])
            self.assertFalse(out['original_type_guard_pass']);self.assertTrue(out['d1_predicate_pass'])
            self.assertNotIn('git_execution_authorized',out)
    return unittest.TestSuite(D2Synthetic(name) for name in (
        'test_A_Z_drift',
        'test_Z_F_drift',
        'test_delete_pending',
        'test_each_guard_field_S_A',
        'test_guarded_reparse_rejection',
        'test_handle_reparse',
        'test_informational_attributes',
        'test_informational_timestamps',
        'test_initial_S_drift',
        'test_initial_type_guard_preserved_on_later_rejection',
        'test_native_A_error',
        'test_native_Z_error',
        'test_native_identity_drift',
        'test_native_stream_count_drift',
        'test_nonregular_path',
        'test_oversize_count',
        'test_short_read',
        'test_size_guard',
        'test_stable_multilink_is_not_admission',
        'test_stable_synthetic_observation',
    ))


if __name__ == '__main__':
    raise SystemExit('REVIEW_ONLY_EXECUTION_LOCKED')
