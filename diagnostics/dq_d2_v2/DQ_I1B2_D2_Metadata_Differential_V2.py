"""D2 review candidate. No CLI execution clearance. No Git invocation or extraction."""
import argparse, hashlib, json, os, shutil, stat, sys
from pathlib import Path
SCRIPT_SHA = 'A7DC49EFD639B8933BB03AEE6FE932307030750956298371A1F1B8A29D2CF24E'
INDEX_SHA = '804860BF6F9B5A8B3D3709F780F25BA68DD029D123A87948326E370EC9DFC4B5'
SEC_SHA = '6503EFF78EDD08531760C65D06EBCC48880E764CBB8834B06B874AE0CF762533'
LIMIT = 64 * 1024 * 1024

def digest(b): return hashlib.sha256(b).hexdigest().upper()
def reparse(s): return stat.S_ISLNK(s.st_mode) or bool(getattr(s, 'st_file_attributes', 0) & 0x400)
def guarded(p):
    for q in (p, *p.parents):
        if reparse(q.lstat()): raise ValueError('REPARSE_OR_LINK')
    return p.lstat()
def checked_hash(p, single=True):
    s=guarded(p)
    if not stat.S_ISREG(s.st_mode) or (single and s.st_nlink != 1) or not 0 <= s.st_size <= LIMIT: raise ValueError('UNSAFE_HASH_INPUT')
    def sig(x): return (x.st_dev,x.st_ino,x.st_size,x.st_nlink,x.st_mtime_ns,x.st_mode)
    with p.open('rb') as f:
        a=os.fstat(f.fileno())
        if not stat.S_ISREG(a.st_mode) or reparse(a) or (single and a.st_nlink != 1) or not 0 <= a.st_size <= LIMIT:
            raise ValueError('UNSAFE_HANDLE_INPUT')
        if sig(s)!=sig(a):
            raise ValueError('FILE_CHANGED')
        b=f.read(LIMIT+1); z=os.fstat(f.fileno())
        if not stat.S_ISREG(z.st_mode) or reparse(z) or (single and z.st_nlink != 1) or not 0 <= z.st_size <= LIMIT:
            raise ValueError('UNSAFE_HANDLE_INPUT')
    if len(b)>LIMIT or len(b)!=s.st_size or not sig(s)==sig(a)==sig(z)==sig(guarded(p)): raise ValueError('FILE_CHANGED')
    return digest(b)

D1_SHA = '53722756FD745BF226F31788CCE6C286B083F8178BF0707C2B0DE386A3422024'
CONSOLE_SHA = '8B847AF2C67E1BF643DD12D3B25943D06D2DA533771362CC238196DF87635CF5'
GUARD_FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_nlink', 'st_mtime_ns', 'st_mode')
OBS_FIELDS = GUARD_FIELDS + ('st_ctime_ns', 'st_atime_ns', 'st_birthtime_ns', 'st_file_attributes', 'st_reparse_tag')
STREAM_BUFFER = 65536


def snapshot(s):
    return {key: getattr(s, key, None) for key in OBS_FIELDS}


def differences(left, right, fields):
    return {key: {'left': left.get(key), 'right': right.get(key)}
            for key in fields if left.get(key) != right.get(key)}


def native_snapshot(fd):
    """Same open file handle; no additional file open; no stream names emitted."""
    import ctypes as c
    import ctypes.wintypes as w
    import msvcrt
    import struct

    class HandleInfo(c.Structure):
        _fields_ = [('attributes', w.DWORD), ('created', w.FILETIME),
                    ('accessed', w.FILETIME), ('written', w.FILETIME),
                    ('volume', w.DWORD), ('size_high', w.DWORD),
                    ('size_low', w.DWORD), ('links', w.DWORD),
                    ('index_high', w.DWORD), ('index_low', w.DWORD)]

    class StandardInfo(c.Structure):
        _fields_ = [('allocation', c.c_int64), ('eof', c.c_int64),
                    ('links', w.DWORD), ('delete_pending', c.c_ubyte),
                    ('directory', c.c_ubyte)]

    # Explicit system DLL search; no shell, executable invocation or fallback.
    k = c.WinDLL('kernel32.dll', use_last_error=True, winmode=0x00000800)
    get_basic = k.GetFileInformationByHandle
    get_basic.argtypes = [w.HANDLE, c.POINTER(HandleInfo)]
    get_basic.restype = w.BOOL
    get_ex = k.GetFileInformationByHandleEx
    get_ex.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
    get_ex.restype = w.BOOL
    h = w.HANDLE(msvcrt.get_osfhandle(fd))
    out = {'errors': {}}
    basic = HandleInfo()
    if get_basic(h, c.byref(basic)):
        out['basic'] = {name: int(getattr(basic, name)) for name in
                        ('attributes', 'volume', 'size_high', 'size_low', 'links', 'index_high', 'index_low')}
    else:
        out['errors']['basic'] = c.get_last_error()
    standard = StandardInfo()
    if get_ex(h, 1, c.byref(standard), c.sizeof(standard)):
        out['standard'] = {name: int(getattr(standard, name)) for name in
                           ('allocation', 'eof', 'links', 'delete_pending', 'directory')}
    else:
        out['errors']['standard'] = c.get_last_error()
    # FILE_STREAM_INFO records: DWORD offset, DWORD name length, two LARGE_INTEGERs.
    # Use 8-byte aligned storage, a fixed ceiling, and no automatic enlargement/retry.
    buf = (c.c_uint64 * (STREAM_BUFFER // 8))()
    if not get_ex(h, 7, c.byref(buf), STREAM_BUFFER):
        out['errors']['streams'] = c.get_last_error()
    else:
        data = bytes(buf); pos = 0; count = 0
        while True:
            if pos + 24 > STREAM_BUFFER:
                out['errors']['streams'] = 'TRUNCATED_HEADER'; break
            nxt, name_len, size, allocation = struct.unpack_from('<IIqq', data, pos)
            end = pos + 24 + name_len
            if not name_len or name_len % 2 or end > STREAM_BUFFER or size < 0 or allocation < 0:
                out['errors']['streams'] = 'INVALID_RECORD'; break
            count += 1
            if not nxt:
                out['stream_count'] = count; break
            if nxt % 8 or nxt < 24 + name_len or pos + nxt + 24 > STREAM_BUFFER:
                out['errors']['streams'] = 'INVALID_NEXT_OFFSET'; break
            pos += nxt
    return out


def differential(p, out):
    initial = guarded(p)
    out['initial_path'] = snapshot(initial)
    out['original_type_guard_pass'] = stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1
    out['resolved_path_sha256'] = digest(str(p).encode('utf-8'))
    out['basename'] = p.name
    if not stat.S_ISREG(initial.st_mode):
        raise ValueError('UNSAFE_HASH_INPUT')
    s = guarded(p)
    out['checkpoints'] = {'S': snapshot(s)}
    if not stat.S_ISREG(s.st_mode) or not 0 <= s.st_size <= LIMIT:
        raise ValueError('UNSAFE_HASH_INPUT')
    # An early abort leaves byte counts and the full legacy predicate unevaluated.
    out.update(byte_count=None, byte_limit_pass=None, byte_count_matches_S=None,
               d1_signature_pass=None, d1_predicate_pass=None)
    if differences(out['initial_path'], out['checkpoints']['S'], GUARD_FIELDS):
        raise ValueError('INITIAL_METADATA_DRIFT')

    def require_native_coherence(label, py, native):
        # native_snapshot returns integers from fixed-width native structures.
        # Do not equate Python device/inode representations to Win32 volume/index.
        if native.get('errors'):
            raise ValueError('NATIVE_METADATA_INCOMPLETE')
        basic = native.get('basic', {}); std = native.get('standard', {})
        bkeys = ('attributes', 'volume', 'size_high', 'size_low', 'links', 'index_high', 'index_low')
        skeys = ('allocation', 'eof', 'links', 'delete_pending', 'directory')
        if (not all(type(basic.get(k)) is int for k in bkeys)
                or not all(type(std.get(k)) is int for k in skeys)
                or type(native.get('stream_count')) is not int):
            raise ValueError('NATIVE_METADATA_INCOMPLETE')
        if (not all(0 <= basic[k] <= 0xFFFFFFFF for k in bkeys)
                or not 0 <= std['links'] <= 0xFFFFFFFF
                or not 0 <= std['allocation'] <= 0x7FFFFFFFFFFFFFFF
                or std['delete_pending'] not in (0, 1) or std['directory'] not in (0, 1)
                or native['stream_count'] < 1):
            raise ValueError('UNSAFE_HANDLE_INPUT')
        if (not stat.S_ISREG(py.st_mode) or reparse(py) or not 0 <= py.st_size <= LIMIT
                or basic['attributes'] & (0x400 | 0x10) or std['directory']
                or std['delete_pending'] or not 0 <= std['eof'] <= LIMIT):
            raise ValueError('UNSAFE_HANDLE_INPUT')
        size = (basic['size_high'] << 32) | basic['size_low']
        coherence = {'size': size == std['eof'] == py.st_size,
                     'links': basic['links'] == std['links'] == py.st_nlink and py.st_nlink >= 1}
        out.setdefault('native_coherence', {})[label] = coherence
        if not all(coherence.values()):
            raise ValueError('UNSAFE_HANDLE_INPUT')

    # Preserve D1 target's single=False; this does not admit a multi-link executable.
    with p.open('rb') as f:
        a = os.fstat(f.fileno())
        out['checkpoints']['A'] = snapshot(a)
        out['guard_deltas'] = {'S_A': differences(out['checkpoints']['S'], out['checkpoints']['A'], GUARD_FIELDS)}
        out['informational_deltas'] = {'S_A': differences(out['checkpoints']['S'], out['checkpoints']['A'], OBS_FIELDS[len(GUARD_FIELDS):])}
        if not stat.S_ISREG(a.st_mode) or reparse(a) or not 0 <= a.st_size <= LIMIT:
            raise ValueError('UNSAFE_HANDLE_INPUT')
        if out['guard_deltas']['S_A']:
            out.update(d1_signature_pass=False, d1_predicate_pass=False)
            raise ValueError('FILE_CHANGED')
        out['native_A'] = native_snapshot(f.fileno())
        require_native_coherence('A', a, out['native_A'])
        b = f.read(LIMIT + 1)
        z = os.fstat(f.fileno())
        out['checkpoints']['Z'] = snapshot(z)
        out['native_Z'] = native_snapshot(f.fileno())
    final = guarded(p)
    out['checkpoints']['F'] = snapshot(final)
    pairs = (('S', 'A'), ('A', 'Z'), ('Z', 'F'), ('S', 'F'))
    out['guard_deltas'] = {f'{l}_{r}': differences(out['checkpoints'][l], out['checkpoints'][r], GUARD_FIELDS) for l, r in pairs}
    out['informational_deltas'] = {f'{l}_{r}': differences(out['checkpoints'][l], out['checkpoints'][r], OBS_FIELDS[len(GUARD_FIELDS):]) for l, r in pairs}
    out['native_handle_delta'] = differences(out['native_A'], out['native_Z'], ('basic', 'standard', 'stream_count', 'errors'))
    out['byte_count'] = len(b)
    out['byte_limit_pass'] = len(b) <= LIMIT
    out['byte_count_matches_S'] = len(b) == s.st_size
    out['d1_signature_pass'] = not any(out['guard_deltas'].values())
    out['d1_predicate_pass'] = all(out[k] for k in ('byte_limit_pass', 'byte_count_matches_S', 'd1_signature_pass'))
    if not out['d1_predicate_pass']:
        raise ValueError('FILE_CHANGED')
    if out['native_Z'].get('errors'):
        raise ValueError('NATIVE_METADATA_INCOMPLETE')
    require_native_coherence('Z', z, out['native_Z'])
    if out['native_handle_delta']:
        raise ValueError('NATIVE_METADATA_DRIFT')
    if differences(out['initial_path'], out['checkpoints']['S'], GUARD_FIELDS):
        raise ValueError('INITIAL_METADATA_DRIFT')
    out['sha256_observed_not_admitted'] = digest(b)
    # One read is not evidence of byte-level divergence across time.


def review_candidate(repo, downloads):
    """Future callable only; no CLI dispatch. Requires separate approved external supervisor."""
    import ctypes
    r = {'gate': 'G4-A16-P3-I1-B2-D2', 'status': 'BLOCKED', 'git_invocations': 0,
         'source_extracted': False, 'retry_authorized': False, 'git_execution_authorized': False,
         'publisher_trust': 'NOT_ESTABLISHED', 'content_mutation': 'NOT_ESTABLISHED'}
    before = None
    try:
        if not (os.name == 'nt' and sys.version_info[:3] == (3,14,0) and sys.flags.isolated and sys.dont_write_bytecode and not ctypes.windll.shell32.IsUserAnAdmin()):
            raise ValueError('WINDOWS_RUNTIME_REQUIRED')
        d = Path(downloads).absolute(); repo = Path(repo).absolute(); gd = repo / '.git'
        if d.is_relative_to(repo) or repo.is_relative_to(d):
            raise ValueError('EXTERNAL_LOCATION')
        if Path(sys.executable).resolve() != (d/'DQ_R11_D2_A2_Provision_1cdb69a916ba40aea442db612e189f36/venv/Scripts/python.exe').resolve(strict=True):
            raise ValueError('APPROVED_PYTHON_REQUIRED')
        if os.path.lexists(gd/'index.lock'):
            raise ValueError('FOREIGN_INDEX_LOCK')
        def pins():
            return {'index': checked_hash(gd/'index'), 'original_supervisor': checked_hash(d/'DQ_I1B2_Source_Only.py'), 'sec_receipt': checked_hash(d/'DQ_G4_A16_P3_SEC_AC_EXECUTION_01/P3_SEC_AC_Local_Receipt.json'), 'd1': checked_hash(d/'DQ_I1B2_D1_Git_Metadata.py'), 'd1_console': checked_hash(d/'DQ_I1B2_D1_Console_Reconstruction.json')}
        before = pins(); r['before'] = before
        if before != {'index': INDEX_SHA, 'original_supervisor': SCRIPT_SHA, 'sec_receipt': SEC_SHA, 'd1': D1_SHA, 'd1_console': CONSOLE_SHA}:
            raise ValueError('ANCHOR_MISMATCH')
        found = shutil.which('git.exe')
        if not found:
            raise ValueError('GIT_NOT_FOUND')
        raw = Path(found).absolute()
        guarded(raw)  # Added: detect reparse ancestors before resolve, not after only.
        p = raw.resolve(strict=True)
        if p.is_relative_to(repo) or p.is_relative_to(d):
            raise ValueError('GIT_EXECUTABLE_LOCATION')
        r['resolved_git'] = {}
        differential(p, r['resolved_git'])
        r['status'] = 'METADATA_COMPLETE_PENDING_REVIEW'
    except Exception as ex:
        allowed = {'REPARSE_OR_LINK','UNSAFE_HASH_INPUT','FILE_CHANGED','WINDOWS_RUNTIME_REQUIRED','EXTERNAL_LOCATION','APPROVED_PYTHON_REQUIRED','ANCHOR_MISMATCH','GIT_NOT_FOUND','GIT_EXECUTABLE_LOCATION','FOREIGN_INDEX_LOCK','UNSAFE_HANDLE_INPUT','NATIVE_METADATA_INCOMPLETE','NATIVE_METADATA_DRIFT','INITIAL_METADATA_DRIFT'}
        r['blocker'] = str(ex) if type(ex) is ValueError and str(ex) in allowed else type(ex).__name__
        r['primary_blocker'] = r['blocker']
    finally:
        if before is not None:
            try:
                r['after'] = pins(); r['anchors_unchanged'] = r['after'] == before
                if not r['anchors_unchanged'] or os.path.lexists(gd/'index.lock'):
                    r.update(status='BLOCKED', blocker='ANCHOR_DRIFT')
            except Exception:
                r.update(status='BLOCKED', blocker='POSTFLIGHT_FAILED')
        r['git_execution_authorized'] = False
    return r


if __name__ == '__main__':
    print('REVIEW_ONLY_EXECUTION_LOCKED')
    raise SystemExit(1)
