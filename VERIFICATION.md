# Release Integrity Verification

## 1. Scope and fixed reference

This guide verifies the contents of **DQ-D2-V2**, the initial scoped public research evidence release. It is an integrity check, not a security assessment or a reproduction of the recorded experiments.

| Reference | Value |
| --- | --- |
| Release | [`v0.1.0-research`](https://github.com/abdalrahman-alakhras/digital-qareen-research/releases/tag/v0.1.0-research) |
| Public commit | [`0867c28a807a96b8e65a2900903dc213cfb91e2a`](https://github.com/abdalrahman-alakhras/digital-qareen-research/tree/0867c28a807a96b8e65a2900903dc213cfb91e2a) |
| Public root tree | `5a6c221143e1224c645e5a38cb89ee95435c8f74` |
| Original release inventory | 12 regular files; 65,693 uncompressed file bytes |
| Original research subset | 9 files; 57,602 bytes |

This guide is a subsequent documentation addition. It is intentionally outside the original tagged twelve-file inventory. Do not verify a changing `main` archive against these fixed pins.

## 2. Acquire the reference archive

Download the [ZIP of the exact public commit](https://github.com/abdalrahman-alakhras/digital-qareen-research/archive/0867c28a807a96b8e65a2900903dc213cfb91e2a.zip). The [tagged release ZIP](https://github.com/abdalrahman-alakhras/digital-qareen-research/archive/refs/tags/v0.1.0-research.zip) is an alternative, provided the tag still resolves to the same commit.

Inspect the [tag ref](https://api.github.com/repos/abdalrahman-alakhras/digital-qareen-research/git/ref/tags/v0.1.0-research) and [recursive tree](https://api.github.com/repos/abdalrahman-alakhras/digital-qareen-research/git/trees/5a6c221143e1224c645e5a38cb89ee95435c8f74?recursive=1) to corroborate the reference and inventory. If the tag moves, do not treat its new contents as the original release.

The ZIP container's own bytes can vary with archive generation. Verify member bytes, not the compressed archive hash. Do not normalize line endings or edit the files before checking them.

## 3. Offline verifier (Python standard library)

Use a trusted Python 3.9+ installation. Save the following code in a separate file called `verify_release.py`, outside the archive and repository. Review it before running it. It reads a ZIP directly, checks all twelve file paths, byte counts, SHA-256 digests and Git blob SHA-1 identifiers, and rejects unexpected files and non-regular member types. It does not extract the archive, import project modules, execute diagnostics, modify the repository, or connect to the network. Run it on the known release archive, not arbitrary untrusted input.

```python
import hashlib
import stat
import sys
import zipfile

# path: (raw byte count, SHA-256, Git blob SHA-1)
EXPECTED = {
    'PROVENANCE.json': (4229, '31049a8b1ea6df8006fa00e85aa79a4a07526e4e9aa8bd35ad8ada65e19c6fc4', 'dc45c6a7947773369d01e97ad1a20f900197e0d2'),
    'README.md': (3128, '7b92cae3634a01d4ea3c2d0b92de604ed39274d6a1065ae4daed06ce0d5ea0ab', '50b243b7329d5142fb2cc93ed281e1e7a791f420'),
    'RIGHTS.md': (734, '22f5fe5ecd47c0495f5b6c3a53525a8b13623ddd4f2c314fe048c5f6447e29ca', '562b6358603f877afd90d560ef0a7bd3d2ddcdae'),
    'diagnostics/dq_d2_v2/Acceptance_Crosswalk_V2.json': (3670, 'd8f982f492f4a4db70564776b5084c5c129ce490b0da4a256b3fd73dc96a0859', '6a6418d6b25ab4d1e6ecaacaf7405318ca399642'),
    'diagnostics/dq_d2_v2/DQ_I1B2_D2_Metadata_Differential_V2.py': (13859, '139aee6b2140206faace28f2f5b30048f26e3313bd057fafee1b4516825024bb', 'b8c1384c788d049c3939f553f07e46af62d5493c'),
    'diagnostics/dq_d2_v2/README.md': (3271, 'dbacfd026a2039197cdd477ea0f5b8c1aace977e01ce90ad9bf98758f9c90162', '1205b14078a445c6b2c76d7050241a6dc974be6a'),
    'diagnostics/dq_d2_v2/Regression_Verification_Receipt.json': (2590, '61c9d59870b451f6db10e3a00a41dd6f4b84106e60721d66a66cca447354980c', 'c6b6edfb1d96071494071a7ed3029d9ce8793917'),
    'diagnostics/dq_d2_v2/Synthetic_Acceptance_Harness_V2.py': (12120, 'db292473f366ed115be554f97b991ccaa0dc70b2021dc2c864070d554b198427', '7b21f179b1fb099a3782d315b2ce27c6438c4a76'),
    'diagnostics/dq_d2_v2/T10_Fixture_Plan_V2.json': (7496, '542cd6c71f87fccdaa75b06c73a07a95eec8336fd3894b432806d99dc5aa2620', 'ce9c16debe45ac960e1f08d30afc2b331aee9648'),
    'diagnostics/dq_d2_v2/T10_Fixture_Plan_V2.schema.json': (3221, '075349815c1f1fe24e818cb69d22d74d1b358910104768366ecd5f5dc8f60d87', '14b88678ca558b444a70d98164bec9f170fe38c1'),
    'diagnostics/dq_d2_v2/Verification_Receipt.json': (2607, 'b792f39ccd9db36293c7f32eb793c55edec96dfe14eb075da98445603e8dcb47', '3c4922c02c6ce18063bc01bc67663c6271c72fbc'),
    'diagnostics/dq_d2_v2/test_candidate_v2_regressions.py': (8768, 'b7873fe5e594ec6ec22f0ad4b31f16906ade5aefeea0aa623eba72889a7bd72f', '553f83fe2da39934c450bdfbf31045445f08185e'),
}
TOTAL = 65693


def verify(archive):
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if not 12 <= len(entries) <= 32:
            raise ValueError("Unexpected entry count")
        names = set()
        for e in entries:
            n = e.orig_filename
            parts = n.rstrip("/").split("/")
            if (n != e.filename or not n or "\\" in n or ":" in n
                    or any(p in ("", ".", "..") for p in parts)
                    or n in names):
                raise ValueError("Invalid or duplicate archive path")
            names.add(n)
            kind = stat.S_IFMT(e.external_attr >> 16)
            if kind not in (0, stat.S_IFDIR if e.is_dir() else stat.S_IFREG):
                raise ValueError("Non-regular archive member")
            if e.flag_bits & 1 or (e.is_dir() and e.file_size != 0):
                raise ValueError("Encrypted member or invalid directory")

        blobs = [e for e in entries if not e.is_dir()]
        raw_paths = {e.filename for e in blobs}
        if raw_paths == set(EXPECTED):
            prefix = ""
        else:
            roots = {p.split("/", 1)[0] for p in raw_paths}
            if len(roots) != 1:
                raise ValueError("Unexpected archive layout")
            prefix = next(iter(roots)) + "/"
        expected_paths = {prefix + p for p in EXPECTED}
        if raw_paths != expected_paths or len(blobs) != len(EXPECTED):
            raise ValueError("Missing, extra or duplicate file")
        allowed_dirs = {"/".join(p.split("/")[:i]) + "/"
                        for p in expected_paths
                        for i in range(1, len(p.split("/")))}
        if any(e.filename not in allowed_dirs for e in entries if e.is_dir()):
            raise ValueError("Unexpected directory")
        if sum(e.file_size for e in blobs) != TOTAL:
            raise ValueError("Unexpected total byte count")

        for e in sorted(blobs, key=lambda item: item.filename):
            path = e.filename[len(prefix):]
            size, sha256, oid = EXPECTED[path]
            if e.file_size != size:
                raise ValueError("Size mismatch: " + path)
            data = z.read(e)
            if len(data) != size or hashlib.sha256(data).hexdigest() != sha256:
                raise ValueError("SHA-256 mismatch: " + path)
            header = f"blob {size}\0".encode("ascii")
            if hashlib.sha1(header + data, usedforsecurity=False).hexdigest() != oid:
                raise ValueError("Git blob OID mismatch: " + path)
            print("OK", path)
    print("PASS: 12/12 files, 65693 bytes, SHA-256 and Git blob OIDs matched.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python -I verify_release.py <release.zip>")
    try:
        verify(sys.argv[1])
    except Exception as exc:
        sys.exit("FAIL: " + str(exc))
```

Run in a terminal (substitute the actual ZIP filename or absolute path):

```sh
python -I verify_release.py "release.zip"
```

On Windows, `py -3 -I` can be used instead of `python -I` if the Python launcher is installed. A successful run ends with:

```text
PASS: 12/12 files, 65693 bytes, SHA-256 and Git blob OIDs matched.
```

A nonzero exit or `FAIL` means the archive has not passed this verification. Do not repair or normalize its contents to force a match. Obtain a clean archive from the fixed commit and investigate any persistent mismatch. Partial `OK` lines are not a successful overall result.

## 4. Independent manual cross-check

The original [PROVENANCE.json](https://github.com/abdalrahman-alakhras/digital-qareen-research/blob/0867c28a807a96b8e65a2900903dc213cfb91e2a/PROVENANCE.json) records the nine diagnostic artifacts. The verifier additionally pins the three top-level files, including the provenance manifest itself; it does not trust hash values read from the input ZIP. To check one safely downloaded raw file in PowerShell, for example:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath 'PROVENANCE.json'
```

Expected SHA-256: `31049a8b1ea6df8006fa00e85aa79a4a07526e4e9aa8bd35ad8ada65e19c6fc4`.

Git blob OIDs use SHA-1 over the Git blob header and raw bytes; they are not raw SHA-1 file hashes. SHA-256 is the additional raw-content integrity check. These pins provide consistency against a fixed reference, not an independent signature, trusted timestamp, author authentication or proof that the private canonical history has the reported ancestry. Obtain reference pins through a channel you independently trust if authenticity is required.

The original manifest retains its packaging-time status (`PREPARED_FOR_PRIVATE_REPOSITORY_REVIEW`, `public_clearance: false`, `public_repository_created: false`). Those fields are historical records, not a live description of current GitHub visibility. The public release is separate from the owner-reported canonical local commit; that private commit and its ancestors are not included or independently verifiable from this repository.

## 5. What a successful result does not establish

- The recorded synthetic acceptance and targeted regression results are not rerun by this guide.
- The complete original controlled runner and external enforcement evidence are not included.
- Native Windows T10 remains `NOT_RUN`.
- OS containment, memory isolation, end-to-end authorization and production security certification remain unestablished.
- No permission to run the diagnostic against a live environment is conferred. See the original [rights notice](https://github.com/abdalrahman-alakhras/digital-qareen-research/blob/0867c28a807a96b8e65a2900903dc213cfb91e2a/RIGHTS.md).

AI Can Propose.  
Policy Must Authorize.  
Infrastructure Must Enforce.  
Evidence Must Prove.
