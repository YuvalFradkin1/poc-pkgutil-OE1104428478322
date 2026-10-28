# PoC Results — OE1104428478322
## Path Traversal in macOS pkgutil --expand via `..` in XAR filenames

### Vulnerability Summary

`pkgutil --expand` on macOS expands `.pkg` files (XAR archives) without sanitising
`../` sequences in the `<name>` field of the XAR table-of-contents XML.

A crafted `.pkg` (XAR) archive containing a filename like:

    ../../../../tmp/pwned_pkgutil

causes pkgutil to write a file **outside** the designated expansion directory.

### Root Cause

The XAR format stores filenames in a zlib-compressed XML TOC embedded in the archive.
`pkgutil --expand` extracts the `<name>` field from each `<file>` entry and appends it
directly to the destination path with no canonicalisation or `../` filtering.

Relevant Apple open-source reference (pkgutil / xar):
- https://github.com/apple-oss-distributions/xar

### Crafted Archive

`poc.xar` is a minimal, hand-built XAR archive (399 bytes):

| Field | Value |
|-------|-------|
| Magic | `0x78617221` ('xar!') |
| Header size | 28 bytes |
| Version | 1 |
| Checksum algorithm | 1 (SHA-1) |
| TOC checksum | SHA-1 of compressed TOC, stored at heap offset 0 (20 bytes) |
| Embedded filename | `../../../../tmp/pwned_pkgutil` |
| Payload content | `pwned via pkgutil --expand path traversal\n` (42 bytes) |

> **Note:** macOS 26.6.2 `pkgutil` enforces a non-zero checksum algorithm — archives
> with `checksum style="none"` are rejected with "Archive uses no hashing algorithm,
> aborting". `poc.xar` therefore uses a valid SHA-1 checksum over the compressed TOC.

### Expected Behaviour

Running:

    pkgutil --expand poc.xar /tmp/safe_expand_dir

**should** write all extracted content under `/tmp/safe_expand_dir/`.

**Actual** (vulnerable) behaviour: pkgutil writes the payload to
`/tmp/pwned_pkgutil` — four directory levels above the expand root —
demonstrating an arbitrary file write primitive.

### Reproduction Steps

```bash
python3 build_poc_xar.py          # produces poc.xar (399 bytes)
pkgutil --expand poc.xar /tmp/safe_expand_dir
ls -la /tmp/pwned_pkgutil         # should NOT exist; if it does → VULNERABLE
cat /tmp/pwned_pkgutil
```

> **Important:** Do **not** pre-create `/tmp/safe_expand_dir` before running pkgutil.
> pkgutil creates the destination directory itself and exits with `Error 17 (EEXIST)`
> if it already exists.

### GitHub Actions CI Results

The workflow `.github/workflows/poc.yml` ran on the `macos-latest` GitHub Actions runner
and confirmed the vulnerability.

| Item | Value |
|------|-------|
| **macOS version** | 26.6.2 |
| **BuildVersion** | 25G83 |
| **Architecture** | arm64 |
| **pkgutil binary** | `/usr/sbin/pkgutil` (universal: x86_64 + arm64e) |
| **pkgutil exit code** | 0 |
| **Result** | **VULNERABLE** |
| **Evidence** | `/tmp/pwned_pkgutil` created outside `/tmp/safe_expand_dir` |

Raw CI output is in `poc_terminal_log.txt`.

### Scope Note — Versions Tested

This CI run confirms the vulnerability on **macOS 26.6.2 (Tahoe, build 25G83)**.

**macOS 27.x (beta)** has not been tested via this CI run. GitHub Actions does not
currently offer `macos-27` runners; the `macos-latest` image resolves to 26.6.2 at
the time of this run. The vulnerability is in the `pkgutil`/`xar` extraction path,
which has not changed significantly between releases, but reproduction on macOS 27.0
and 27.2 beta would require access to a device running those builds.
