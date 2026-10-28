# PoC Results — OE1104428478322
## Path Traversal in macOS pkgutil --expand via `..` in XAR filenames

### Vulnerability Summary

`pkgutil --expand` on macOS expands `.pkg` files (XAR archives) without sanitising
`../` sequences in the `<name>` field of the XAR table-of-contents XML.

A crafted `.pkg` (XAR) archive containing a filename like:

    ../../../../tmp/pwned_pkgutil

causes pkgutil to write a file **outside** the designated expansion directory on
macOS 26 (confirmed below). On macOS 27.0.1, the slash is not traversed but the
`..` sequences are still written verbatim to disk as a literal filename — see the
"Differential Analysis" section.

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

**Actual** (vulnerable) behaviour on macOS 26: pkgutil writes the payload to
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

---

## GitHub Actions CI Results

Both runs used the same `poc.xar` (399 bytes, SHA-1 checksum). Logs are in this directory.

### macOS 26.6.2 — VULNERABLE

| Item | Value |
|------|-------|
| macOS version | 26.6.2 |
| BuildVersion | 25G83 |
| Architecture | arm64 |
| pkgutil binary | `/usr/sbin/pkgutil` (universal: x86_64 + arm64e) |
| pkgutil exit code | 0 |
| **Result** | **VULNERABLE** |
| Evidence | `/tmp/pwned_pkgutil` created outside `/tmp/safe_expand_dir` |

Log: `poc_terminal_log.txt`

```
RESULT: VULNERABLE
File written OUTSIDE expansion directory:
-rw-r--r--  1 runner  staff  42 Oct 28 12:13 /tmp/pwned_pkgutil
Contents: pwned via pkgutil --expand path traversal
```

### macOS 27.0.1 — Partial Mitigation (Incomplete Fix)

| Item | Value |
|------|-------|
| macOS version | 27.0.1 |
| BuildVersion | 26A434 |
| Architecture | arm64 |
| pkgutil binary | `/usr/sbin/pkgutil` (universal: x86_64 + arm64e + arm64e.x1) |
| pkgutil exit code | 0 |
| **Result** | **PARTIAL MITIGATION — not a complete fix** |
| `/tmp/pwned_pkgutil` created | No |

Log: `poc_terminal_log_macos-27.txt`

**Differential Analysis:**

On macOS 27.0.1, pkgutil no longer traverses the `../` sequences across directory
boundaries. However, it does **not** reject or sanitise the malicious filename —
instead it writes a file whose literal name contains the `..` sequences, with slashes
replaced by colons:

```
/tmp/safe_expand_dir/..:..:..:..:tmp:pwned_pkgutil
```

This confirms that:
1. macOS 27 changed the path-joining behaviour (slashes → colons), preventing
   escape from the destination directory.
2. The `<name>` field is **still accepted verbatim** without validation or rejection.
3. An attacker who controls the archive can still write files with arbitrary
   colon-separated names inside the expansion directory.
4. The root cause (unsanitised `<name>` field) was not properly fixed — the mitigation
   is a side-effect of filesystem path handling, not an input validation fix.

Whether this colon-filename behaviour constitutes a separate issue is left to Apple's
determination.

---

## Scope Summary

| macOS | Build | Arbitrary write outside dir | Accepts traversal name |
|-------|-------|----|----|
| 26.6.2 | 25G83 | ✅ YES — VULNERABLE | ✅ YES |
| 27.0.1 | 26A434 | ❌ No | ✅ YES (writes literal `..:..:` name) |
