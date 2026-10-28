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

`poc.xar` is a minimal, hand-built XAR archive (306 bytes):

| Field | Value |
|-------|-------|
| Magic | `0x78617221` ('xar!') |
| Header size | 28 bytes |
| Version | 1 |
| Checksum algorithm | 0 (none) |
| Embedded filename | `../../../../tmp/pwned_pkgutil` |
| Payload content | `pwned via pkgutil --expand path traversal\n` |

### Expected Behaviour

Running:

    pkgutil --expand poc.xar /tmp/safe_expand_dir

**should** write all extracted content under `/tmp/safe_expand_dir/`.

**Actual** (vulnerable) behaviour: pkgutil writes the payload to
`/tmp/pwned_pkgutil` — four directory levels above the expand root —
demonstrating an arbitrary file write primitive.

### Reproduction Steps

```bash
python3 build_poc_xar.py          # produces poc.xar
pkgutil --expand poc.xar /tmp/safe_expand_dir
ls -la /tmp/pwned_pkgutil         # should NOT exist; if it does → VULNERABLE
cat /tmp/pwned_pkgutil
```

### GitHub Actions Results

See `poc_terminal_log.txt` in this directory for the raw CI output,
including macOS version (`sw_vers`), pkgutil path, TOC dump, and
out-of-bounds check.
