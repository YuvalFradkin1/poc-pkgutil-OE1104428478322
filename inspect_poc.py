#!/usr/bin/env python3
"""
inspect_poc.py — dump the embedded filename(s) from a hand-crafted XAR archive.
Used by the GitHub Actions workflow to verify the malicious name is present in poc.xar.
"""
import sys, struct, zlib

def inspect(path):
    with open(path, "rb") as f:
        data = f.read()

    magic, hdr_size, version, toc_comp_len, toc_uncomp_len, cksum_alg = struct.unpack_from(">IHHqqI", data, 0)
    assert magic == 0x78617221, f"bad magic: {magic:#x}"

    toc_raw = data[hdr_size : hdr_size + toc_comp_len]
    toc_xml = zlib.decompress(toc_raw).decode("utf-8")

    print("=== XAR TOC ===")
    print(toc_xml)

    import re
    names = re.findall(r"<name>(.*?)</name>", toc_xml)
    print("=== Embedded filenames ===")
    for n in names:
        print(f"  {n!r}")
        if ".." in n:
            print(f"  ^^^ PATH TRAVERSAL SEQUENCE DETECTED")

if __name__ == "__main__":
    inspect(sys.argv[1] if len(sys.argv) > 1 else "poc.xar")
