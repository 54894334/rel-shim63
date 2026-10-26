#!/usr/bin/env python3
"""把 LC_ID_DYLIB 的 install_name 改成指定值（不能比原来长）。"""
import struct
import sys


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: patch_install_name.py <macho> <new_name>")
    path, new_name = sys.argv[1], sys.argv[2]

    d = bytearray(open(path, "rb").read())
    if struct.unpack("<I", d[:4])[0] != 0xFEEDFACF:
        raise SystemExit("not a thin 64-bit Mach-O")

    ncmds = struct.unpack("<I", d[16:20])[0]
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", d[off:off + 8])
        if cmd == 0xD:  # LC_ID_DYLIB
            name_off = struct.unpack("<I", d[off + 8:off + 12])[0]
            start = off + name_off
            end = start
            while end < off + cmdsize and d[end] != 0:
                end += 1
            old_len = end - start
            raw = new_name.encode() + b"\0"
            if len(raw) > old_len + 1:
                raise SystemExit("new name too long (%d > %d)" % (len(raw), old_len + 1))
            d[start:start + len(raw)] = raw
            for i in range(start + len(raw), start + old_len + 1):
                d[i] = 0
            open(path, "wb").write(bytes(d))
            print("install_name ->", new_name)
            return
        off += cmdsize

    raise SystemExit("LC_ID_DYLIB not found")


if __name__ == "__main__":
    main()
