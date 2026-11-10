#!/usr/bin/env python3
"""
MiTEE bootfs unpack/repack tool.

Bootfs format:
  Header: magic(4) + dir_size(4) + reserved(8) = 16 bytes
  Directory entries: name_len(4) + data_off(4) + data_len(4) + name(padded to 4)
  Data section starts at: 16 + dir_size
  File data at: data_start + data_off

Usage:
  # List files in raw bootfs
  python3 mitee_bootfs.py list bootfs.bin

  # Extract raw bootfs
  python3 mitee_bootfs.py extract bootfs.bin outdir/

  # Pack raw bootfs (needs reference bootfs for file positions)
  python3 mitee_bootfs.py pack <outdir> <reference.bin> <output.bin>

  # Extract from tee.img (decompresses LZ4 first)
  python3 mitee_bootfs.py extract-tee tee.img outdir/

  # Pack into tee.img (compresses with LZ4, preserves file positions from original tee.img)
  python3 mitee_bootfs.py pack-tee outdir/ tee.img tee_new.img [--sign[=mode]]

  # Re-sign an image with lkpatcher cert bypass (mode: override | wrap)
  python3 mitee_bootfs.py sign img_in.img img_out.img [--mode override|wrap]
"""

import struct, os, sys

# ── LZ4 decompression (pure Python, for reading) ──────────────────────

def xxh32(data, seed=0):
    P1, P2, P3, P4, P5 = 0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1
    h32 = seed + P5
    length = len(data)
    idx = 0
    if length >= 16:
        v1, v2, v3, v4 = seed + P1 + P2, seed + P2, seed, seed - P1
        end = length - 16
        while idx <= end:
            for v, offset in [(v1, 0), (v2, 4), (v3, 8), (v4, 12)]:
                v = (v + struct.unpack('<I', data[idx+offset:idx+offset+4])[0] * P2) & 0xFFFFFFFF
                v = ((v << 13) | (v >> 19)) * P1 & 0xFFFFFFFF
            idx += 16
        h32 = ((v1 << 1) | (v1 >> 31)) + ((v2 << 7) | (v2 >> 25)) + ((v3 << 12) | (v3 >> 20)) + ((v4 << 18) | (v4 >> 14))
        h32 &= 0xFFFFFFFF
    h32 = (h32 + length) & 0xFFFFFFFF
    while idx < length - 4:
        h32 = (h32 + struct.unpack('<I', data[idx:idx+4])[0] * P3) & 0xFFFFFFFF
        h32 = ((h32 << 17) | (h32 >> 15)) * P4 & 0xFFFFFFFF
        idx += 4
    while idx < length:
        h32 = (h32 + data[idx] * P5) & 0xFFFFFFFF
        h32 = ((h32 << 11) | (h32 >> 21)) * P1 & 0xFFFFFFFF
        idx += 1
    h32 ^= (h32 >> 15) & 0xFFFFFFFF
    h32 = (h32 * P2) & 0xFFFFFFFF
    h32 ^= (h32 >> 13) & 0xFFFFFFFF
    h32 = (h32 * P3) & 0xFFFFFFFF
    return h32 ^ (h32 >> 16) & 0xFFFFFFFF


def lz4_decompress_block(src, src_offset, max_size=None):
    out = bytearray()
    spos = src_offset
    end = src_offset + max_size if max_size else len(src)
    if end > len(src): end = len(src)
    while spos < end - 1:
        token = src[spos]; spos += 1
        literal_len = token >> 4
        match_len = (token & 0xF) + 4
        if literal_len == 15:
            while True:
                if spos >= end: return bytes(out)
                extra = src[spos]; spos += 1
                literal_len += extra
                if extra < 255: break
        if spos + literal_len > end: return bytes(out)
        out.extend(src[spos:spos+literal_len]); spos += literal_len
        if spos >= end - 2: break
        match_offset = src[spos] | (src[spos+1] << 8); spos += 2
        if match_offset == 0: break
        if match_len == 4 + 15:
            while True:
                if spos >= end: return bytes(out)
                extra = src[spos]; spos += 1
                match_len += extra
                if extra < 255: break
        match_start = len(out) - match_offset
        if match_start < 0: return bytes(out)
        remaining = match_len
        while remaining > 0:
            chunk = min(remaining, match_offset)
            out.extend(out[match_start:match_start+chunk])
            remaining -= chunk; match_start += chunk
    return bytes(out)


def decompress_lz4_frame(data):
    magic = struct.unpack('<I', data[0:4])[0]
    assert magic == 0x184D2204, f"Bad LZ4 magic: 0x{magic:08x}"
    flg = data[4]; bd = data[5]
    block_checksum = (flg >> 4) & 1
    content_size_flag = (flg >> 3) & 1
    content_checksum = (flg >> 2) & 1
    block_indep = (flg >> 5) & 1
    pos = 6
    if content_size_flag: pos += 8
    pos += 1  # HC
    output = bytearray()
    while pos < len(data) - 4:
        block_size = struct.unpack('<I', data[pos:pos+4])[0]; pos += 4
        if block_size == 0: break
        actual_size = block_size & 0x7FFFFFFF
        if block_size & 0x80000000:
            output.extend(data[pos:pos+actual_size])
        else:
            output.extend(lz4_decompress_block(data, pos, actual_size))
        pos += actual_size
        if block_checksum: pos += 4
    if content_checksum: pos += 4
    return bytes(output)


# ── LZ4 compression (using lz4 library) ───────────────────────────────

def compress_lz4_frame(data):
    import lz4.frame
    # MiTEE original uses lz4 -4 -B4 (HC level 4, 64KB blocks, independent)
    compressed = lz4.frame.compress(
        data,
        compression_level=4,
        block_size=lz4.frame.BLOCKSIZE_MAX64KB,
        block_linked=False,
        content_checksum=False,
        store_size=True,
    )
    return compressed


# ── Bootfs format ─────────────────────────────────────────────────────

BOOTFS_MAGIC = 0xa56d3ff9

def parse_header(data):
    magic = struct.unpack('<I', data[0:4])[0]
    dir_size = struct.unpack('<I', data[4:8])[0]
    if magic != BOOTFS_MAGIC:
        raise ValueError(f"Bad bootfs magic: 0x{magic:08x}")
    return dir_size

def parse_entries(data):
    dir_size = parse_header(data)
    data_start = 16 + dir_size
    entries = []
    pos = 16
    while pos + 12 <= len(data):
        name_len = struct.unpack('<I', data[pos:pos+4])[0]
        if name_len == 0 or name_len > 512:
            break
        data_off = struct.unpack('<I', data[pos+4:pos+8])[0]
        data_len = struct.unpack('<I', data[pos+8:pos+12])[0]
        name = data[pos+12:pos+12+name_len].rstrip(b'\x00').decode('ascii', errors='replace')
        entry_size = (12 + name_len + 3) & ~3
        entries.append({
            'name': name,
            'name_len': name_len,
            'data_off': data_off,
            'data_len': data_len,
            'entry_size': entry_size,
        })
        pos += entry_size
    # 注意: data_len 字段是文件数据的『绝对偏移』(不是长度)。
    # 文件大小 = 下一个目录项的 data_len - 当前 data_len (最后一项到数据末尾)。
    total = len(data)
    for i, e in enumerate(entries):
        nxt = entries[i + 1]['data_len'] if i + 1 < len(entries) else total
        e['file_off'] = e['data_len']
        e['file_size'] = nxt - e['data_len']
    return entries, data_start, dir_size

def build_bootfs(entries_data):
    """Build bootfs from list of (name, data) tuples."""
    dir_entries = bytearray()
    file_data = bytearray()
    data_off = 0
    for name, fdata in entries_data:
        name_bytes = name.encode('ascii') + b'\x00'
        name_len = len(name_bytes)
        entry = struct.pack('<III', name_len, data_off, len(fdata)) + name_bytes
        entry += b'\x00' * ((4 - (len(entry) % 4)) % 4)
        dir_entries.extend(entry)
        file_data.extend(fdata)
        data_off += len(fdata)
    dir_size = len(dir_entries)
    header = struct.pack('<II', BOOTFS_MAGIC, dir_size) + struct.pack('<Q', 0)
    return bytes(header) + bytes(dir_entries) + bytes(file_data)


# ── Commands ──────────────────────────────────────────────────────────

def cmd_list(bootfs_path):
    with open(bootfs_path, 'rb') as f:
        data = f.read()
    entries, data_start, dir_size = parse_entries(data)
    print(f"Bootfs: {bootfs_path}")
    print(f"Size: {len(data)} bytes")
    print(f"Data section: 0x{data_start:x} (dir_size=0x{dir_size:x})")
    print(f"Files: {len(entries)}")
    print()
    print(f"{'#':>3} {'Name':35s} {'DataOff':>10s} {'DataLen':>10s} {'FileOff':>10s} {'Size':>10s}")
    print("-" * 80)
    for i, e in enumerate(entries):
        print(f"{i:3d} {e['name']:35s} 0x{e['data_off']:08x} 0x{e['data_len']:08x} 0x{e['file_off']:08x} 0x{e['file_size']:08x}")


def cmd_extract(bootfs_path, output_dir):
    with open(bootfs_path, 'rb') as f:
        data = f.read()
    entries, _, _ = parse_entries(data)
    os.makedirs(output_dir, exist_ok=True)
    for e in entries:
        fpath = os.path.join(output_dir, e['name'])
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        with open(fpath, 'wb') as f:
            f.write(data[e['file_off']:e['file_off']+e['file_size']])
        print(f"  {e['name']:35s} {e['file_size']:8d} bytes")


def cmd_pack(input_dir, reference_bootfs, output_path):
    # Use reference bootfs to preserve file positions and sizes
    with open(reference_bootfs, 'rb') as f:
        ref_data = f.read()
    ref_entries, _, _ = parse_entries(ref_data)
    ref_map = {e['name']: e for e in ref_entries}
    bootfs = bytearray(ref_data)
    for root, dirs, files in os.walk(input_dir):
        for fname in sorted(files):
            if fname == "bootfs_metadata.json":
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, input_dir)
            if rel in ref_map:
                with open(fpath, 'rb') as f:
                    fdata = f.read()
                e = ref_map[rel]
                new_len = len(fdata)
                old_len = e['file_size']
                if new_len > old_len:
                    print(f"  WARN: {rel} too large ({new_len} > {old_len}), truncating")
                    fdata = fdata[:old_len]
                bootfs[e['file_off']:e['file_off']+new_len] = fdata
                if new_len < old_len:
                    bootfs[e['file_off']+new_len:e['file_off']+old_len] = b'\x00' * (old_len - new_len)
                print(f"  {rel:35s} {new_len:8d} bytes (was {old_len})")
            else:
                print(f"  WARN: {rel} not found in reference bootfs, skipping")
    with open(output_path, 'wb') as f:
        f.write(bootfs)
    print(f"[+] Written: {output_path} ({len(bootfs)} bytes, reference-based)")


def cmd_extract_tee(tee_img_path, output_dir):
    with open(tee_img_path, 'rb') as f:
        tee = f.read()
    lz4_magic = struct.pack('<I', 0x184D2204)
    lz4_off = tee.find(lz4_magic)
    if lz4_off < 0:
        raise ValueError("No LZ4 frame found in tee.img")
    decompressed = decompress_lz4_frame(tee[lz4_off:])
    os.makedirs(output_dir, exist_ok=True)
    # Save raw bootfs
    raw_path = os.path.join(output_dir, "bootfs_raw.bin")
    with open(raw_path, 'wb') as f:
        f.write(decompressed)
    print(f"  bootfs_raw.bin: {len(decompressed)} bytes")
    # Extract files
    cmd_extract(raw_path, output_dir)


def apply_cert_bypass(image_path, output_path, mode='override'):
    """用 lkpatcher 的 cert bypass 重新签名镜像中已修改的分区。

    mode: 'override' (默认) 或 'wrap'。只重签 cert2 哈希不再匹配的分区，
    未修改分区保留原证书。
    """
    from liblk.image import LkImage
    from lkpatcher.cert_bypass import apply_cert_bypass, CertBypassMode

    img = LkImage(image_path)
    signed = apply_cert_bypass(img, mode=CertBypassMode(mode))
    img.save(output_path)
    return signed


def cmd_sign(image_path, output_path, mode='override'):
    print(f"[*] Cert bypass ({mode}): {image_path} -> {output_path}")
    signed = apply_cert_bypass(image_path, output_path, mode)
    if signed:
        print(f"[+] Re-signed partitions: {signed}")
    else:
        print("[i] No partition needed re-signing (all cert2 already match)")
    print(f"[+] Written: {output_path}")


def cmd_pack_tee(input_dir, original_tee_img, output_path, sign=False):
    # Build bootfs from directory using reference tee.img
    with open(original_tee_img, 'rb') as f:
        tee = bytearray(f.read())
    lz4_magic = struct.pack('<I', 0x184D2204)
    lz4_off = tee.find(lz4_magic)
    if lz4_off < 0:
        raise ValueError("No LZ4 frame found in tee.img")
    decompressed = decompress_lz4_frame(bytes(tee[lz4_off:]))
    ref_entries, _, _ = parse_entries(decompressed)
    ref_map = {e['name']: e for e in ref_entries}
    
    # Build new bootfs by replacing files
    bootfs = bytearray(decompressed)
    for root, dirs, files in os.walk(input_dir):
        for fname in sorted(files):
            if fname == "bootfs_raw.bin":
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, input_dir)
            if rel in ref_map:
                with open(fpath, 'rb') as f:
                    fdata = f.read()
                e = ref_map[rel]
                new_len = len(fdata)
                old_len = e['file_size']
                if new_len > old_len:
                    print(f"  WARN: {rel} too large ({new_len} > {old_len}), truncating")
                    fdata = fdata[:old_len]
                bootfs[e['file_off']:e['file_off']+new_len] = fdata
                if new_len < old_len:
                    bootfs[e['file_off']+new_len:e['file_off']+old_len] = b'\x00' * (old_len - new_len)
                print(f"  {rel:35s} {new_len:8d} bytes (was {old_len})")
            else:
                print(f"  WARN: {rel} not found in reference, skipping")
    
    print(f"[*] Bootfs: {len(bootfs)} bytes")
    compressed = compress_lz4_frame(bytes(bootfs))
    print(f"[*] Compressed: {len(compressed)} bytes")

    # 计算原 LZ4 帧的结束位置（帧之后还有 spmc_dtb / cert 等分区，必须保留）
    flg = tee[lz4_off + 4]
    pos = lz4_off + 6
    if (flg >> 3) & 1:
        pos += 8
    if flg & 1:
        pos += 4
    pos += 1
    while True:
        bs = struct.unpack('<I', tee[pos:pos + 4])[0]
        pos += 4
        if bs == 0:
            break
        pos += (bs & 0x7fffffff)
        if (flg >> 4) & 1:
            pos += 4
    frame_end = pos

    # 原位替换 [lz4_off, frame_end) 区间，保留帧之后的内容
    if len(compressed) > frame_end - lz4_off:
        raise ValueError(
            f"New LZ4 frame ({len(compressed)} B) exceeds original frame "
            f"space ({frame_end - lz4_off} B)")
    tee[lz4_off:lz4_off + len(compressed)] = compressed
    if len(compressed) < frame_end - lz4_off:
        tee[lz4_off + len(compressed):frame_end] = b'\x00' * (frame_end - lz4_off - len(compressed))
    with open(output_path, 'wb') as f:
        f.write(tee)
    print(f"[+] Written: {output_path} ({len(tee)} bytes)")

    if sign:
        mode = sign if isinstance(sign, str) else 'override'
        print(f"[*] Re-signing with cert bypass ({mode})...")
        signed = apply_cert_bypass(output_path, output_path, mode)
        if signed:
            print(f"[+] Re-signed partitions: {signed}")
        else:
            print("[i] No partition needed re-signing (all cert2 already match)")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "list" and len(sys.argv) >= 3:
        cmd_list(sys.argv[2])
    elif cmd == "extract" and len(sys.argv) >= 4:
        cmd_extract(sys.argv[2], sys.argv[3])
    elif cmd == "pack" and len(sys.argv) >= 5:
        cmd_pack(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "extract-tee" and len(sys.argv) >= 4:
        cmd_extract_tee(sys.argv[2], sys.argv[3])
    elif cmd == "pack-tee":
        args = sys.argv[2:]
        sign = False
        rest = []
        for a in args:
            if a == '--sign':
                sign = 'override'
            elif a.startswith('--sign='):
                sign = a.split('=', 1)[1]
            else:
                rest.append(a)
        if len(rest) != 3:
            print("Usage: pack-tee <bootfs_dir> <tee.img> <output.img> [--sign[=mode]]")
            sys.exit(1)
        cmd_pack_tee(rest[0], rest[1], rest[2], sign=sign)
    elif cmd == "sign" and len(sys.argv) >= 4:
        mode = 'override'
        if '--mode' in sys.argv:
            i = sys.argv.index('--mode')
            mode = sys.argv[i + 1]
            sys.argv = sys.argv[:i] + sys.argv[i + 2:]
        cmd_sign(sys.argv[2], sys.argv[3], mode)
    else:
        print(f"Usage: see below")
        print(__doc__)
        sys.exit(1)

if __name__ == '__main__':
    main()