#!/usr/bin/env python3

import os
import sys
import re
import hashlib
import binascii
import struct

def extract_valuable_info(filepath):
    print(f"""
============================================================================
     ABL/tz.mbn Valuable Information Extractor - Supports All Brands
     File: {os.path.basename(filepath)}
============================================================================
""")
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    size = len(data)
    print(f"[+] File size: {size:,} bytes (0x{size:x})\n")
    
    output_dir = "abl_analysis"
    os.makedirs(output_dir, exist_ok=True)
    
    print("[1] BRAND & SECURITY STRINGS")
    print("-" * 60)
    brand_strings = extract_brand_strings(data)
    for offset, s in brand_strings:
        print(f"  [0x{offset:06x}] {s}")
    save_strings_list(brand_strings, f"{output_dir}/brand_strings.txt")
    print()
    
    print("[2] CERTIFICATES")
    print("-" * 60)
    certs = extract_certificates(data)
    for i, (offset, cert) in enumerate(certs):
        filename = f"{output_dir}/cert_{i+1}_{offset:x}.der"
        with open(filename, 'wb') as f:
            f.write(cert)
        print(f"  [0x{offset:x}] Certificate #{i+1} -> {filename}")
        info = parse_certificate_basic(cert)
        if info:
            print(f"      {info}")
    if not certs:
        print("  No certificates found")
    print()
    
    print("[3] CRYPTOGRAPHIC KEYS")
    print("-" * 60)
    keys = extract_crypto_keys(data)
    for key_type, value, offset in keys[:20]:
        print(f"  [0x{offset:06x}] {value}")
    save_keys_list(keys, f"{output_dir}/crypto_keys.txt")
    if not keys:
        print("  No crypto keys found")
    print()
    
    print("[4] OEM & FASTBOOT COMMANDS")
    print("-" * 60)
    commands = extract_oem_commands(data)
    for cmd, offset in commands:
        print(f"  [0x{offset:06x}] {cmd}")
    save_cmd_list(commands, f"{output_dir}/commands.txt")
    if not commands:
        print("  No OEM commands found")
    print()
    
    print("[5] PARTITIONS")
    print("-" * 60)
    partitions = extract_partitions(data)
    for part, offset in partitions:
        print(f"  [0x{offset:06x}] {part}")
    save_part_list(partitions, f"{output_dir}/partitions.txt")
    if not partitions:
        print("  No partitions found")
    print()
    
    print("[6] DEBUG INTERFACES")
    print("-" * 60)
    debug = extract_debug_interfaces(data)
    for item, offset in debug:
        print(f"  [0x{offset:06x}] {item}")
    save_debug_list(debug, f"{output_dir}/debug.txt")
    if not debug:
        print("  No debug interfaces found")
    print()
    
    print("[7] EMBEDDED FILES")
    print("-" * 60)
    embedded = extract_embedded_files(data, output_dir)
    for ftype, offset, filename in embedded:
        print(f"  [0x{offset:06x}] {ftype} -> {filename}")
    if not embedded:
        print("  No embedded files found")
    print()
    
    print("[8] UNIQUE IDENTIFIERS")
    print("-" * 60)
    guids = extract_guids(data)
    for guid, offset in guids:
        print(f"  [0x{offset:06x}] {guid}")
    save_guid_list(guids, f"{output_dir}/guids.txt")
    if not guids:
        print("  No GUIDs found")
    print()
    
    print("="*60)
    print(f"EXTRACTION COMPLETE -> {output_dir}/")
    print("="*60)

def extract_all_strings(data, min_len=3):
    strings = []
    current = []
    start = 0
    
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append((start, ''.join(current)))
            current = []
    
    if len(current) >= min_len:
        strings.append((start, ''.join(current)))
    
    return strings

def extract_brand_strings(data):
    strings = extract_all_strings(data, 4)
    important = []
    
    brands = [
        'xiaomi', 'samsung', 'oneplus', 'google', 'pixel', 'huawei', 'honor',
        'oppo', 'vivo', 'realme', 'nothing', 'sony', 'lg', 'motorola', 'moto',
        'nokia', 'htc', 'asus', 'lenovo', 'zte', 'micromax', 'lava', 'infinix',
        'tecno', 'itel', 'qmobile', 'alcatel', 'blackberry', 'fairphone'
    ]
    
    security = [
        'secureboot', 'verified', 'avb', 'rollback', 'trustzone', 'tz',
        'qsee', 'tee', 'trusty', 'knox', 'titan', 'pixel', 'vault'
    ]
    
    bootloader = [
        'aboot', 'sbl', 'xbl', 'lk', 'littlekernel', 'u-boot', 'uboot',
        'bootloader', 'fastboot', 'recovery', 'edl', 'download', 'odin'
    ]
    
    keywords = brands + security + bootloader
    
    for offset, s in strings:
        s_lower = s.lower()
        if any(k in s_lower for k in keywords):
            if 3 < len(s) < 100:
                important.append((offset, s))
    
    return important

def extract_certificates(data):
    certs = []
    i = 0
    
    while i < len(data) - 100:
        if data[i] == 0x30:
            if data[i+1] & 0x80:
                length_bytes = data[i+1] & 0x7f
                if length_bytes == 1:
                    length = data[i+2]
                    offset = 3
                elif length_bytes == 2:
                    length = (data[i+2] << 8) | data[i+3]
                    offset = 4
                else:
                    i += 1
                    continue
            else:
                length = data[i+1]
                offset = 2
            
            if i + offset + length <= len(data):
                cert = data[i:i+offset+length]
                if b'\x06\x03U' in cert[:50] or b'\x30\x31' in cert[:20]:
                    certs.append((i, cert))
                    i += length
        i += 1
    
    unique = []
    seen = set()
    for offset, cert in certs:
        h = hashlib.md5(cert).hexdigest()
        if h not in seen:
            seen.add(h)
            unique.append((offset, cert))
    
    return unique

def parse_certificate_basic(cert):
    try:
        if b'test' in cert.lower():
            return "TEST CERTIFICATE"
        if b'debug' in cert.lower():
            return "DEBUG CERTIFICATE"
        if b'engineering' in cert.lower():
            return "ENGINEERING CERTIFICATE"
        return f"Size: {len(cert)} bytes"
    except:
        return ""

def extract_crypto_keys(data):
    keys = []
    seen = set()
    
    for size in [16, 24, 32]:
        for i in range(0, len(data) - size, size):
            chunk = data[i:i+size]
            if len(set(chunk)) > size * 0.75 and i % 16 == 0:
                hex_str = binascii.hexlify(chunk).decode()
                if hex_str not in seen:
                    seen.add(hex_str)
                    keys.append((f"AES-{size*8}", hex_str, i))
    
    for i in range(0, len(data) - 256, 256):
        chunk = data[i:i+256]
        if len(set(chunk)) > 200:
            hex_str = binascii.hexlify(chunk[:32]).decode() + "..."
            if hex_str not in seen:
                seen.add(hex_str)
                keys.append(("RSA-2048", hex_str, i))
    
    return keys

def extract_oem_commands(data):
    strings = extract_all_strings(data, 3)
    commands = []
    seen = set()
    
    content = data
    matches = re.findall(rb'oem\s+([^\x00\n]+)', content, re.IGNORECASE)
    
    for s in matches:
        try:
            cmd_str = s.decode('ascii', errors='ignore').strip()
            if 2 <= len(cmd_str.split()) <= 5:
                if '<' not in cmd_str and '>' not in cmd_str:
                    full_cmd = f'fastboot oem {cmd_str}'
                    if full_cmd not in seen:
                        seen.add(full_cmd)
                        commands.append((full_cmd, 0))
        except:
            pass
    
    for offset, s in strings:
        s_lower = s.lower()
        if 'oem' in s_lower and len(s) < 60 and len(s) > 4:
            if s not in seen:
                seen.add(s)
                commands.append((s, offset))
        elif 'fastboot' in s_lower and len(s) < 60:
            if s not in seen:
                seen.add(s)
                commands.append((s, offset))
        elif 'download' in s_lower and len(s) < 40:
            if s not in seen:
                seen.add(s)
                commands.append((s, offset))
    
    return commands

def extract_partitions(data):
    strings = extract_all_strings(data, 3)
    partitions = []
    seen = set()
    
    part_list = [
        'boot', 'system', 'userdata', 'cache', 'recovery', 'vendor',
        'dtbo', 'vbmeta', 'modem', 'persist', 'misc', 'aboot',
        'sbl', 'xbl', 'tz', 'hyp', 'devcfg', 'keymaster', 'logo',
        'dsp', 'bluetooth', 'efs', 'sec', 'cdt', 'ddr', 'xbl_config',
        'boot_a', 'boot_b', 'system_a', 'system_b', 'vendor_a', 'vendor_b',
        'odm', 'product', 'metadata', 'super', 'init_boot', 'vbmeta_system'
    ]
    
    for offset, s in strings:
        s_lower = s.lower()
        for p in part_list:
            if p in s_lower and 2 < len(s) < 60:
                if s not in seen:
                    seen.add(s)
                    partitions.append((s, offset))
                break
    
    return partitions

def extract_debug_interfaces(data):
    strings = extract_all_strings(data, 3)
    debug = []
    seen = set()
    
    debug_list = [
        'uart', 'jtag', 'swd', 'usb', 'serial', 'console', 
        'debug', 'diag', 'adb', 'edl', '9008', '9006', '900e',
        'com', 'tty', 'ttyS', 'ttyUSB', 'acm', 'dbg', 'debugging'
    ]
    
    for offset, s in strings:
        s_lower = s.lower()
        for d in debug_list:
            if d in s_lower and 2 < len(s) < 50:
                if s not in seen:
                    seen.add(s)
                    debug.append((s, offset))
    
    return debug

def extract_embedded_files(data, output_dir):
    magic = {
        b'\x7fELF': 'ELF',
        b'MZ': 'PE',
        b'\x1f\x8b': 'GZIP',
        b'PK\x03\x04': 'ZIP',
        b'BZh': 'BZIP2',
        b'\xfd7zXZ': 'XZ',
    }
    
    embedded = []
    
    for mag, ftype in magic.items():
        pos = 0
        while True:
            pos = data.find(mag, pos)
            if pos == -1:
                break
            end = min(pos + 65536, len(data))
            filename = f"{output_dir}/embedded_{ftype}_{pos:x}.bin"
            with open(filename, 'wb') as f:
                f.write(data[pos:end])
            embedded.append((ftype, pos, filename))
            pos += 1
    
    return embedded

def extract_guids(data):
    strings = extract_all_strings(data, 30)
    guids = []
    seen = set()
    
    pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    
    for offset, s in strings:
        matches = re.findall(pattern, s.lower())
        for m in matches:
            if m not in seen:
                seen.add(m)
                guids.append((m, offset))
    
    return guids

def save_strings_list(items, filename):
    with open(filename, 'w', encoding='utf-8', errors='ignore') as f:
        for offset, s in items:
            f.write(f"0x{offset:06x}: {s}\n")

def save_keys_list(keys, filename):
    with open(filename, 'w') as f:
        for ktype, value, offset in keys:
            f.write(f"0x{offset:06x}: {value}\n")

def save_cmd_list(commands, filename):
    with open(filename, 'w') as f:
        for cmd, offset in commands:
            f.write(f"0x{offset:06x}: {cmd}\n")

def save_part_list(partitions, filename):
    with open(filename, 'w') as f:
        for part, offset in partitions:
            f.write(f"0x{offset:06x}: {part}\n")

def save_debug_list(debug, filename):
    with open(filename, 'w') as f:
        for item, offset in debug:
            f.write(f"0x{offset:06x}: {item}\n")

def save_guid_list(guids, filename):
    with open(filename, 'w') as f:
        for guid, offset in guids:
            f.write(f"0x{offset:06x}: {guid}\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 decode.py <abl.elf>")
        sys.exit(1)
    
    if not os.path.exists(sys.argv[1]):
        print(f"Error: {sys.argv[1]} not found")
        sys.exit(1)
    
    extract_valuable_info(sys.argv[1])