#!/usr/bin/env python3
"""
Advanced Preloader Extractor & Disassembler for MT6765
Fixed version - no decode errors
"""

import struct
import re
import os
import subprocess
from typing import List, Tuple, Optional

class PreloaderExtractor:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.data = None
        self.load_file()
        
    def load_file(self):
        with open(self.file_path, 'rb') as f:
            self.data = f.read()
    
    def find_embedded_binaries(self) -> List[Tuple[int, int, str]]:
        """Find embedded binaries like LK, ATF, TEE within preloader"""
        binaries = []
        
        # Common magic bytes for boot images
        magic_patterns = [
            (b'ANDROID!', 'Android Boot Image'),
            (b'LK\x00\x00', 'LK Bootloader'),
            (b'\x00\x00\x00\x00', 'Empty header'),
            (b'ATF\x00', 'ARM Trusted Firmware'),
            (b'TEE\x00', 'Trusted Execution Environment'),
            (b'EFI PART', 'GPT Header'),
        ]
        
        # Search for known partition names as markers
        partition_names = [b'proinfo', b'boot_para', b'lk', b'atf', b'tee', b'sspm']
        
        for i in range(len(self.data) - 4):
            for magic, name in magic_patterns:
                if self.data[i:i+len(magic)] == magic:
                    binaries.append((i, len(magic), name))
                    break
            
            # Check for partition names (limit to first few)
            if len(binaries) < 30:
                for pname in partition_names:
                    if self.data[i:i+len(pname)] == pname:
                        binaries.append((i, len(pname), f"Partition: {pname.decode()}"))
                        break
        
        # Remove duplicates while preserving order
        seen = set()
        unique_binaries = []
        for b in binaries:
            if b[0] not in seen:
                seen.add(b[0])
                unique_binaries.append(b)
        
        return unique_binaries[:30]
    
    def extract_arm_instructions(self, offset: int, count: int = 50) -> List[str]:
        """Extract potential ARM instructions (Thumb/ARM mode)"""
        instructions = []
        for i in range(offset, min(offset + count*4, len(self.data)-4), 4):
            # Try to interpret as ARM instruction (32-bit)
            insn = struct.unpack('<I', self.data[i:i+4])[0]
            # Check for common ARM instruction patterns
            if (insn & 0x0FFFFFF0) == 0x0:  # NOP or AND EQ R0,R0,R0
                instructions.append(f"0x{i:08X}: {insn:08X} (potential NOP)")
            elif (insn & 0xFF000000) == 0xEA000000:  # B instruction
                offset_val = ((insn & 0x00FFFFFF) << 2) + 8
                instructions.append(f"0x{i:08X}: {insn:08X} (Branch +{offset_val} bytes)")
            elif (insn & 0x0F000000) == 0x0F000000:  # SWI/SVC instruction
                instructions.append(f"0x{i:08X}: {insn:08X} (SVC #{insn & 0x00FFFFFF})")
            elif (insn & 0xFE000000) == 0xFA000000:  # BL instruction
                offset_val = ((insn & 0x00FFFFFF) << 2) + 8
                instructions.append(f"0x{i:08X}: {insn:08X} (Branch with Link +{offset_val})")
            else:
                # Check if it looks like valid ARM instruction (not all zeros/ones)
                if insn != 0 and insn != 0xFFFFFFFF:
                    # Try to decode LDR/STR
                    if (insn & 0x0E500000) == 0x04100000:
                        instructions.append(f"0x{i:08X}: {insn:08X} (LDR/STR instruction)")
                    else:
                        instructions.append(f"0x{i:08X}: {insn:08X}")
        
        return instructions
    
    def find_entry_point(self) -> Optional[int]:
        """Find reset vector / entry point"""
        # Look for typical reset vector patterns in ARM
        # Usually starts with stack pointer setup and branch to reset handler
        
        # Check first few bytes for common ARM startup
        if len(self.data) > 4:
            first_insn = struct.unpack('<I', self.data[0:4])[0]
            if (first_insn & 0xFE000000) == 0xEA000000:
                return 0
        
        # Look for LDR PC, [PC, #offset] pattern
        for i in range(0, min(0x400, len(self.data) - 8), 4):
            insn = struct.unpack('<I', self.data[i:i+4])[0]
            if (insn & 0x0FF0F000) == 0x0E50F000:
                return i
            # Check for B (branch) instruction
            if (insn & 0xFE000000) == 0xEA000000:
                return i
        
        return None
    
    def extract_string_table(self) -> dict:
        """Extract organized string table with categories"""
        categories = {
            'debug_paths': [],
            'error_messages': [],
            'function_names': [],
            'partition_names': [],
            'security_strings': [],
            'register_names': [],
            'config_values': []
        }
        
        # Extract strings from the data - FIXED: properly handle bytes
        pattern = re.compile(b'[ -~]{4,}')
        for match in pattern.finditer(self.data):
            try:
                s = match.group().decode('ascii', errors='ignore')
            except:
                continue
            
            # Categorize
            if s.startswith('/home/') or s.startswith('/mfs/') or 'jenkins' in s:
                categories['debug_paths'].append(s)
            elif 'fail' in s.lower() or 'error' in s.lower() or 'timeout' in s.lower():
                if len(s) < 100:  # Avoid huge strings
                    categories['error_messages'].append(s)
            elif re.match(r'^[a-z_][a-z0-9_]*$', s) and len(s) > 3 and len(s) < 30:
                if not s.isdigit():
                    categories['function_names'].append(s)
            elif s in ['proinfo', 'boot_para', 'lk', 'atf', 'tee', 'seccfg', 'sspm', 
                       'system', 'userdata', 'keystore']:
                categories['partition_names'].append(s)
            elif 'sec' in s.lower() or 'auth' in s.lower() or 'key' in s.lower() or 'cert' in s.lower():
                if len(s) < 100:
                    categories['security_strings'].append(s)
            elif s.startswith('0x') or s.upper().startswith('REG'):
                categories['register_names'].append(s)
            elif re.match(r'^[0-9A-Fa-f]{16,}$', s) and len(s) <= 64:
                categories['config_values'].append(s)
        
        # Remove duplicates and limit
        for k in categories:
            categories[k] = list(set(categories[k]))[:20]
        
        return categories
    
    def find_dram_configuration(self) -> dict:
        """Extract DRAM configuration parameters"""
        dram_info = {
            'dram_type': None,
            'channel_count': None,
            'rank_count': None,
            'rank_sizes': [],
            'calibration_data': []
        }
        
        # Extract strings properly
        strings = self.extract_strings_from_data()
        
        # Look for DRAM type strings
        for s in strings:
            if 'dram_type' in s.lower():
                dram_info['dram_type'] = s[:80]
            if 'ch_num' in s.lower() or 'channel' in s.lower():
                dram_info['channel_count'] = s[:80]
            if 'rk_num' in s.lower() or 'rank' in s.lower():
                if 'size' in s.lower():
                    dram_info['rank_sizes'].append(s[:80])
                else:
                    dram_info['rank_count'] = s[:80]
            if 'calibration' in s.lower():
                dram_info['calibration_data'].append(s[:80])
        
        return dram_info
    
    def extract_strings_from_data(self) -> List[str]:
        """Helper to extract all strings - FIXED version"""
        strings = []
        pattern = re.compile(b'[ -~]{4,}')
        for match in pattern.finditer(self.data):
            try:
                s = match.group().decode('ascii', errors='ignore')
                if len(s) > 3:
                    strings.append(s)
            except:
                continue
        return strings
    
    def export_disassembly(self, output_file: str):
        """Export disassembly using external tools if available"""
        # Try to use objdump if installed
        try:
            # Check if it's ARM binary
            result = subprocess.run(['file', self.file_path], 
                                  capture_output=True, text=True)
            if 'ARM' in result.stdout or 'ELF' in result.stdout:
                cmd = ['arm-none-eabi-objdump', '-D', '-b', 'binary', 
                       '-m', 'arm', self.file_path, 
                       '--start-address=0x0', '--stop-address=0x1000']
                subprocess.run(cmd, stdout=open(output_file, 'w'))
                print(f"[+] Disassembly exported to {output_file}")
            else:
                # Still try with raw binary disassembly
                cmd = ['arm-none-eabi-objdump', '-D', '-b', 'binary', 
                       '-m', 'arm', self.file_path]
                subprocess.run(cmd, stdout=open(output_file, 'w'))
                print(f"[+] Raw disassembly exported to {output_file}")
        except FileNotFoundError:
            print("[!] arm-none-eabi-objdump not installed. Skipping disassembly.")
            print("    Install with: sudo apt install gcc-arm-none-eabi")
    
    def save_embedded_parts(self, output_dir: str = 'extracted_parts'):
        """Save identified embedded parts to files"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Find and extract potential partitions
        partitions = ['proinfo', 'boot_para', 'lk', 'atf', 'tee', 'sspm', 'seccfg']
        
        for part in partitions:
            # Search for partition name in data
            part_bytes = part.encode()
            pos = self.data.find(part_bytes)
            if pos != -1:
                # Try to find end of this section
                end = pos + 0x200  # Assume at least 512 bytes
                # Look for next null or next partition
                while end < len(self.data) and end - pos < 0x10000:  # Max 64KB
                    if self.data[end:end+4] == b'\x00\x00\x00\x00':
                        break
                    end += 0x100
                
                extracted = self.data[pos:min(end, len(self.data))]
                out_file = os.path.join(output_dir, f"{part}.bin")
                with open(out_file, 'wb') as f:
                    f.write(extracted)
                print(f"[+] Extracted {part} to {out_file} ({len(extracted)} bytes)")
    
    def analyze_vector_table(self):
        """Analyze the ARM exception vector table"""
        print("\n[VECTOR TABLE ANALYSIS]")
        print("  Offset | Vector         | Value")
        print("  -------|----------------|----------")
        
        vectors = [
            (0x00, "Reset"),
            (0x04, "Undefined Instruction"),
            (0x08, "Software Interrupt (SVC)"),
            (0x0C, "Prefetch Abort"),
            (0x10, "Data Abort"),
            (0x14, "Reserved"),
            (0x18, "IRQ"),
            (0x1C, "FIQ")
        ]
        
        for offset, name in vectors:
            if offset + 4 <= len(self.data):
                val = struct.unpack('<I', self.data[offset:offset+4])[0]
                if (val & 0xFE000000) == 0xEA000000:  # Branch
                    dest = ((val & 0x00FFFFFF) << 2) + 8 + offset
                    print(f"  0x{offset:02X}    | {name:16} | 0x{val:08X} (Branch to 0x{dest:08X})")
                else:
                    print(f"  0x{offset:02X}    | {name:16} | 0x{val:08X}")
    
    def generate_complete_report(self):
        """Generate comprehensive report with all findings"""
        print("\n" + "="*80)
        print("PRELOADER DEEP EXTRACTION REPORT")
        print("="*80)
        
        # 0. Vector table analysis
        self.analyze_vector_table()
        
        # 1. Entry point
        entry = self.find_entry_point()
        if entry is not None:
            print(f"\n[ENTRY POINT]")
            print(f"  Potential entry at offset 0x{entry:04X}")
            print("  First few instructions:")
            for insn in self.extract_arm_instructions(entry, 10):
                print(f"    {insn}")
        
        # 2. Embedded binaries
        print(f"\n[EMBEDDED BINARIES FOUND]")
        binaries = self.find_embedded_binaries()
        if binaries:
            for offset, size, name in binaries[:15]:
                print(f"  0x{offset:06X}: {name} ({size} bytes)")
        else:
            print("  No embedded binaries identified")
        
        # 3. String table categories
        print(f"\n[STRING CATEGORIES]")
        categories = self.extract_string_table()
        for cat, items in categories.items():
            if items:
                print(f"  {cat}: {len(items)} items")
                if len(items) <= 5 and items:
                    for item in items[:3]:
                        print(f"    - {item[:60]}")
        
        # 4. DRAM configuration
        print(f"\n[DRAM CONFIGURATION]")
        dram = self.find_dram_configuration()
        for key, value in dram.items():
            if value:
                if isinstance(value, list) and value:
                    print(f"  {key}: {len(value)} items")
                    for v in value[:2]:
                        print(f"    - {v[:60]}")
                elif value and not isinstance(value, list):
                    print(f"  {key}: {value[:60]}")
        
        # 5. Security analysis
        print(f"\n[SECURITY ANALYSIS]")
        strings = self.extract_strings_from_data()
        sec_strings = [s for s in strings if 'sec' in s.lower() or 'auth' in s.lower()]
        print(f"  Security-related strings: {len(sec_strings)}")
        
        # Look for key material
        key_patterns = ['key', 'cert', 'signature', 'hash', 'rpmb', 'sha', 'aes']
        found_keys = []
        for s in sec_strings:
            if any(k in s.lower() for k in key_patterns):
                found_keys.append(s[:80])
        if found_keys:
            print(f"  Key/cert references found ({len(found_keys)}):")
            for k in found_keys[:5]:
                print(f"    - {k}")
        
        # 6. Look for interesting constants
        print(f"\n[INTERESTING CONSTANTS]")
        constants = []
        hex_pattern = re.compile(r'0x[0-9a-fA-F]{4,8}')
        for s in strings:
            matches = hex_pattern.findall(s)
            for m in matches:
                if m not in constants:
                    constants.append(m)
        if constants:
            print(f"  Found {len(constants)} hex constants:")
            for c in constants[:10]:
                print(f"    - {c}")
        
        # 7. Save extracted data
        print(f"\n[EXTRACTING DATA]")
        self.save_embedded_parts()
        
        # 8. Try disassembly
        try:
            self.export_disassembly('preloader_disassembly.txt')
        except Exception as e:
            print(f"  Disassembly note: {e}")
        
        print("\n" + "="*80)
        print("EXTRACTION COMPLETE")
        print("="*80)

def main():
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python3 unpack.py <preloader_file>")
        sys.exit(1)
    
    extractor = PreloaderExtractor(sys.argv[1])
    extractor.generate_complete_report()

if __name__ == "__main__":
    main()