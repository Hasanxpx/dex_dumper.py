import os
import sys
import time
import struct
import subprocess
import re
from pathlib import Path
from typing import List, Dict, Optional, Any

class DexDumper:
    def __init__(self):
        self.target_package = None
        self.root_dir = Path("/sdcard/dumpDex")
        self.range_map = {
            'Jh': 'JAVA_HEAP',
            'Ch': 'C_HEAP', 
            'Ca': 'C_ALLOC',
            'Cd': 'C_DATA',
            'Cb': 'C_BSS',
            'PS': 'PPSSPP',
            'A': 'ANONYMOUS',
            'J': 'JAVA',
            'S': 'STACK',
            'As': 'ASHMEM',
            'V': 'VIDEO',
            'O': 'OTHER',
            'B': 'BAD',
            'Xa': 'CODE_APP',
            'Xs': 'CODE_SYS'
        }
        
    def get_target_package(self) -> Optional[str]:
        return self.target_package
    
    def set_target_package(self, package_name: str) -> None:
        self.target_package = package_name
        
    def get_dump_dir(self) -> Path:
        return self.root_dir / self.target_package if self.target_package else self.root_dir
    
    def select_memory_ranges(self) -> List[str]:
        """Select memory ranges to scan"""
        print("In Termux, scanning will be done through available memory regions via /proc/pid/maps")
        names = list(self.range_map.keys())
        
        print("\nAvailable memory regions:")
        for i, name in enumerate(names):
            print(f"{i+1:2d}. {name} - {self.range_map[name]}")
        
        try:
            selection = input("\nSelect memory regions (comma-separated): ")
            selected_indices = [int(x.strip()) for x in selection.split(",")]
            selected_ranges = [names[i-1] for i in selected_indices if 1 <= i <= len(names)]
            
            if selected_ranges:
                print(f"Selected: {', '.join(selected_ranges)}")
                return selected_ranges
            else:
                print("Invalid selection, using default")
        except (ValueError, IndexError) as e:
            print(f"Selection error: {e}, using default")
        
        return ['J']  # Default Java region
    
    def get_pid_by_package(self, package_name: str) -> Optional[int]:
        """Get PID from package name"""
        try:
            # Try using pidof
            result = subprocess.run(['pidof', package_name], 
                                  capture_output=True, text=True, timeout=10)
            if result.stdout and result.stdout.strip():
                return int(result.stdout.strip())
            
            # Try using ps
            result = subprocess.run(['ps', '-A', '-o', 'pid,cmd'], 
                                  capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')
            for line in lines:
                if package_name in line:
                    parts = line.strip().split()
                    if parts and parts[0].isdigit():
                        return int(parts[0])
                        
        except subprocess.TimeoutExpired:
            print("Timeout while getting PID")
        except Exception as e:
            print(f"Error getting PID: {e}")
        
        return None
    
    def read_maps_file(self, pid: int) -> List[Dict[str, Any]]:
        """Read /proc/pid/maps to get memory regions"""
        maps_path = f"/proc/{pid}/maps"
        memory_ranges = []
        
        try:
            with open(maps_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 5:
                        address_range = parts[0]
                        perms = parts[1]
                        offset = parts[2]
                        dev = parts[3]
                        inode = parts[4]
                        pathname = parts[5] if len(parts) > 5 else ''
                        
                        if '-' in address_range:
                            start_end = address_range.split('-')
                            if len(start_end) == 2:
                                try:
                                    start_addr = int(start_end[0], 16)
                                    end_addr = int(start_end[1], 16)
                                    size = end_addr - start_addr
                                    
                                    memory_ranges.append({
                                        'start': start_addr,
                                        'end': end_addr,
                                        'size': size,
                                        'perms': perms,
                                        'pathname': pathname,
                                        'line': line_num
                                    })
                                except ValueError:
                                    continue
        except FileNotFoundError:
            print(f"Maps file not found for PID {pid}")
        except Exception as e:
            print(f"Error reading maps file: {e}")
        
        return memory_ranges
    
    def find_dex_in_memory(self, package_name: str) -> List[Dict[str, Any]]:
        """Find DEX files in memory using /proc/pid/maps and /proc/pid/mem"""
        print(f"Searching for DEX in memory of {package_name}...")
        
        pid = self.get_pid_by_package(package_name)
        if not pid:
            print("Cannot find PID for application")
            return []
        
        memory_ranges = self.read_maps_file(pid)
        dex_files = []
        
        print(f"Found {len(memory_ranges)} memory regions to scan")
        
        for i, mem_range in enumerate(memory_ranges):
            # Only search readable regions with sufficient size
            if 'r' in mem_range['perms'] and mem_range['size'] > 40:
                if i % 10 == 0:  # Print progress every 10 regions
                    print(f"Scanning region {i+1}/{len(memory_ranges)}...")
                
                try:
                    mem_path = f"/proc/{pid}/mem"
                    with open(mem_path, 'rb') as mem_file:
                        mem_file.seek(mem_range['start'])
                        header = mem_file.read(40)
                        
                        if len(header) >= 8:
                            # Check for DEX signature (dex\n035 or dex\n037)
                            magic = header[:8]
                            if magic.startswith(b'dex\n035') or magic.startswith(b'dex\n037'):
                                dex_files.append({
                                    'address': mem_range['start'],
                                    'size': mem_range['size'],
                                    'path': mem_range['pathname'],
                                    'perms': mem_range['perms']
                                })
                                print(f"✓ Found potential DEX at: {hex(mem_range['start'])}")
                
                except (PermissionError, FileNotFoundError):
                    continue
                except Exception as e:
                    if 'Permission denied' not in str(e):
                        print(f"Error scanning region {hex(mem_range['start'])}: {e}")
        
        return dex_files
    
    def dump_memory(self, start_addr: int, end_addr: int, output_path: Path) -> bool:
        """Dump memory content to file"""
        try:
            pid = self.get_pid_by_package(self.target_package)
            if not pid:
                print("Cannot find PID for application")
                return False
                
            mem_path = f"/proc/{pid}/mem"
            size = end_addr - start_addr
            
            # Limit dump size to prevent memory issues
            max_dump_size = 50 * 1024 * 1024  # 50MB max
            if size > max_dump_size:
                print(f"Warning: Region too large ({size} bytes), limiting to {max_dump_size} bytes")
                size = max_dump_size
            
            print(f"Dumping memory from {hex(start_addr)} to {hex(start_addr + size)}...")
            
            with open(mem_path, 'rb') as mem_file:
                mem_file.seek(start_addr)
                
                # Read in chunks to handle large regions
                chunk_size = 1024 * 1024  # 1MB chunks
                bytes_read = 0
                
                with open(output_path, 'wb') as out_file:
                    while bytes_read < size:
                        remaining = size - bytes_read
                        read_size = min(chunk_size, remaining)
                        
                        data = mem_file.read(read_size)
                        if not data:
                            break
                            
                        out_file.write(data)
                        bytes_read += len(data)
                        
                        # Show progress
                        if bytes_read % (5 * 1024 * 1024) == 0:  # Every 5MB
                            print(f"  Dumped {bytes_read}/{size} bytes ({bytes_read/size*100:.1f}%)")
                    
            print(f"✓ Memory dump completed: {output_path}")
            return True
            
        except Exception as e:
            print(f"✗ Error dumping memory: {e}")
            return False
    
    def extract_dex_from_dump(self, dump_path: Path, dex_offset: int, 
                             dex_size: int, output_path: Path) -> bool:
        """Extract DEX from memory dump file"""
        try:
            print(f"Extracting DEX from dump...")
            
            with open(dump_path, 'rb') as dump_file:
                dump_file.seek(dex_offset)
                
                # Read in chunks for large files
                chunk_size = 1024 * 1024  # 1MB chunks
                bytes_read = 0
                
                with open(output_path, 'wb') as dex_file:
                    while bytes_read < dex_size:
                        remaining = dex_size - bytes_read
                        read_size = min(chunk_size, remaining)
                        
                        dex_data = dump_file.read(read_size)
                        if not dex_data:
                            break
                            
                        dex_file.write(dex_data)
                        bytes_read += len(dex_data)
            
            print(f"✓ DEX extracted successfully: {output_path}")
            return True
            
        except Exception as e:
            print(f"✗ Error extracting DEX: {e}")
            return False
    
    def start_dump(self, header_type: str = "035") -> None:
        """Start DEX extraction process"""
        if not self.target_package:
            print("✗ No target package specified!")
            return
            
        print(f"\nStarting DEX extraction from {self.target_package} with header {header_type}")
        print("=" * 60)
        
        # Create output directory
        dump_dir = self.get_dump_dir()
        dump_dir.mkdir(parents=True, exist_ok=True)
        
        # Find DEX addresses
        dex_addresses = self.find_dex_in_memory(self.target_package)
        
        if not dex_addresses:
            print("✗ No DEX files found in memory")
            return
            
        print(f"\n✓ Found {len(dex_addresses)} potential DEX files")
        
        success_count = 0
        for i, dex_info in enumerate(dex_addresses):
            dex_name = f"classes{'' if i == 0 else i+1}.dex"
            output_path = dump_dir / dex_name
            
            print(f"\n[{i+1}/{len(dex_addresses)}] Extracting {dex_name}...")
            print(f"  Address: {hex(dex_info['address'])}")
            print(f"  Size:    {dex_info['size']} bytes")
            
            # Dump memory
            start_addr = dex_info['address']
            end_addr = start_addr + dex_info['size']
            temp_dump_path = dump_dir / f"temp_dump_{i:03d}.bin"
            
            if self.dump_memory(start_addr, end_addr, temp_dump_path):
                # Extract DEX from dump
                if self.extract_dex_from_dump(temp_dump_path, 0, dex_info['size'], output_path):
                    success_count += 1
                    print(f"  ✓ Successfully extracted {dex_name}")
                else:
                    print(f"  ✗ Failed to extract {dex_name}")
                
                # Clean up temporary file
                try:
                    os.remove(temp_dump_path)
                except:
                    pass
            else:
                print(f"  ✗ Failed to dump memory for {dex_name}")
        
        print(f"\n{'='*60}")
        print(f"Extraction completed: {success_count}/{len(dex_addresses)} DEX files extracted")
        print(f"Files saved to: {dump_dir}")
        print(f"{'='*60}")
    
    def main_menu(self) -> None:
        """Main menu interface"""
        while True:
            print("\n" + "="*60)
            print("DEX Dumper for Termux (No Frida Required)")
            print("="*60)
            
            # Show current target
            if self.target_package:
                print(f"📦 Target Package: {self.target_package}")
            else:
                print("📦 No target package set")
            
            # Menu options
            print("\nOptions:")
            print("1. Set target package")
            print("2. Select memory regions")
            print("3. Start extraction (Header 035)")
            print("4. Start extraction (Header 037)") 
            print("5. Comprehensive memory scan")
            print("6. Exit")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == "1":
                package = input("Enter package name: ").strip()
                if package:
                    self.set_target_package(package)
                    print(f"✓ Target set to: {package}")
                else:
                    print("✗ Invalid package name")
                    
            elif choice == "2":
                self.select_memory_ranges()
                
            elif choice == "3":
                self.start_dump("035")
                
            elif choice == "4":
                self.start_dump("037")
                
            elif choice == "5":
                print("Comprehensive scan feature would be implemented here")
                
            elif choice == "6":
                print("👋 Goodbye!")
                break
                
            else:
                print("✗ Invalid option, please try again")

def check_root() -> bool:
    """Check if running as root"""
    if os.geteuid() != 0:
        print("❌ This script requires root privileges to work properly")
        print("💡 Run: su")
        return False
    return True

def main() -> None:
    """Main function"""
    print("🔍 DEX Dumper - Android Memory DEX Extraction Tool")
    print("⚠️  Requires rooted Android device")
    print("-" * 50)
    
    if not check_root():
        sys.exit(1)
    
    try:
        dumper = DexDumper()
        dumper.main_menu()
    except KeyboardInterrupt:
        print("\n\n⏹️  Operation cancelled by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()