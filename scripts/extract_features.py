# malware_detector/scripts/extract_features.py
import pefile
import pandas as pd 
import os 
import numpy as np 
import re 
from typing import Dict, Optional

DATA_DIR = "../data"
OUTPUT_FILE = "../output/processed_features_dataset.csv"

def get_strings(filepath: str, min_length: int = 4) -> list:
    with open(filepath, 'rb') as f:
        data = f.read()
    
    ascii_pattern = rb'[\x20-\x7E]{%d,}' % min_length
    ascii_strings = re.findall(ascii_pattern, data)
    
    unicode_pattern = rb'(?:[\x20-\x7E]\x00){%d,}' % min_length
    unicode_strings = [s.replace(b'\x00', b'') for s in re.findall(unicode_pattern, data)]
    
    return list(set(ascii_strings + unicode_strings))

def is_valid_pe(filepath: str) -> bool:
    try:
        with open(filepath, 'rb') as f:
            if f.read(2) != b'MZ':
                return False
            
            f.seek(0x3C)
            pe_offset = int.from_bytes(f.read(4), byteorder='little')
            
            if pe_offset > os.path.getsize(filepath) - 4:
                return False
                
            f.seek(pe_offset)
            return f.read(4) == b'PE\0\0'
    except Exception:
        return False

def extract_features(filepath: str) -> Optional[Dict]:
    filename = os.path.basename(filepath)
    
    if not is_valid_pe(filepath):
        print(f"[!] Not a valid PE file: {filename}")
        return None

    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']
            ]
        )

        # Section analysis
        section_names = [s.Name.decode(errors='ignore').rstrip('\x00') for s in pe.sections]
        section_sizes = [s.SizeOfRawData for s in pe.sections]
        section_entropies = [s.get_entropy() for s in pe.sections]

        # Section name entropy
        counts = [section_names.count(name) for name in set(section_names)]
        probs = [count / len(section_names) for count in counts]
        section_names_entropy = -sum(p * np.log2(p) for p in probs) if probs else 0

        # Import analysis
        num_imports = 0
        num_unique_dlls = 0
        num_unique_imports = 0
        name_mismatches = 0
        suspicious_imports = 0
        import_functions = []
        
        # VM detection related APIs
        vm_detection_apis = {
            'cpuid', 'hypervisor', 'vmcheck', 'vbox', 'vmware', 'virtualbox',
            'wine_get_unix_file_name', 'wine_get_dos_file_name'
        }
        
        # Anti-debugging related APIs
        anti_debug_apis = {
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugStringA',
            'NtQueryInformationProcess', 'NtSetInformationThread', 'NtQuerySystemInformation',
            'GetTickCount', 'QueryPerformanceCounter', 'RDTSC', 'GetProcessHeap',
            'ZwSetInformationThread', 'DbgBreakPoint', 'DbgUiRemoteBreakin'
        }
        
        # Process creation APIs
        process_creation_apis = {
            'CreateProcessA', 'CreateProcessW', 'CreateProcessAsUserA', 'CreateProcessAsUserW',
            'SetWindowsHookExA', 'SetWindowsHookExW', 'ShellExecuteA', 'ShellExecuteW',
            'WinExec', 'System'
        }
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            dll_names = []
            suspicious_apis = {
                'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread', 
                'WriteProcessMemory', 'LoadLibrary', 'GetProcAddress',
                'NtCreateThreadEx', 'RtlCreateUserThread', 'WinExec', 
                'ShellExecuteA', 'RegSetValue', 'RegDeleteKey',
                'NtQueryInformationProcess', 'CheckRemoteDebuggerPresent',
                'Process32FirstW', 'Process32First', 'CreateToolhelp32Snapshot'
            }
            
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors='ignore').lower()
                dll_names.append(dll_name)
                
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode(errors='ignore')
                        import_functions.append(func_name)
                        
                        # Check for suspicious APIs
                        if func_name in suspicious_apis:
                            suspicious_imports += 1
                            
                        # Check for VM detection APIs
                        if any(vm_api in func_name.lower() for vm_api in vm_detection_apis):
                            suspicious_imports += 1
                            
                        # Check for anti-debugging APIs
                        if func_name in anti_debug_apis:
                            suspicious_imports += 1
                            
                        # Check for process creation APIs
                        if func_name in process_creation_apis:
                            suspicious_imports += 1
                    else:
                        name_mismatches += 1

            num_imports = len(import_functions)
            num_unique_dlls = len(set(dll_names))
            num_unique_imports = len(set(import_functions))

        # VM detection patterns in strings
        vm_detection_strings = {
            b'vbox', b'vmware', b'virtualbox', b'qemu', b'xen', b'hypervisor',
            b'virtual machine', b'vmcheck', b'vboxguest', b'vboxsf', b'vboxvideo',
            b'vm3dmp', b'vmmouse', b'vmhgfs', b'vmtools', b'vmci', b'vmxnet',
            b'vmx_fb', b'vmware user', b'vmware tools', b'vboxservice', b'vboxtray'
        }
        
        # Known VM MAC address prefixes
        vm_mac_prefixes = {
            b'00:0C:29', b'00:1C:14', b'00:05:69', b'00:50:56',  # VMware
            b'08:00:27',  # VirtualBox
            b'00:16:3E',  # Xen
            b'00:1C:42',  # Parallels
            b'00:15:5D'   # Hyper-V
        }
        
        # Anti-debugging strings
        anti_debug_strings = {
            b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent', b'OutputDebugString',
            b'NtQueryInformationProcess', b'NtSetInformationThread', b'ZwSetInformationThread',
            b'GetTickCount', b'QueryPerformanceCounter', b'RDTSC', b'GetProcessHeap',
            b'PEB!BeingDebugged', b'PEB!NtGlobalFlag', b'DebugPort', b'DbgBreakPoint',
            b'DbgUiRemoteBreakin', b'INT3', b'INT 3', b'CC', b'0xCC'
        }

        suspicious_patterns = {
            # Malware components
            b'payload', b'malware', b'inject', b'virus', b'trojan',
            b'backdoor', b'rat', b'worm', b'spyware', b'keylog',
            b'ransom', b'crypt', b'miner', b'bot', b'rootkit',
            
            # Obfuscation techniques
            b'xored', b'encrypted', b'packed', b'obfus',
            b'strdecode', b'decode', b'vmprotect',
            
            # Common malicious exports
            b'start', b'run', b'exec', b'install', b'persist',
            b'config', b'update', b'connect', b'server',
            
            # Anti-analysis
            b'sandbox', b'debug', b'vmdetect', b'analysis'
        }

        # String analysis
        strings = get_strings(filepath)
        num_strings = len(strings)
        avg_string_length = np.mean([len(s) for s in strings]) if strings else 0
        
        # Check for VM detection strings
        has_vm_detection_strings = int(any(
            any(vm_str in s.lower() for vm_str in vm_detection_strings) 
            for s in strings
        ))
        
        # Check for VM MAC addresses
        has_vm_mac_addresses = int(any(
            any(mac_prefix in s for mac_prefix in vm_mac_prefixes)
            for s in strings
        ))
        
        # Check for anti-debugging strings
        has_anti_debug_strings = int(any(
            any(anti_str in s for anti_str in anti_debug_strings)
            for s in strings
        ))
        
        # Check for NOP sleds (90 = x86 NOP opcode)
        nop_sled_pattern = rb'\x90{%d,}' % 10  # Sequences of 10+ NOPs
        has_nop_sleds = int(len(re.findall(nop_sled_pattern, pe.__data__)) > 0)

        # Export analysis
        num_exports = 0
        suspicious_exports = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            num_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            suspicious_exports = sum(
                1 for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols
                if exp.name and any(pattern in exp.name.lower() for pattern in suspicious_patterns)
            )

        # Entry point analysis
        ep_section_index = -1
        if hasattr(pe, 'OPTIONAL_HEADER'):
            for i, section in enumerate(pe.sections):
                if (pe.OPTIONAL_HEADER.AddressOfEntryPoint >= section.VirtualAddress and 
                    pe.OPTIONAL_HEADER.AddressOfEntryPoint < section.VirtualAddress + section.Misc_VirtualSize):
                    ep_section_index = i
                    break

        # API call chain detection
        api_sequences = {
            ('VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread'): 'Process Injection',
            ('RegCreateKey', 'RegSetValue', 'RegCloseKey'): 'Registry Persistence',
            ('LoadLibraryA', 'GetProcAddress', 'VirtualProtect'): 'Dynamic API Resolution',
            ('OpenProcess', 'ReadProcessMemory', 'WriteProcessMemory'): 'Process Hollowing',
            ('NtUnmapViewOfSection', 'MapViewOfFile', 'ResumeThread'): 'RunPE Technique',
            ('CreateProcessA', 'WriteProcessMemory', 'ResumeThread'): 'Process Injection',
            ('SetWindowsHookExA', 'GetMessage', 'DispatchMessage'): 'Hook Injection'
        }
        suspicious_api_chains = sum(
            1 for sequence in api_sequences
            if all(api in import_functions for api in sequence)
        )

        # Feature compilation
        features = {
            # Basic file info
            'size': os.path.getsize(filepath), 
            'num_sections': len(pe.sections),
            'num_unique_sections': len(set(section_names)), 
            'section_names_entropy': section_names_entropy,
            
            # Section characteristics
            'avg_section_size': np.mean(section_sizes) if section_sizes else 0, 
            'min_section_size': min(section_sizes) if section_sizes else 0,
            'max_section_size': max(section_sizes) if section_sizes else 0,
            'total_section_size': sum(section_sizes), 
            'avg_entropy': np.mean(section_entropies) if section_entropies else 0,
            'min_entropy': min(section_entropies) if section_entropies else 0,
            'max_entropy': max(section_entropies) if section_entropies else 0, 
            'has_packed_sections': int(any(s.SizeOfRawData == 0 and s.Misc_VirtualSize > 0 for s in pe.sections)),
            'has_executable_sections': int(any(s.Characteristics & 0x20000000 for s in pe.sections)),
            'writable_executable_sections': sum(
                1 for s in pe.sections 
                if s.Characteristics & 0x20000000 and s.Characteristics & 0x80000000
            ),
            
            # Import/export features
            'num_imports': num_imports,
            'num_unique_dlls': num_unique_dlls,
            'num_unique_imports': num_unique_imports,
            'imports_to_dlls_ratio': num_imports / num_unique_dlls if num_unique_dlls > 0 else 0, 
            'has_import_name_mismatches': int(name_mismatches > 0),
            'suspicious_imports_count': suspicious_imports,
            'num_exports': num_exports,
            'suspicious_exports': suspicious_exports,
            'suspicious_api_chains': suspicious_api_chains,
            'has_delayed_imports': int(hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT')),
            
            # File type flags
            'is_dll': int(pe.FILE_HEADER.Characteristics & 0x2000),
            'is_executable': int(pe.FILE_HEADER.Characteristics & 0x0002),
            'is_system_file': int(pe.FILE_HEADER.Characteristics & 0x1000), 
            'has_aslr': int(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040) if hasattr(pe, 'OPTIONAL_HEADER') else 0,
            'has_dep': int(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100) if hasattr(pe, 'OPTIONAL_HEADER') else 0,
            'is_signed': int(pe.verify_authenticode() if hasattr(pe, 'verify_authenticode') else 0),
            'has_rich_header': int(hasattr(pe, 'RICH_HEADER')),
            'rich_header_entries': len(pe.RICH_HEADER.entries) if hasattr(pe, 'RICH_HEADER') else 0,
            
            # String analysis
            'num_strings': num_strings,
            'avg_string_length': avg_string_length,
            'has_suspicious_strings': int(any(b'http://' in s or b'https://' in s or b'.dll' in s for s in strings)),
            'has_anti_debug': int(any(b'IsDebuggerPresent' in s for s in strings)),
            
            # VM detection features
            'has_vm_detection_imports': int(any(
                any(vm_api in func.lower() for vm_api in vm_detection_apis)
                for func in import_functions
            )),
            'has_vm_detection_strings': has_vm_detection_strings,
            'has_vm_mac_addresses': has_vm_mac_addresses,
            
            # Anti-debugging features
            'has_anti_debug_imports': int(any(
                func in anti_debug_apis for func in import_functions
            )),
            'has_anti_debug_strings': has_anti_debug_strings,
            
            # Process creation features
            'has_process_creation_imports': int(any(
                func in process_creation_apis for func in import_functions
            )),
            'has_createprocess': int(any(
                'CreateProcess' in func for func in import_functions
            )),
            'has_setwindowshookex': int(any(
                'SetWindowsHookEx' in func for func in import_functions
            )),
            
            # Code patterns
            'has_nop_sleds': has_nop_sleds,
            
            # Resource analysis
            'has_resources': int(hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE')),
            'num_resources': len(pe.DIRECTORY_ENTRY_RESOURCE.entries) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0,
            'has_embedded_exe': int(any(
                entry.id == pefile.RESOURCE_TYPE['RT_RCDATA'] 
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries
            ) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0),
            'has_debug': int(hasattr(pe, 'DIRECTORY_ENTRY_DEBUG')), 
            'has_tls': int(hasattr(pe, 'DIRECTORY_ENTRY_TLS')),
            'has_relocations': int(hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC')),
            
            # Entry point analysis
            'ep_in_first_section': int(ep_section_index == 0),
            'ep_in_last_section': int(ep_section_index == len(pe.sections)-1),
            'ep_section_entropy': pe.sections[ep_section_index].get_entropy() if ep_section_index != -1 else 0,
            
            # Section anomalies
            'has_suspicious_sections': int(any(name.lower() in ['.crypto', '.lock', '.packed'] for name in section_names)),
        }
        
        pe.close()
        return features
        
    except pefile.PEFormatError as e:
        print(f"[!] Invalid PE format in {filename}: {str(e)}")
        return None
    except Exception as e:
        print(f"[!] Error processing {filename}: {str(e)}")
        return None

def build_dataset():
    """Build dataset from samples"""
    data = []
    
    # Process benign samples
    benign_path = os.path.join(DATA_DIR, "benign")
    if os.path.exists(benign_path):
        print(f"[*] Processing benign samples from {benign_path}...")
        for file in os.listdir(benign_path):
            if not file.lower().endswith('.exe'):
                continue
            full_path = os.path.join(benign_path, file)
            features = extract_features(full_path)
            if features:
                features["label"] = 0
                data.append(features)
    
    # Process malware samples
    malware_path = os.path.join(DATA_DIR, "malware")
    if os.path.exists(malware_path):
        print(f"[*] Processing malware samples (limited to 4200) from {malware_path}...")
        processed = 0
        for file in os.listdir(malware_path):
            if not file.lower().endswith('.exe'):
                continue
            if processed >= 4200:
                break
            full_path = os.path.join(malware_path, file)
            features = extract_features(full_path)
            if features:
                features["label"] = 1
                data.append(features)
                processed += 1

    # Save dataset
    if data:
        df = pd.DataFrame(data)
        df.to_csv(OUTPUT_FILE, index=False)
        print(f"\n[+] Processed Features Dataset saved to {OUTPUT_FILE}")
        print(f"[+] Total samples: {len(df)}")
        print(f"[+] Malware samples: {len(df[df['label'] == 1])}")
        print(f"[+] Benign samples: {len(df[df['label'] == 0])}")
    else:
        print("[!] No valid samples found")

if __name__ == "__main__":
    build_dataset()
