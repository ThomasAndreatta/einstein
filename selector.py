#!/usr/bin/env python3
"""
Syscall Taint Analysis Configuration Generator

This script analyzes syscall traces to identify tainted syscalls and generates
configuration files for S2E symbolic execution.
"""
import os 
import json
import sys
import re
from typing import Dict, List, Optional, Tuple, Union


class SyscallConfig:
    
    def __init__(self, config_file: str = "syscall_config.json"):
        self.config = {}
        self.load_config(config_file)
    
    def load_config(self, config_file: str):
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
            print(f"Loaded syscall configuration from {config_file}")
        except FileNotFoundError:
            print(f"Warning: Config file '{config_file}' not found. Using empty configuration.")
            self.config = {}
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in config file '{config_file}': {e}")
            sys.exit(1)
    
    def get_syscall_info(self, syscall_name: str) -> Optional[Dict]:
        return self.config.get(syscall_name)
    
    def is_supported(self, syscall_name: str) -> bool:
        return syscall_name in self.config
    
    def get_supported_syscalls(self) -> List[str]:
        return list(self.config.keys())
    
    def get_double_run_setting(self, syscall_name: str, arg_index: int, sub_arg_index: Optional[int] = None) -> bool:
        
        config_info = self.get_syscall_info(syscall_name)
        if not config_info:
            return False  # Default to False if no config
        
        # Handle special cases with nested_args (like execve)
        if config_info.get('special_handling', False) and 'nested_args' in config_info:
            nested_args = config_info['nested_args']
            arg_key = str(arg_index)
            
            if arg_key in nested_args:
                nested_info = nested_args[arg_key]
                double_run_value = nested_info.get('double_run', 'false')
                # Convert string to boolean
                if isinstance(double_run_value, str):
                    return double_run_value.lower() == 'true'
                return bool(double_run_value)
        
        # Handle regular syscalls with double_run array
        double_run_list = config_info.get('double_run', [])
        if isinstance(double_run_list, list) and arg_index < len(double_run_list):
            double_run_value = double_run_list[arg_index]
            # Convert string to boolean
            if isinstance(double_run_value, str):
                return double_run_value.lower() == 'true'
            return bool(double_run_value)
        
        # Fallback: check if it's a single boolean value
        single_double_run = config_info.get('double_run', False)
        if isinstance(single_double_run, bool):
            return single_double_run
        
        return False


class TaintAnalyzer:
    
    @staticmethod
    def has_taint_data(arg: Dict) -> bool:
        arg_type = arg.get('type', 'unknown')
        
        def has_valid_taint_entries(taint_data):
            if not taint_data:
                return False
            
            for taint_entry in taint_data:
                if taint_entry == "FULL":
                    return True  # "FULL" indicates tainted data
                elif isinstance(taint_entry, list) and len(taint_entry) > 0:
                    return True  # Non-empty list indicates tainted data
                elif isinstance(taint_entry, int):
                    return True  # Direct integer value indicates tainted data
            
            return False
        
        if arg_type == 'QWORD':
            qword_taint = arg.get('qword_taint', [])
            return has_valid_taint_entries(qword_taint)
        
        elif arg_type == 'DWORD':
            dword_taint = arg.get('dword_taint', [])
            return has_valid_taint_entries(dword_taint)
        
        elif arg_type == 'WORD':
            word_taint = arg.get('word_taint', [])
            return has_valid_taint_entries(word_taint)
        
        elif arg_type == 'BYTE':
            byte_taint = arg.get('byte_taint', [])
            return has_valid_taint_entries(byte_taint)
        
        elif arg_type == 'VPTR':
            # Check both qword_taint (pointer taint) and buf_taint (buffer content taint)
            qword_taint = arg.get('qword_taint', [])
            buf_taint = arg.get('buf_taint', [])
            
            has_qword_taint = has_valid_taint_entries(qword_taint)
            has_buf_taint = has_valid_taint_entries(buf_taint)
            
            return has_qword_taint or has_buf_taint
        
        elif arg_type == 'PPCHAR':
            # Check qword_taint and nested pchars
            qword_taint = arg.get('qword_taint', [])
            has_qword_taint = has_valid_taint_entries(qword_taint)
            
            # Check nested pchars
            pchars = arg.get('pchars', [])
            has_nested_taint = any(TaintAnalyzer.has_taint_data(pchar) for pchar in pchars)
            
            return has_qword_taint or has_nested_taint
        
        elif arg_type == 'IOVEC':
            # Check qword_taint (iovec array pointer) and nested vptrs
            qword_taint = arg.get('qword_taint', [])
            has_qword_taint = has_valid_taint_entries(qword_taint)
            
            # Check nested vptrs (the actual iovec entries)
            vptrs = arg.get('vptrs', [])
            has_nested_taint = any(TaintAnalyzer.has_taint_data(vptr) for vptr in vptrs)
            
            return has_qword_taint or has_nested_taint
        
        return False

    @staticmethod
    def get_taint_address(arg: Dict) -> Optional[int]:
        arg_type = arg.get('type', 'unknown')
        
        def find_valid_address_in_taint(taint_data):
            if not taint_data:
                return None
            
            for taint_entry in taint_data:
                if isinstance(taint_entry, list) and len(taint_entry) > 0:
                    if isinstance(taint_entry[0], int):
                        return taint_entry[0]
                elif isinstance(taint_entry, int):
                    return taint_entry
            
            return None
        
        if arg_type == 'QWORD':
            qword_taint = arg.get('qword_taint', [])
            address = find_valid_address_in_taint(qword_taint)
            return address if address is not None else arg.get('qword', 0)
        
        elif arg_type == 'DWORD':
            dword_taint = arg.get('dword_taint', [])
            address = find_valid_address_in_taint(dword_taint)
            return address if address is not None else arg.get('dword', 0)
        
        elif arg_type == 'WORD':
            word_taint = arg.get('word_taint', [])
            address = find_valid_address_in_taint(word_taint)
            return address if address is not None else arg.get('word', 0)
        
        elif arg_type == 'BYTE':
            byte_taint = arg.get('byte_taint', [])
            address = find_valid_address_in_taint(byte_taint)
            return address if address is not None else arg.get('byte', 0)
        
        elif arg_type == 'VPTR':
            # For VPTR, try buf_taint first (buffer content), then qword_taint (pointer)
            buf_taint = arg.get('buf_taint', [])
            if buf_taint:
                address = find_valid_address_in_taint(buf_taint)
                if address is not None:
                    return address
            
            qword_taint = arg.get('qword_taint', [])
            address = find_valid_address_in_taint(qword_taint)
            return address if address is not None else arg.get('qword', 0)
        
        elif arg_type == 'PPCHAR':
            qword_taint = arg.get('qword_taint', [])
            address = find_valid_address_in_taint(qword_taint)
            return address if address is not None else arg.get('qword', 0)
        elif arg_type == 'IOVEC':
            # For IOVEC, check nested vptrs first, then qword_taint
            vptrs = arg.get('vptrs', [])
            if vptrs:
                # Return address of first tainted vptr
                for vptr in vptrs:
                    if TaintAnalyzer.has_taint_data(vptr):
                        return TaintAnalyzer.get_taint_address(vptr)
            
            qword_taint = arg.get('qword_taint', [])
            address = find_valid_address_in_taint(qword_taint)
            return address if address is not None else arg.get('qword', 0)
        
        return 0
    @staticmethod
    def get_argument_size(arg: Dict) -> int:
        arg_type = arg.get('type', 'unknown')
        
        if arg_type == 'VPTR':
            # For string pointers, use actual buffer length
            buf = arg.get('buf', [])
            if buf:
                return len(buf)
            # Fallback to string length + null terminator
            string_content = arg.get('str', '')
            return len(string_content.encode('utf-8')) + 1
        elif arg_type == 'IOVEC':
            # For iovec, calculate total size of all buffers
            vptrs = arg.get('vptrs', [])
            total_size = 0
            for vptr in vptrs:
                total_size += TaintAnalyzer.get_argument_size(vptr)
            return total_size if total_size > 0 else 8  # Default to pointer size
        
        # Fixed sizes for other types
        size_map = {
            'QWORD': 8,
            'DWORD': 4, 
            'WORD': 2,
            'BYTE': 1,
            'PPCHAR': 8
        }
        
        return size_map.get(arg_type, 8)


class BacktraceAnalyzer:
    
    LIBRARY_INDICATORS = [
        '/lib64/', '/lib/x86_64-linux-gnu/', '/lib/i386-linux-gnu/',
        '/lib/', '/usr/lib/', 'libc.so', 'ld-linux', '.so.'
    ]
    
    @staticmethod
    def is_library_path(backtrace_entry: str) -> bool:
        return any(indicator in backtrace_entry for indicator in BacktraceAnalyzer.LIBRARY_INDICATORS)
    
    @staticmethod
    def extract_address_from_backtrace(backtrace_entry: str) -> Optional[str]:
        # Look for pattern like "server+0x7fff00102f74" after " at "
        match = re.search(r' at [^+]+\+0x([0-9a-fA-F]+)', backtrace_entry)
        if match:
            return match.group(1).lower()
        
        # Fallback: look for the last hex address pattern
        matches = re.findall(r'\+0x([0-9a-fA-F]+)', backtrace_entry)
        if matches:
            return matches[-1].lower()
        
        return None
    
    @staticmethod
    def get_pc_from_backtrace(backtrace: List[str]) -> Optional[str]:
        if not backtrace:
            return None
        
        # Find first non-library entry
        for entry in backtrace:
            if not BacktraceAnalyzer.is_library_path(entry):
                offset = BacktraceAnalyzer.extract_address_from_backtrace(entry)
                if offset:
                    return f"0x{offset.upper()}"
        
        # Fallback to first entry
        first_entry = backtrace[0]
        offset = BacktraceAnalyzer.extract_address_from_backtrace(first_entry)
        if offset:
            return f"0x{offset.upper()}"
        
        return None


class ArgumentDisplay:
    
    @staticmethod
    def format_argument_info(arg: Dict, arg_index: int, arg_name: str) -> Tuple[str, str]:
        arg_type = arg.get('type', 'unknown')
        
        if arg_type == 'VPTR':
            string_content = arg.get('str', '')
            buf = arg.get('buf', [])
            if buf:
                actual_length = len(buf)
                content_info = f' = "{string_content}" (length: {actual_length} bytes)'
                size_info = f' [{actual_length} bytes]'
            else:
                content_info = f' = "{string_content}"'
                size_info = ' [pointer: 8 bytes]'
        
        elif arg_type == 'PPCHAR':
            pchars = arg.get('pchars', [])
            if pchars:
                content_info = f' (array with {len(pchars)} elements)'
            else:
                content_info = ' (empty array)'
            size_info = ' [pointer: 8 bytes]'
        
        elif arg_type == 'IOVEC':
            vptrs = arg.get('vptrs', [])
            if vptrs:
                total_size = sum(TaintAnalyzer.get_argument_size(vptr) for vptr in vptrs)
                # Show first iovec entry content
                first_vptr = vptrs[0]
                if TaintAnalyzer.has_taint_data(first_vptr):
                    string_content = first_vptr.get('str', '')
                    if string_content:
                        # Truncate for display
                        if len(string_content) > 60:
                            truncated = string_content[:57] + "..."
                        else:
                            truncated = string_content
                        content_info = f' = "{truncated}" (iovec with {len(vptrs)} entries, total {total_size} bytes)'
                    else:
                        content_info = f' (iovec with {len(vptrs)} entries, total {total_size} bytes)'
                else:
                    content_info = f' (iovec with {len(vptrs)} entries, total {total_size} bytes)'
            else:
                content_info = ' (empty iovec)'
            size_info = ' [iovec array]'
        
        elif arg_type in ['QWORD', 'DWORD', 'WORD', 'BYTE']:
            value_field = arg_type.lower()
            value = arg.get(value_field, 0)
            content_info = f' = 0x{value:x}'
            size_info = f' [{TaintAnalyzer.get_argument_size(arg)} bytes]'
        
        else:
            content_info = ''
            size_info = ' [unknown size]'
        
        return content_info, size_info

class SyscallSelector:
    
    def __init__(self, config_file: str = "syscall_config.json"):
        self.config = SyscallConfig(config_file)
        self.selected_syscall_name = ""
        self.selected_argument_name = ""
        self.selected_arg_index = 0
        self.selected_sub_arg_index = None
    
    def load_trace_data(self, filename: str) -> List[Dict]:
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in file '{filename}': {e}")
            sys.exit(1)
    
    def filter_tainted_syscalls(self, data: List[Dict]) -> List[Dict]:
        tainted_calls = []
        seen_signatures = set()
        skipped_count = 0
        duplicate_count = 0
        
        for call in data:
            if call.get('tainted', False):
                syscall_name = call.get('syscall', 'unknown')
                
                # Only include syscalls in configuration
                if self.config.is_supported(syscall_name):
                    # Simple deduplication based on syscall name and backtraces
                    signature = f"{syscall_name}|{call.get('taint_introduction_pc_backtrace', [])}|{call.get('backtrace', [])}"
                    if signature not in seen_signatures:
                        seen_signatures.add(signature)
                        tainted_calls.append(call)
                    else:
                        duplicate_count += 1
                else:
                    skipped_count += 1
        
        if skipped_count > 0:
            print(f"Skipped {skipped_count} tainted syscall(s) - not in configuration")
        if duplicate_count > 0:
            print(f"Removed {duplicate_count} duplicate tainted syscall(s)")
        
        return tainted_calls
        
    def display_tainted_syscalls(self, tainted_calls: List[Dict]):
        if not tainted_calls:
            print("\nNo tainted syscalls found in configuration.")
            print(f"Supported syscalls: {self.config.get_supported_syscalls()}")
            return
        
        print(f"\nTainted Syscalls Found:")
        print("=" * 50)
        
        for i, call in enumerate(tainted_calls, 1):
            syscall_name = call.get('syscall', 'unknown')
            config_info = self.config.get_syscall_info(syscall_name)
            
            print(f"{i}. {syscall_name} (syscall #{config_info.get('syscall_number', 'unknown')})")
            print(f"   Report: {call.get('report_num', 'N/A')}, PID: {call.get('pid', 'N/A')}")
            
            # Display tainted argument content on separate lines
            syscall_args = call.get('syscall_args', [])
            tainted_content = self._get_tainted_content_summary(syscall_args)
            if tainted_content:
                for content_line in tainted_content:
                    print(f"   Content: {content_line}")
            
            # Show first few backtrace frames
            backtrace = call.get('backtrace', [])
            print(f"   Backtrace:")
            for j, frame in enumerate(backtrace[:3]):
                lib_status = " (library)" if BacktraceAnalyzer.is_library_path(frame) else " (program)"
                print(f"     {j+1}: {frame}{lib_status}")
            if len(backtrace) > 3:
                print(f"     ... and {len(backtrace) - 3} more frames")
            print()

    def _get_tainted_content_summary(self, syscall_args: List[Dict]) -> List[str]:
        tainted_contents = []
        
        for i, arg in enumerate(syscall_args):
            if TaintAnalyzer.has_taint_data(arg):
                arg_type = arg.get('type', 'unknown')
                
                if arg_type == 'VPTR':
                    string_content = arg.get('str', '')
                    buf = arg.get('buf', [])
                    if string_content:  # Only show if there's actual content
                        if buf:
                            actual_length = len(buf)
                            content_summary = f'"{string_content}" (length: {actual_length} bytes)'
                        else:
                            content_summary = f'"{string_content}"'
                        tainted_contents.append(content_summary)
                
                elif arg_type == 'IOVEC':
                    vptrs = arg.get('vptrs', [])
                    if vptrs:
                        for j, vptr in enumerate(vptrs[:2]):  # Show first 2 iovec entries
                            if TaintAnalyzer.has_taint_data(vptr):
                                string_content = vptr.get('str', '')
                                if string_content:
                                    # Truncate long strings for display
                                    if len(string_content) > 80:
                                        truncated_content = string_content[:77] + "..."
                                    else:
                                        truncated_content = string_content
                                    
                                    buf = vptr.get('buf', [])
                                    if buf:
                                        actual_length = len(buf)
                                        content_summary = f'"{truncated_content}" (length: {actual_length} bytes)'
                                    else:
                                        content_summary = f'"{truncated_content}"'
                                    tainted_contents.append(f'iov[{j}]: {content_summary}')
                        
                        # If we have more than 2 entries, show a summary
                        if len(vptrs) > 2:
                            tainted_contents.append(f"... and {len(vptrs) - 2} more iovec entries")
                
                elif arg_type == 'PPCHAR':
                    pchars = arg.get('pchars', [])
                    if pchars:
                        argv_contents = []
                        for j, pchar in enumerate(pchars[:3]):
                            if pchar.get('qword', 0) != 0:
                                argv_str = pchar.get('str', '')
                                if argv_str:
                                    argv_contents.append(f'argv[{j}]="{argv_str}"')
                        
                        if argv_contents:
                            if len(pchars) > 3:
                                argv_contents.append(f"... and {len(pchars) - 3} more")
                            tainted_contents.append(f"[{', '.join(argv_contents)}]")
                
                elif arg_type in ['QWORD', 'DWORD', 'WORD', 'BYTE']:
                    value_field = arg_type.lower()
                    value = arg.get(value_field, 0)
                    if value != 0:  # Only show non-zero values
                        tainted_contents.append(f"{arg_type}: 0x{value:x}")
        
        return tainted_contents

    def select_syscall(self, tainted_calls: List[Dict]) -> Optional[Dict]:
        while True:
            try:
                choice = int(input(f"Select a tainted syscall (1-{len(tainted_calls)}): "))
                if 1 <= choice <= len(tainted_calls):
                    return tainted_calls[choice - 1]
                else:
                    print(f"Please enter a number between 1 and {len(tainted_calls)}")
            except ValueError:
                print("Please enter a valid number")
    
    def select_argument(self, syscall_call: Dict) -> Optional[Tuple[int, Optional[int]]]:
        syscall_name = syscall_call.get('syscall', 'unknown')
        syscall_args = syscall_call.get('syscall_args', [])
        config_info = self.config.get_syscall_info(syscall_name)
        
        self.selected_syscall_name = syscall_name
        
        if not config_info:
            print(f"Warning: No configuration found for {syscall_name}")
            result = self._select_generic_argument(syscall_args)
        elif config_info.get('special_handling', False):
            result = self._select_execve_argument(syscall_args, config_info)
        else:
            result = self._select_regular_argument(syscall_args, config_info)
        
        if result:
            self.selected_arg_index, self.selected_sub_arg_index = result
        
        return result
    
    def _select_generic_argument(self, syscall_args: List[Dict]) -> Optional[Tuple[int, None]]:
        tainted_choices = []
        
        print("Available tainted arguments:")
        for i, arg in enumerate(syscall_args):
            if TaintAnalyzer.has_taint_data(arg):
                content_info, size_info = ArgumentDisplay.format_argument_info(arg, i, f"arg{i}")
                print(f"  {i}: arg{i} ({arg.get('type', 'unknown')}){content_info}{size_info} [TAINTED]")
                tainted_choices.append(i)
        
        if not tainted_choices:
            print("No tainted arguments found!")
            return None
        
        while True:
            try:
                choice = int(input(f"Select argument from {tainted_choices}: "))
                if choice in tainted_choices:
                    return (choice, None)
                else:
                    print(f"Please select from: {tainted_choices}")
            except ValueError:
                print("Please enter a valid number")
    
    def _select_regular_argument(self, syscall_args: List[Dict], config_info: Dict) -> Optional[Tuple[int, None]]:
        valid_args = config_info.get('valid_args', [])
        arg_names = config_info.get('arg_names', [])
        
        print(f"\nSelected syscall: {self.selected_syscall_name}")
        print("Available tainted arguments:")
        
        tainted_choices = []
        
        # Check each valid argument - determine if config uses 0-based or 1-based indexing
        for i, arg_index in enumerate(valid_args):
            actual_index = arg_index
            if arg_index >= len(syscall_args) and arg_index > 0:
                actual_index = arg_index - 1
            
            if actual_index < len(syscall_args):
                arg = syscall_args[actual_index]
                
                has_taint = TaintAnalyzer.has_taint_data(arg)
                
                if has_taint:
                    arg_name = arg_names[i] if i < len(arg_names) else f"arg{actual_index}"
                    content_info, size_info = ArgumentDisplay.format_argument_info(arg, actual_index, arg_name)
                    print(f"  {actual_index}: {arg_name} ({arg.get('type', 'unknown')}){content_info}{size_info} [TAINTED]")
                    tainted_choices.append(actual_index)
        
        if not tainted_choices:
            print("No tainted arguments found in valid argument list!")
            return None
        
        while True:
            try:
                choice = int(input(f"Select argument from {tainted_choices}: "))
                if choice in tainted_choices:
                    # Find the argument name
                    for i, arg_index in enumerate(valid_args):
                        actual_index = arg_index if arg_index < len(syscall_args) else arg_index - 1
                        if actual_index == choice:
                            self.selected_argument_name = arg_names[i] if i < len(arg_names) else f"arg{choice}"
                            break
                    return (choice, None)
                else:
                    print(f"Please select from: {tainted_choices}")
            except ValueError:
                print("Please enter a valid number")
    
    def _select_execve_argument(self, syscall_args: List[Dict], config_info: Dict) -> Optional[Tuple[int, Optional[int]]]:
        nested_args = config_info.get('nested_args', {})
        
        print(f"\nExecutve Arguments:")
        main_choices = []
        
        # Show main arguments that have taint data
        for i, arg in enumerate(syscall_args):
            if TaintAnalyzer.has_taint_data(arg):
                arg_key = str(i)
                if arg_key in nested_args:
                    nested_info = nested_args[arg_key]
                    content_info, size_info = ArgumentDisplay.format_argument_info(arg, i, nested_info['description'])
                    print(f"  {i+1}: {nested_info['description']} ({arg.get('type', 'unknown')}){content_info}{size_info} [TAINTED]")
                    main_choices.append(i+1)
        
        if not main_choices:
            print("No tainted arguments found!")
            return None
        
        while True:
            try:
                main_choice = int(input(f"Select main argument from {main_choices}: "))
                if main_choice in main_choices:
                    main_choice -=1
                    break
                else:
                    print(f"Please select from: {main_choices}")
            except ValueError:
                print("Please enter a valid number")
        
        # Check for sub-arguments
        main_arg = syscall_args[main_choice]
        if (str(main_choice) in nested_args and 
            main_arg.get('type') == 'PPCHAR' and 
            'pchars' in main_arg):
            
            nested_info = nested_args[str(main_choice)]
            sub_args = nested_info.get('sub_args', {})
            pchars = main_arg['pchars']
            
            print(f"\nSub-arguments for {nested_info['description']}:")
            sub_choices = []
            
            for j, pchar in enumerate(pchars):
                if str(j) in sub_args and TaintAnalyzer.has_taint_data(pchar):
                    string_content = pchar.get('str', '')
                    is_null = pchar.get('qword', 0) == 0
                    if is_null:
                        status = " (NULL)"
                    else:
                        status = f' = "{string_content}"'
                    
                    print(f"  {j}: {sub_args[str(j)]}{status} [TAINTED]")
                    sub_choices.append(j)
            
            if sub_choices:
                while True:
                    try:
                        sub_choice = int(input(f"Select sub-argument from {sub_choices}: "))
                        if sub_choice in sub_choices:
                            self.selected_argument_name = f"argv[{sub_choice}]"
                            return (main_choice, sub_choice)  # Both already 0-based
                        else:
                            print(f"Please select from: {sub_choices}")
                    except ValueError:
                        print("Please enter a valid number")
        
        # No sub-arguments, return main argument
        nested_info = nested_args.get(str(main_choice), {})
        self.selected_argument_name = nested_info.get('description', f"arg{main_choice}")
        return (main_choice, None)
    
    def get_argument_info(self, syscall_args: List[Dict], arg_choice: Tuple[int, Optional[int]]) -> Tuple[int, int]:
        main_arg_index, sub_arg_index = arg_choice
        
        # Handle nested arguments (like execve argv[N])
        if sub_arg_index is not None:
            main_arg = syscall_args[main_arg_index]
            if main_arg.get('type') == 'PPCHAR' and 'pchars' in main_arg:
                pchars = main_arg['pchars']
                if sub_arg_index < len(pchars):
                    sub_arg = pchars[sub_arg_index]
                    if sub_arg.get('qword', 0) == 0:
                        print(f"Warning: argv[{sub_arg_index}] appears to be null")
                        return 0, 0
                    
                    address = TaintAnalyzer.get_taint_address(sub_arg)
                    size = TaintAnalyzer.get_argument_size(sub_arg)
                    return address, size
            return 0, 0
        
        # Handle regular arguments
        if main_arg_index < len(syscall_args):
            arg = syscall_args[main_arg_index]
            address = TaintAnalyzer.get_taint_address(arg)
            size = TaintAnalyzer.get_argument_size(arg)
            return address, size
        
        return 0, 0
        
    def generate_config(self, syscall_call: Dict, arg_choice: Tuple[int, Optional[int]]) -> str:
        syscall_name = syscall_call.get('syscall', 'unknown')
        config_info = self.config.get_syscall_info(syscall_name)
        syscall_number = config_info.get('syscall_number', 'unknown') if config_info else 'unknown'
        
        # Get double_run setting from configuration
        main_arg_index, sub_arg_index = arg_choice
        print(f"Main_arg: {main_arg_index}")
        double_run = self.config.get_double_run_setting(syscall_name, main_arg_index, sub_arg_index)
        solve = not double_run  # solve = !double_run
        
        # Extract all addresses from taint_introduction_pc_backtrace
        taint_backtrace = syscall_call.get('taint_introduction_pc_backtrace', [])
        taint_introduction_addresses = []
        
        for entry in taint_backtrace:
            address = BacktraceAnalyzer.extract_address_from_backtrace(entry)
            if address:
                # Convert to hex with 0x prefix
                taint_introduction_addresses.append(f"0x{address}")
        
        # Format the taint addresses array for Lua
        if taint_introduction_addresses:
            taint_introduction_pc_array = "{" + ",".join(taint_introduction_addresses) + "}"
        else:
            # Fallback to single address
            single_taint_pc = BacktraceAnalyzer.get_pc_from_backtrace(taint_backtrace)
            taint_introduction_pc_array = single_taint_pc or '0x0'
        
        # Extract all addresses from backtrace for syscall_sink_pc array
        backtrace = syscall_call.get('backtrace', [])
        syscall_sink_addresses = []
        
        for entry in backtrace:
            address = BacktraceAnalyzer.extract_address_from_backtrace(entry)
            if address:
                # Convert to hex with 0x prefix
                syscall_sink_addresses.append(f"0x{address}")
        
        # Format the addresses array for Lua
        if syscall_sink_addresses:
            syscall_sink_pc_array = "{" + ",".join(syscall_sink_addresses) + "}"
        else:
            # Fallback to single address
            single_pc = BacktraceAnalyzer.get_pc_from_backtrace(backtrace)
            syscall_sink_pc_array = single_pc or '0x0'
        
        # Get argument info
        syscall_args = syscall_call.get('syscall_args', [])
        buffer_address, buffer_size = self.get_argument_info(syscall_args, arg_choice)
        
        # Format output
        main_arg_index, sub_arg_index = arg_choice
        # print(f"Buffer address: {buffer_address}")
        # print(f"Taint introduction addresses: {taint_introduction_addresses}")
        # print(f"Syscall sink addresses: {syscall_sink_addresses}")
        # print(f"Double run setting: {double_run}")
        # print(f"Solve setting: {solve}")
        
        config_output = f"""
    pluginsConfig.traceanalysis = {{
        taint_introduction_pc = {taint_introduction_pc_array},
        buffer_to_symbolic = 0x{buffer_address:X},
        buffer_to_symbolic_size = {buffer_size},
        syscall_sink_pc = {syscall_sink_pc_array},
        target_syscall = {syscall_number}, -- {syscall_name}
        command = {main_arg_index}, -- {self.selected_argument_name}
        track_workers = true,
        process_name = "name_placeholder",
        base_binary = 0x7fff00000000,
        end_binary = 0x7ffff0000000,
        solve = {str(solve).lower()},
        double_run = {str(double_run).lower()}
    }}
    """
        return config_output


    def save_config(self, config_output: str, binary_name: str, template_file: str = "s2e-config.template.lua", 
                    output_file: str = "s2e-config.lua"):
        try:
            with open(template_file, 'r') as tf:
                template_content = tf.read()
        except IOError as e:
            print(f"Error reading template file {template_file}: {e}")
            return
        
        # Replace name_placeholder with binary_name
        dir_path = '/'.join(os.path.dirname(os.path.realpath(__file__)).split("/")[:-1])
        template_content = template_content.replace("name_placeholder", binary_name)
        template_content = template_content.replace("s2e_path_placeholder", dir_path)
        config_output = config_output.replace("name_placeholder", binary_name)
        
        print("\nGenerated Configuration:")
        print("=" * 50)
        print(f"S2E working path: {dir_path}/s2e-traceanalysis")
        print(config_output)

        try:
            with open(output_file, 'w') as of:
                of.write(template_content)
                of.write('\n')
                of.write(config_output)
                of.write('\n')
            print(f"\nConfiguration saved to {output_file}")
        except IOError as e:
            print(f"Error writing to output file {output_file}: {e}")
    
    def run(self, trace_file: str, binary_name: str):
        data = self.load_trace_data(trace_file)
        tainted_calls = self.filter_tainted_syscalls(data)
        
        if not tainted_calls:
            print("No tainted syscalls found in configuration.")
            return
        
        self.display_tainted_syscalls(tainted_calls)
        selected_call = self.select_syscall(tainted_calls)
        
        if not selected_call:
            return
        
        arg_choice = self.select_argument(selected_call)
        if not arg_choice:
            print("No valid arguments selected.")
            return
        
        # Generate and save config
        config = self.generate_config(selected_call, arg_choice)
        
        self.save_config(config, binary_name)


def main():
   if len(sys.argv) < 3 or len(sys.argv) > 4:
       print("Usage: python syscall_selector.py <binary_name> <trace_file> [config_file]")
       print("  binary_name: Name of the binary to replace name_placeholder")
       print("  trace_file: The syscall trace JSON file")
       print("  config_file: Optional syscall configuration file (default: syscall_config.json)")
       sys.exit(1)
   
   binary_name = sys.argv[1]
   trace_file = sys.argv[2]
   config_file = sys.argv[3] if len(sys.argv) == 4 else "syscall_config.json"
   
   selector = SyscallSelector(config_file)
   selector.run(trace_file, binary_name)


if __name__ == "__main__":
    main()