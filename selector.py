#!/usr/bin/env python3
"""
Syscall Taint Analysis Configuration Generator

This script analyzes syscall traces to identify tainted syscalls and generates
configuration files for S2E symbolic execution.
"""

import json
import sys
import re
from typing import Dict, List, Optional, Tuple, Union


class SyscallConfig:
    """Handles syscall configuration loading and validation."""
    
    def __init__(self, config_file: str = "syscall_config.json"):
        self.config = {}
        self.load_config(config_file)
    
    def load_config(self, config_file: str):
        """Load syscall configuration from JSON file."""
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
        """Get configuration info for a syscall."""
        return self.config.get(syscall_name)
    
    def is_supported(self, syscall_name: str) -> bool:
        """Check if syscall is supported in configuration."""
        return syscall_name in self.config
    
    def get_supported_syscalls(self) -> List[str]:
        """Get list of supported syscall names."""
        return list(self.config.keys())


class TaintAnalyzer:
    """Handles taint analysis and argument inspection."""
    
    @staticmethod
    def has_taint_data(arg: Dict) -> bool:
        """Check if an argument has any taint data."""
        arg_type = arg.get('type', 'unknown')
        
        def has_valid_taint_entries(taint_data):
            """Helper function to check if taint data has valid entries."""
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
        
        return False
    
    @staticmethod
    def get_taint_address(arg: Dict) -> Optional[int]:
        """Extract the taint address from an argument."""
        arg_type = arg.get('type', 'unknown')
        
        def find_valid_address_in_taint(taint_data):
            """Helper function to find first valid numeric address in taint data."""
            if not taint_data:
                return None
            
            for taint_entry in taint_data:
                if isinstance(taint_entry, list) and len(taint_entry) > 0:
                    # Found a list with addresses
                    if isinstance(taint_entry[0], int):
                        return taint_entry[0]
                elif isinstance(taint_entry, int):
                    # Direct integer value
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
        
        return 0
    @staticmethod
    def get_argument_size(arg: Dict) -> int:
        """Calculate the actual size of an argument."""
        arg_type = arg.get('type', 'unknown')
        
        if arg_type == 'VPTR':
            # For string pointers, use actual buffer length
            buf = arg.get('buf', [])
            if buf:
                return len(buf)
            # Fallback to string length + null terminator
            string_content = arg.get('str', '')
            return len(string_content.encode('utf-8')) + 1
        
        # Fixed sizes for other types
        size_map = {
            'QWORD': 8,
            'DWORD': 4, 
            'WORD': 2,
            'BYTE': 1,
            'PPCHAR': 8  # Pointer size
        }
        
        return size_map.get(arg_type, 8)  # Default to 8 bytes


class BacktraceAnalyzer:
    """Handles backtrace analysis and PC extraction."""
    
    LIBRARY_INDICATORS = [
        '/lib64/', '/lib/x86_64-linux-gnu/', '/lib/i386-linux-gnu/',
        '/lib/', '/usr/lib/', 'libc.so', 'ld-linux', '.so.'
    ]
    
    @staticmethod
    def is_library_path(backtrace_entry: str) -> bool:
        """Check if a backtrace entry is from a library."""
        return any(indicator in backtrace_entry for indicator in BacktraceAnalyzer.LIBRARY_INDICATORS)
    
    @staticmethod
    def extract_address_from_backtrace(backtrace_entry: str) -> Optional[str]:
        """Extract hex address from backtrace entry."""
        # Look for pattern like "server+0x7fff00102f74" after " at "
        match = re.search(r' at [^+]+\+0x([0-9a-fA-F]+)', backtrace_entry)
        if match:
            return match.group(1)
        
        # Fallback: look for the last hex address pattern
        matches = re.findall(r'\+0x([0-9a-fA-F]+)', backtrace_entry)
        if matches:
            return matches[-1]
        
        return None
    
    @staticmethod
    def get_pc_from_backtrace(backtrace: List[str]) -> Optional[str]:
        """Get PC from backtrace (first non-library entry)."""
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
    """Handles argument display formatting."""
    
    @staticmethod
    def format_argument_info(arg: Dict, arg_index: int, arg_name: str) -> Tuple[str, str]:
        """Format argument information for display."""
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
    """Main class for syscall selection and configuration generation."""
    
    def __init__(self, config_file: str = "syscall_config.json"):
        self.config = SyscallConfig(config_file)
        self.selected_syscall_name = ""
        self.selected_argument_name = ""
    
    def load_trace_data(self, filename: str) -> List[Dict]:
        """Load syscall trace data from JSON file."""
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
        """Filter syscalls to only include tainted ones that are in config."""
        tainted_calls = []
        seen_signatures = set()
        skipped_count = 0
        duplicate_count = 0
        
        for call in data:
            if call.get('tainted', False):
                syscall_name = call.get('syscall', 'unknown')
                
                # Only include syscalls in configuration
                if self.config.is_supported(syscall_name):
                    # Simple deduplication based on syscall name and args
                    signature = f"{syscall_name}|{len(call.get('syscall_args', []))}"
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
        """Display available tainted syscalls."""
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
            
            # Show first few backtrace frames
            backtrace = call.get('backtrace', [])
            print(f"   Backtrace:")
            for j, frame in enumerate(backtrace[:3]):
                lib_status = " (library)" if BacktraceAnalyzer.is_library_path(frame) else " (program)"
                print(f"     {j+1}: {frame}{lib_status}")
            if len(backtrace) > 3:
                print(f"     ... and {len(backtrace) - 3} more frames")
            print()
    
    def select_syscall(self, tainted_calls: List[Dict]) -> Optional[Dict]:
        """Let user select a syscall."""
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
        """Select argument for the syscall. Returns (arg_index, sub_arg_index)."""
        syscall_name = syscall_call.get('syscall', 'unknown')
        syscall_args = syscall_call.get('syscall_args', [])
        config_info = self.config.get_syscall_info(syscall_name)
        
        self.selected_syscall_name = syscall_name
        
        if not config_info:
            print(f"Warning: No configuration found for {syscall_name}")
            return self._select_generic_argument(syscall_args)
        
        # Handle special cases (like execve)
        if config_info.get('special_handling', False):
            return self._select_execve_argument(syscall_args, config_info)
        else:
            return self._select_regular_argument(syscall_args, config_info)
    
    def _select_generic_argument(self, syscall_args: List[Dict]) -> Optional[Tuple[int, None]]:
        """Select argument for unsupported syscalls."""
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
        """Select argument for regular syscalls."""
        valid_args = config_info.get('valid_args', [])
        arg_names = config_info.get('arg_names', [])
        
        print(f"\nSelected syscall: {self.selected_syscall_name}")
        print("Available tainted arguments:")
        
        tainted_choices = []
        
        # Debug: show what we're working with
        # print(f"DEBUG: valid_args from config: {valid_args}")
        # print(f"DEBUG: total syscall_args: {len(syscall_args)}")
        
        # Check each valid argument - determine if config uses 0-based or 1-based indexing
        for i, arg_index in enumerate(valid_args):
            # Try both 0-based and 1-based indexing
            actual_index = arg_index
            if arg_index >= len(syscall_args) and arg_index > 0:
                # Config might be 1-based, convert to 0-based
                actual_index = arg_index - 1
                # print(f"DEBUG: Converting {arg_index} to 0-based index {actual_index}")
            
            if actual_index < len(syscall_args):
                arg = syscall_args[actual_index]
                # print(f"DEBUG: Checking arg {actual_index}: type={arg.get('type')}")
                
                has_taint = TaintAnalyzer.has_taint_data(arg)
                # print(f"DEBUG: Arg {actual_index} has_taint_data: {has_taint}")
                
                if arg.get('type') == 'VPTR':
                    qword_taint = arg.get('qword_taint', [])
                    buf_taint = arg.get('buf_taint', [])
                    # print(f"DEBUG: VPTR qword_taint length: {len(qword_taint)}")
                    # print(f"DEBUG: VPTR buf_taint length: {len(buf_taint)}")
                    # if buf_taint:
                    #     print(f"DEBUG: First buf_taint entry: {buf_taint[0] if buf_taint else 'None'}")
                
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
                    return (choice, None)  # Return the actual 0-based index
                else:
                    print(f"Please select from: {tainted_choices}")
            except ValueError:
                print("Please enter a valid number")
    
    def _select_execve_argument(self, syscall_args: List[Dict], config_info: Dict) -> Optional[Tuple[int, Optional[int]]]:
        """Handle execve special case with nested arguments."""
        nested_args = config_info.get('nested_args', {})
        
        print(f"\nExecutve Arguments:")
        main_choices = []
        
        # Show main arguments that have taint data
        for i, arg in enumerate(syscall_args):
            if TaintAnalyzer.has_taint_data(arg):
                arg_key = str(i)  # Config uses 0-based indexing
                if arg_key in nested_args:
                    nested_info = nested_args[arg_key]
                    content_info, size_info = ArgumentDisplay.format_argument_info(arg, i, nested_info['description'])
                    print(f"  {i}: {nested_info['description']} ({arg.get('type', 'unknown')}){content_info}{size_info} [TAINTED]")
                    main_choices.append(i)
        
        if not main_choices:
            print("No tainted arguments found!")
            return None
        
        # Select main argument
        while True:
            try:
                main_choice = int(input(f"Select main argument from {main_choices}: "))
                if main_choice in main_choices:
                    break
                else:
                    print(f"Please select from: {main_choices}")
            except ValueError:
                print("Please enter a valid number")
        
        # Check for sub-arguments
        main_arg = syscall_args[main_choice]  # Already 0-based
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
        return (main_choice, None)  # Already 0-based
    
    def get_argument_info(self, syscall_args: List[Dict], arg_choice: Tuple[int, Optional[int]]) -> Tuple[int, int]:
        """Get address and size for the selected argument."""
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
        """Generate S2E configuration."""
        syscall_name = syscall_call.get('syscall', 'unknown')
        config_info = self.config.get_syscall_info(syscall_name)
        syscall_number = config_info.get('syscall_number', 'unknown') if config_info else 'unknown'
        
        # Get PCs
        taint_backtrace = syscall_call.get('taint_introduction_pc_backtrace', [])
        taint_introduction_pc = BacktraceAnalyzer.get_pc_from_backtrace(taint_backtrace)
        
        backtrace = syscall_call.get('backtrace', [])
        syscall_sink_pc = BacktraceAnalyzer.get_pc_from_backtrace(backtrace)
        
        # Get argument info
        syscall_args = syscall_call.get('syscall_args', [])
        buffer_address, buffer_size = self.get_argument_info(syscall_args, arg_choice)
        
        # Format output
        main_arg_index, sub_arg_index = arg_choice
        print(f"Buffer address: {buffer_address}")
        config_output = f"""
pluginsConfig.traceanalysis = {{
    taint_introduction_pc = {taint_introduction_pc or '0x0'},
    buffer_to_symbolic = 0x{buffer_address:X},
    buffer_to_symbolic_size = {buffer_size},
    syscall_sink_pc = {syscall_sink_pc or '0x0'},
    target_syscall = {syscall_number}, -- {syscall_name}
    command = {main_arg_index}, -- {self.selected_argument_name}
    track_workers = true,
    process_name = "reproducer"
}}
"""
        return config_output
    
    def save_config(self, config_output: str, template_file: str = "s2e-config.template.lua", 
                   output_file: str = "s2e-config.lua"):
        """Save configuration to file."""
        try:
            with open(template_file, 'r') as tf:
                template_content = tf.read()
        except IOError as e:
            print(f"Error reading template file {template_file}: {e}")
            return
        
        try:
            with open(output_file, 'w') as of:
                of.write(template_content)
                of.write('\n')
                of.write(config_output)
                of.write('\n')
            print(f"\nConfiguration saved to {output_file}")
        except IOError as e:
            print(f"Error writing to output file {output_file}: {e}")
    
    def run(self, trace_file: str):
        """Main execution flow."""
        # Load and filter data
        data = self.load_trace_data(trace_file)
        tainted_calls = self.filter_tainted_syscalls(data)
        
        if not tainted_calls:
            print("No tainted syscalls found in configuration.")
            return
        
        # Display and select
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
        
        print("\nGenerated Configuration:")
        print("=" * 50)
        print(config)
        
        self.save_config(config)


def main():
    """Main entry point."""
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python syscall_selector.py <trace_file> [config_file]")
        print("  trace_file: The syscall trace JSON file")
        print("  config_file: Optional syscall configuration file (default: syscall_config.json)")
        sys.exit(1)
    
    trace_file = sys.argv[1]
    config_file = sys.argv[2] if len(sys.argv) == 3 else "syscall_config.json"
    
    selector = SyscallSelector(config_file)
    selector.run(trace_file)


if __name__ == "__main__":
    main()