#!/usr/bin/env python3
import json
import sys
import re

# Global variable to store syscall configuration
SYSCALL_CONFIG = {}

def load_syscall_config(config_file):
    global SYSCALL_CONFIG
    try:
        with open(config_file, 'r') as f:
            SYSCALL_CONFIG = json.load(f)
        print(f"Loaded syscall configuration from {config_file}")
    except FileNotFoundError:
        print(f"Warning: Config file '{config_file}' not found. Using empty configuration.")
        SYSCALL_CONFIG = {}
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in config file '{config_file}': {e}")
        sys.exit(1)

def load_json_file(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in file '{filename}': {e}")
        sys.exit(1)

def is_library_path(backtrace_entry):
    library_indicators = [
        '/lib64/',
        '/lib/x86_64-linux-gnu/',
        '/lib/i386-linux-gnu/',
        '/lib/',
        '/usr/lib/',
        'libc.so',
        'ld-linux',
        '.so.'
    ]
    return any(indicator in backtrace_entry for indicator in library_indicators)

def extract_address_from_backtrace(backtrace_entry):
    # Look for pattern like "server+0x7fff00102f74" after " at "
    # This gives us the absolute address in the binary, not just the function offset
    match = re.search(r' at [^+]+\+0x([0-9a-fA-F]+)', backtrace_entry)
    if match:
        return match.group(1)
    
    # Fallback: look for the last hex address pattern in the entry
    matches = re.findall(r'\+0x([0-9a-fA-F]+)', backtrace_entry)
    if matches:
        return matches[-1]  # Return the last (absolute) address
    return None

def get_syscall_sink_pc(backtrace):
    if not backtrace:
        return None
    
    # Find the first non-library entry
    for entry in backtrace:
        if not is_library_path(entry):
            offset = extract_address_from_backtrace(entry)
            if offset:
                return f"0x{offset.upper()}"
    
    # If no non-library entry found, fall back to first entry
    first_entry = backtrace[0]
    offset = extract_address_from_backtrace(first_entry)
    if offset:
        return f"0x{offset.upper()}"
    return None

def get_taint_introduction_pc(taint_backtrace):
    if not taint_backtrace:
        return None
    
    # Find the first non-library entry
    for entry in taint_backtrace:
        if not is_library_path(entry):
            offset = extract_address_from_backtrace(entry)
            if offset:
                return f"0x{offset.upper()}"
    
    # If no non-library entry found, fall back to first entry
    first_entry = taint_backtrace[0]
    offset = extract_address_from_backtrace(first_entry)
    if offset:
        return f"0x{offset.upper()}"
    return None

def create_syscall_signature(call):
    syscall_name = call.get('syscall', 'unknown')
    syscall_args = call.get('syscall_args', [])
    backtrace = call.get('backtrace', [])
    
    # Create a signature based on syscall name, args, and backtrace
    args_signature = []
    for arg in syscall_args:
        if arg['type'] == 'QWORD':
            args_signature.append(f"QWORD:{arg.get('qword', 0)}")
        elif arg['type'] == 'DWORD':
            args_signature.append(f"DWORD:{arg.get('dword', 0)}")
        elif arg['type'] == 'WORD':
            args_signature.append(f"WORD:{arg.get('word', 0)}")
        elif arg['type'] == 'BYTE':
            args_signature.append(f"BYTE:{arg.get('byte', 0)}")
    
    # Use first few backtrace entries for signature (skip library calls)
    backtrace_signature = []
    for entry in backtrace[:3]:  # Use first 3 entries
        if not is_library_path(entry):
            backtrace_signature.append(entry)
    
    signature = f"{syscall_name}|{','.join(args_signature)}|{','.join(backtrace_signature)}"
    return signature

def filter_tainted_syscalls(data):
    tainted_calls = []
    seen_signatures = set()
    skipped_count = 0
    duplicate_count = 0
    
    for call in data:
        if call.get('tainted', False):
            syscall_name = call.get('syscall', 'unknown')
            # Only include syscalls that are in the configuration
            if syscall_name in SYSCALL_CONFIG:
                # Check for duplicates
                signature = create_syscall_signature(call)
                if signature not in seen_signatures:
                    seen_signatures.add(signature)
                    tainted_calls.append(call)
                else:
                    duplicate_count += 1
            else:
                skipped_count += 1
    
    if skipped_count > 0:
        print(f"Skipped {skipped_count} tainted syscall(s) - not found in configuration")
    if duplicate_count > 0:
        print(f"Removed {duplicate_count} duplicate tainted syscall(s)")
    
    return tainted_calls

def has_taint_data(arg):
    """Check if an argument has any taint data."""
    arg_type = arg.get('type', 'unknown')
    
    if arg_type == 'QWORD':
        qword_taint = arg.get('qword_taint', [])
        return qword_taint and any(taint_list for taint_list in qword_taint if taint_list)
    elif arg_type == 'DWORD':
        dword_taint = arg.get('dword_taint', [])
        return dword_taint and any(taint_list for taint_list in dword_taint if taint_list)
    elif arg_type == 'WORD':
        word_taint = arg.get('word_taint', [])
        return word_taint and any(taint_list for taint_list in word_taint if taint_list)
    elif arg_type == 'BYTE':
        byte_taint = arg.get('byte_taint', [])
        return byte_taint and any(taint_list for taint_list in byte_taint if taint_list)
    elif arg_type == 'VPTR':
        # Check both qword_taint and buf_taint for string pointers
        qword_taint = arg.get('qword_taint', [])
        buf_taint = arg.get('buf_taint', [])
        return ((qword_taint and any(taint_list for taint_list in qword_taint if taint_list)) or
                (buf_taint and any(taint_list for taint_list in buf_taint if taint_list)))
    elif arg_type == 'PPCHAR':
        # Check qword_taint and also check nested pchars
        qword_taint = arg.get('qword_taint', [])
        has_qword_taint = qword_taint and any(taint_list for taint_list in qword_taint if taint_list)
        
        # Check if any of the nested pchars have taint
        pchars = arg.get('pchars', [])
        has_nested_taint = False
        for pchar in pchars:
            if has_taint_data(pchar):  # Recursive check
                has_nested_taint = True
                break
        
        return has_qword_taint or has_nested_taint
    
    return False

def get_argument_display_info(arg, arg_index, arg_name):
    """Get display information for an argument including its content and size."""
    arg_type = arg.get('type', 'unknown')
    content_info = ""
    size_info = ""
    
    if arg_type == 'VPTR':
        # String pointer - show string content and calculate actual length
        string_content = arg.get('str', '')
        buf = arg.get('buf', [])
        if buf:
            # Calculate actual buffer length (including null terminator if present)
            actual_length = len(buf)
            content_info = f" = \"{string_content}\" (actual length: {actual_length} bytes)"
            size_info = f" [{actual_length} bytes]"
        else:
            content_info = f" = \"{string_content}\""
            size_info = f" [pointer: 8 bytes]"
    elif arg_type == 'PPCHAR':
        # Array of string pointers
        pchars = arg.get('pchars', [])
        if pchars:
            content_info = f" (array with {len(pchars)} elements)"
            size_info = f" [pointer: 8 bytes]"
        else:
            content_info = " (empty array)"
            size_info = f" [pointer: 8 bytes]"
    elif arg_type == 'QWORD':
        value = arg.get('qword', 0)
        content_info = f" = 0x{value:x}"
        size_info = f" [8 bytes]"
    elif arg_type == 'DWORD':
        value = arg.get('dword', 0)
        content_info = f" = 0x{value:x}"
        size_info = f" [4 bytes]"
    elif arg_type == 'WORD':
        value = arg.get('word', 0)
        content_info = f" = 0x{value:x}"
        size_info = f" [2 bytes]"
    elif arg_type == 'BYTE':
        value = arg.get('byte', 0)
        content_info = f" = 0x{value:x}"
        size_info = f" [1 byte]"
    else:
        content_info = ""
        size_info = f" [unknown size]"
    
    return content_info, size_info

def display_tainted_syscalls(tainted_calls):
    if not tainted_calls:
        print("\nNo tainted syscalls found that are defined in the configuration file.")
        return
        
    print(f"\nTainted Syscalls Found (from config file):")
    print("=" * 50)
    
    for i, call in enumerate(tainted_calls, 1):
        syscall_name = call.get('syscall', 'unknown')
        report_num = call.get('report_num', 'N/A')
        pid = call.get('pid', 'N/A')
        
        # Show syscall info from config
        config_info = SYSCALL_CONFIG.get(syscall_name, {})
        syscall_number = config_info.get('syscall_number', 'unknown')
        valid_args = config_info.get('valid_args', [])
        
        print(f"{i}. Syscall: {syscall_name} (syscall #{syscall_number})")
        print(f"   Report Number: {report_num}")
        print(f"   PID: {pid}")
        print(f"   Valid Arguments: {valid_args}")
        print(f"   Backtrace:")
        
        backtrace = call.get('backtrace', [])
        for j, frame in enumerate(backtrace[:5]):  # Show first 5 frames
            library_indicator = " (library)" if is_library_path(frame) else " (program)"
            print(f"     {j+1}: {frame}{library_indicator}")
        if len(backtrace) > 5:
            print(f"     ... and {len(backtrace) - 5} more frames")
        print()

def select_execve_argument(syscall_args, config_info):
    """Handle special case for execve with nested arguments."""
    nested_args = config_info.get('nested_args', {})
    
    print(f"\nExecutve Arguments:")
    main_choices = []
    
    # Show main arguments (only those with taint data)
    for i, arg in enumerate(syscall_args, 1):
        if has_taint_data(arg):  # Only show if argument has taint data
            if str(i) in nested_args:
                nested_info = nested_args[str(i)]
                content_info, size_info = get_argument_display_info(arg, i, nested_info['description'])
                print(f"  {i}: {nested_info['description']} ({arg.get('type', 'unknown')}){content_info}{size_info} [TAINTED]")
                main_choices.append(i)
            else:
                arg_names = config_info.get('arg_names', [])
                arg_name = arg_names[i-1] if i-1 < len(arg_names) else f"arg{i}"
                content_info, size_info = get_argument_display_info(arg, i, arg_name)
                print(f"  {i}: {arg_name} ({arg.get('type', 'unknown')}){content_info}{size_info} [TAINTED]")
                main_choices.append(i)
    
    if not main_choices:
        print("No tainted arguments found for this syscall!")
        return None, None
    
    # Select main argument
    while True:
        try:
            main_choice = int(input(f"\nSelect main argument from tainted options {main_choices}: "))
            if main_choice in main_choices:
                break
            else:
                print(f"Please select from tainted arguments: {main_choices}")
        except ValueError:
            print("Please enter a valid number")
    
    # Check if this argument has sub-arguments
    main_arg = syscall_args[main_choice - 1]
    if str(main_choice) in nested_args and main_arg.get('type') == 'PPCHAR' and 'pchars' in main_arg:
        nested_info = nested_args[str(main_choice)]
        sub_args = nested_info.get('sub_args', {})
        pchars = main_arg['pchars']
        
        print(f"\nSub-arguments for {nested_info['description']}:")
        sub_choices = []
        for j, pchar in enumerate(pchars):
            if str(j) in sub_args and has_taint_data(pchar):  # Only show if has taint data
                string_content = pchar.get('str', '')
                is_null = pchar.get('qword', 0) == 0
                if is_null:
                    status = " (NULL)"
                    size_info = " [0 bytes]"
                else:
                    buf = pchar.get('buf', [])
                    if buf:
                        actual_length = len(buf)
                        status = f" = \"{string_content}\" (length: {actual_length} bytes)"
                        size_info = f" [{actual_length} bytes]"
                    else:
                        status = f" = \"{string_content}\""
                        size_info = f" [pointer: 8 bytes]"
                print(f"  {j}: {sub_args[str(j)]}{status}{size_info} [TAINTED]")
                sub_choices.append(j)
        
        if sub_choices:
            while True:
                try:
                    sub_choice = int(input(f"\nSelect sub-argument from tainted options {sub_choices}: "))
                    if sub_choice in sub_choices:
                        return main_choice, sub_choice
                    else:
                        print(f"Please select from tainted sub-arguments: {sub_choices}")
                except ValueError:
                    print("Please enter a valid number")
        else:
            print("No tainted sub-arguments available")
            return main_choice, None
    else:
        return main_choice, None

def select_syscall_and_argument(tainted_calls):
    while True:
        try:
            choice = int(input(f"\nSelect a tainted syscall (1-{len(tainted_calls)}): "))
            if 1 <= choice <= len(tainted_calls):
                selected_call = tainted_calls[choice - 1]
                break
            else:
                print(f"Please enter a number between 1 and {len(tainted_calls)}")
        except ValueError:
            print("Please enter a valid number")
    
    syscall_name = selected_call.get('syscall', 'unknown')
    syscall_args = selected_call.get('syscall_args', [])
    
    # Check if syscall is supported
    if syscall_name not in SYSCALL_CONFIG:
        print(f"Warning: Syscall '{syscall_name}' not found in configuration")
        print(f"Available tainted arguments:")
        
        # Only show arguments that have taint data
        tainted_arg_choices = []
        for i, arg in enumerate(syscall_args, 1):
            if has_taint_data(arg):
                content_info, size_info = get_argument_display_info(arg, i, f"arg{i}")
                print(f"  {i}: arg{i} ({arg.get('type', 'unknown')}){content_info}{size_info} [TAINTED]")
                tainted_arg_choices.append(i)
        
        if not tainted_arg_choices:
            print("No tainted arguments found for this syscall!")
            return None, None, None
        
        while True:
            try:
                arg_choice = int(input(f"Select argument to track from tainted options {tainted_arg_choices}: "))
                if arg_choice in tainted_arg_choices:
                    break
                else:
                    print(f"Please select from tainted arguments: {tainted_arg_choices}")
            except ValueError:
                print("Please enter a valid number")
        return selected_call, arg_choice, None
    
    config = SYSCALL_CONFIG[syscall_name]
    syscall_number = config['syscall_number']
    
    # Handle special case for execve
    if syscall_name == 'execve' and config.get('special_handling', False):
        main_arg, sub_arg = select_execve_argument(syscall_args, config)
        if main_arg is None:
            print("No tainted arguments available for selection!")
            return None, None, None
        if sub_arg is not None:
            arg_choice = (main_arg, sub_arg)  # Return tuple for nested
        else:
            arg_choice = main_arg
    else:
        # Regular syscall handling - only show tainted arguments
        valid_args = config['valid_args']
        arg_names = config['arg_names']
        
        print(f"\nSelected syscall: {syscall_name}")
        print(f"Available tainted arguments:")
        
        # Filter to only show arguments that are both valid and tainted
        tainted_valid_choices = []
        for i, arg_name in enumerate(arg_names, 1):
            if i in valid_args and i <= len(syscall_args) and has_taint_data(syscall_args[i-1]):
                arg = syscall_args[i-1]
                content_info, size_info = get_argument_display_info(arg, i, arg_name)
                print(f"  {i}: {arg_name} ({arg.get('type', 'unknown')}){content_info}{size_info} [TAINTED]")
                tainted_valid_choices.append(i)
        
        if not tainted_valid_choices:
            print("No tainted arguments found in the valid argument list!")
            return None, None, None
        
        # Select argument
        while True:
            try:
                arg_choice = int(input(f"\nSelect argument to track from tainted options {tainted_valid_choices}: "))
                if arg_choice in tainted_valid_choices:
                    break
                else:
                    print(f"Please select from tainted arguments: {tainted_valid_choices}")
            except ValueError:
                print("Please enter a valid number")
    
    return selected_call, arg_choice, syscall_number

def get_argument_size(arg):
    """Calculate the actual size of an argument based on its type and content."""
    arg_type = arg.get('type', 'unknown')
    
    if arg_type == 'VPTR':
        # For string pointers, use the actual buffer length if available
        buf = arg.get('buf', [])
        if buf:
            return len(buf)  # Actual string length including null terminator
        else:
            # Fallback: try to calculate from string content
            string_content = arg.get('str', '')
            return len(string_content.encode('utf-8')) + 1  # +1 for null terminator
    elif arg_type == 'PPCHAR':
        return 8  # Pointer size
    elif arg_type == 'QWORD':
        return 8
    elif arg_type == 'DWORD':
        return 4
    elif arg_type == 'WORD':
        return 2
    elif arg_type == 'BYTE':
        return 1
    else:
        return 8  # Default fallback

def get_execve_nested_argument_info(syscall_args, main_arg, sub_arg):
    if main_arg < 1 or main_arg > len(syscall_args):
        return None, None
        
    main_argument = syscall_args[main_arg - 1]
    
    if main_argument.get('type') == 'PPCHAR' and 'pchars' in main_argument:
        pchars = main_argument['pchars']
        if sub_arg < len(pchars):
            sub_argument = pchars[sub_arg]
            # Check if this is a null pointer or empty entry
            if sub_argument.get('qword', 0) == 0:
                print(f"Warning: argv[{sub_arg}] appears to be null or empty")
                return 0, 0
            
            # Get taint from the nested structure
            taint_data = sub_argument.get('qword_taint', [])
            if taint_data and len(taint_data) > 0 and len(taint_data[0]) > 0:
                address = taint_data[0][0]
            else:
                address = sub_argument.get('qword', 0)
            
            # Calculate size for the string content
            size = get_argument_size(sub_argument)
            return address, size
        else:
            print(f"Warning: argv[{sub_arg}] index out of range")
            return None, None
    
    return None, None

def get_argument_info(syscall_args, arg_choice):
    # Handle execve nested arguments (tuple format)
    if isinstance(arg_choice, tuple) and len(arg_choice) == 2:
        main_arg, sub_arg = arg_choice
        return get_execve_nested_argument_info(syscall_args, main_arg, sub_arg)
    
    # Handle regular arguments (must be integer)
    arg_index = arg_choice
    
    # Regular argument handling for non-nested cases
    if arg_index < 1 or arg_index > len(syscall_args):
        return None, None
    
    arg = syscall_args[arg_index - 1]  # Convert to 0-based index
    
    # Get the address and size based on argument type
    address = None
    size = get_argument_size(arg)
    
    if arg['type'] == 'QWORD':
        address = arg.get('qword', 0)
        # Get the first taint address if available
        qword_taint = arg.get('qword_taint', [])
        if qword_taint and len(qword_taint) > 0 and len(qword_taint[0]) > 0:
            address = qword_taint[0][0]  # First element of first taint entry
    elif arg['type'] == 'DWORD':
        address = arg.get('dword', 0)
        # Get the first taint address if available
        dword_taint = arg.get('dword_taint', [])
        if dword_taint and len(dword_taint) > 0 and len(dword_taint[0]) > 0:
            address = dword_taint[0][0]  # First element of first taint entry
    elif arg['type'] == 'WORD':
        address = arg.get('word', 0)
        # Get the first taint address if available
        word_taint = arg.get('word_taint', [])
        if word_taint and len(word_taint) > 0 and len(word_taint[0]) > 0:
            address = word_taint[0][0]  # First element of first taint entry
    elif arg['type'] == 'BYTE':
        address = arg.get('byte', 0)
        # Get the first taint address if available
        byte_taint = arg.get('byte_taint', [])
        if byte_taint and len(byte_taint) > 0 and len(byte_taint[0]) > 0:
            address = byte_taint[0][0]  # First element of first taint entry
    elif arg['type'] in ['VPTR', 'PPCHAR']:
        address = arg.get('qword', 0)
        # Get the first taint address if available
        qword_taint = arg.get('qword_taint', [])
        if qword_taint and len(qword_taint) > 0 and len(qword_taint[0]) > 0:
            address = qword_taint[0][0]  # First element of first taint entry
    
    return address, size

def generate_config(selected_call, arg_choice, syscall_number):
    # Get taint introduction PC (first non-library entry)
    taint_backtrace = selected_call.get('taint_introduction_pc_backtrace', [])
    taint_introduction_pc = get_taint_introduction_pc(taint_backtrace)
    
    # Get syscall sink PC (first non-library entry)
    backtrace = selected_call.get('backtrace', [])
    syscall_sink_pc = get_syscall_sink_pc(backtrace)
    
    # Get argument info
    syscall_args = selected_call.get('syscall_args', [])
    buffer_address, buffer_size = get_argument_info(syscall_args, arg_choice)
    
    # Format buffer address properly
    buffer_addr_hex = f"0x{buffer_address:X}" if buffer_address else "0x0"
    
    # Determine argument number (0-based indexing for syscalls)
    if isinstance(arg_choice, tuple) and len(arg_choice) == 2:
        # For nested arguments like execve argv[N], use the main argument index (0-based)
        argument_number = arg_choice[0] - 1
    else:
        # For regular arguments, convert from 1-based to 0-based
        argument_number = arg_choice - 1
    
    # Format the output
    config_output = f"""
pluginsConfig.traceanalysis = {{
    taint_introduction_pc = {taint_introduction_pc or '0x0'},
    buffer_to_symbolic = {buffer_addr_hex},
    buffer_to_symbolic_size = {buffer_size or 0},
    syscall_sink_pc = {syscall_sink_pc or '0x0'},
    target_syscall = {syscall_number if syscall_number is not None else 'unknown'},
    command = {argument_number},
}}
"""
    
    return config_output

def save_config_to_file(config_output, template_file="s2e-config.template.lua", output_file="s2e-config.lua"):
    try:
        with open(template_file, 'r') as tf:
            template_content = tf.read()
    except IOError as e:
        print(f"Error reading from template file {template_file}: {e}")
        return

    try:
        with open(output_file, 'w') as of:
            of.write(template_content)
            of.write('\n')  # Separate from template
            of.write(config_output)
            of.write('\n')  # Extra newline
        print(f"\nConfiguration saved to {output_file}")
    except IOError as e:
        print(f"Error writing to output file {output_file}: {e}")

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python tainted_syscall_analyzer.py <json_file> [config_file]")
        print("  json_file: The syscall trace JSON file")
        print("  config_file: Optional syscall configuration file (default: syscall_config.json)")
        sys.exit(1)
    
    filename = sys.argv[1]
    config_file = sys.argv[2] if len(sys.argv) == 3 else "syscall_config.json"
    
    # Load syscall configuration
    load_syscall_config(config_file)
    
    # Load JSON data
    data = load_json_file(filename)
    
    # Filter tainted syscalls (only those in config file)
    tainted_calls = filter_tainted_syscalls(data)
    
    if not tainted_calls:
        print("No tainted syscalls found that are defined in the configuration file.")
        print(f"Available syscalls in config: {list(SYSCALL_CONFIG.keys())}")
        sys.exit(0)
    
    # Display tainted syscalls
    display_tainted_syscalls(tainted_calls)
    
    # Let user select syscall and argument
    selected_call, arg_choice, syscall_number = select_syscall_and_argument(tainted_calls)
    
    # Check if selection was successful
    if selected_call is None:
        print("No valid tainted arguments available for configuration generation.")
        sys.exit(0)
    
    # Generate configuration
    config = generate_config(selected_call, arg_choice, syscall_number)
    
    print("\nGenerated Configuration:")
    print("=" * 50)
    print(config)
    
    # Save to file
    save_config_to_file(config)

if __name__ == "__main__":
    main()