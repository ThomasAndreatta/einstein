#!/bin/bash

# Address translation script for PIN -> S2E
# Usage: ./translate_addresses.sh <einstein_output_file>

# Configuration
PIN_BASE_TYPICAL=0x7fff00000000      # PIN's typical base address
S2E_BASE=0x400000                    # S2E's base address

# Function to translate a single address
translate_address() {
    local addr=$1
    
    # Remove 0x prefix if present
    addr=${addr#0x}
    
    # Convert to decimal
    local addr_dec=$((16#$addr))
    local pin_base_dec=$((PIN_BASE_TYPICAL))
    local s2e_base_dec=$((S2E_BASE))
    
    # Calculate offset from PIN base
    local offset=$((addr_dec - pin_base_dec))
    
    # Calculate S2E address
    local s2e_addr=$((s2e_base_dec + offset))
    
    # Output in hex format
    printf "0x%x\n" $s2e_addr
}

# Function to get actual base address from /proc/maps
get_actual_base() {
    local binary_name=$1
    
    # Look for the binary in /proc/*/maps
    local base_addr=$(pgrep -f "$binary_name" | head -1 | xargs -I {} cat /proc/{}/maps 2>/dev/null | grep -E "r-xp.*$binary_name" | head -1 | cut -d'-' -f1)
    
    if [ -n "$base_addr" ]; then
        echo "0x$base_addr"
    else
        echo "0x7fff00000000"  # fallback
    fi
}

# Function to process Einstein JSON output file
process_einstein_output() {
    local input_file=$1
    local output_file="${input_file}.s2e_translated"
    
    echo "Translating addresses from $input_file to $output_file"
    
    # Use sed to replace all 0x7fff... addresses in the JSON
    sed -E 's/0x7fff([0-9a-fA-F]+)/0x40\1/g' "$input_file" > "$output_file"
    
    echo "Translation complete: $output_file"
    echo "Sample translations:"
    
    # Show a few example translations
    grep -oE '0x7fff[0-9a-fA-F]+' "$input_file" | head -5 | while read addr; do
        translated=$(translate_address "$addr")
        echo "  $addr -> $translated"
    done
}

# Function to extract specific addresses for S2E checks
extract_addresses_for_s2e() {
    local input_file=$1
    local output_file="${input_file}.s2e_checks"
    
    echo "Extracting addresses for S2E checks..."
    
    # Extract all addresses from backtraces that point to your binary
    jq -r '.[] | select(.backtrace) | .backtrace[] | select(contains("server+0x")) | gsub(".*server\\+"; "") | gsub(" \\(.*"; "")' "$input_file" | \
    while read addr; do
        # Convert to full address (assuming base 0x7fff00000000)
        full_addr="0x7fff00000000"
        # This is a simplified approach - you may need to adjust based on your binary's actual base
        echo "$addr"
    done > "$output_file"
    
    echo "S2E check addresses saved to: $output_file"
}

# Function to get key addresses from Einstein report
get_key_addresses() {
    local input_file=$1
    
    echo "Key addresses from Einstein analysis:"
    echo "===================================="
    
    # Extract addresses from backtraces in your binary
    echo "Addresses in your binary (server):"
    jq -r '.[] | .backtrace[] | select(contains("server+0x"))' "$input_file" | \
    grep -oE '0x7fff[0-9a-fA-F]+' | sort -u | while read addr; do
        translated=$(translate_address "$addr")
        echo "  PIN: $addr -> S2E: $translated"
    done
    
    echo ""
    echo "Taint introduction points:"
    jq -r '.[] | .taint_introduction_pc_backtrace[] | select(contains("server+0x"))' "$input_file" | \
    grep -oE '0x7fff[0-9a-fA-F]+' | sort -u | while read addr; do
        translated=$(translate_address "$addr")
        echo "  PIN: $addr -> S2E: $translated"
    done
}

# Main execution
if [ $# -eq 0 ]; then
    echo "Usage: $0 <address_or_file>"
    echo "Examples:"
    echo "  $0 0x7fff00102f03                    # Translate single address"
    echo "  $0 paste.txt                         # Translate entire JSON file"
    echo "  $0 --extract paste.txt               # Extract key addresses"
    echo "  $0 --s2e-checks paste.txt            # Generate S2E check addresses"
    echo "  $0 --interactive                     # Interactive mode"
    exit 1
fi

case "$1" in
    --interactive)
        echo "Interactive address translation (PIN -> S2E)"
        echo "Enter addresses (0x7fff...) or 'quit' to exit:"
        while true; do
            read -p "PIN address: " addr
            if [ "$addr" = "quit" ]; then
                break
            fi
            if [[ $addr =~ ^0x[0-9a-fA-F]+$ ]]; then
                translated=$(translate_address "$addr")
                echo "S2E address: $translated"
            else
                echo "Invalid address format. Use 0x7fff... format"
            fi
        done
        ;;
    --extract)
        # Extract key addresses for S2E
        if [ -f "$2" ]; then
            get_key_addresses "$2"
        else
            echo "File not found: $2"
            exit 1
        fi
        ;;
    --s2e-checks)
        # Generate S2E check addresses
        if [ -f "$2" ]; then
            extract_addresses_for_s2e "$2"
        else
            echo "File not found: $2"
            exit 1
        fi
        ;;
    0x*)
        # Single address translation
        translated=$(translate_address "$1")
        echo "PIN address: $1"
        echo "S2E address: $translated"
        ;;
    *)
        # File processing
        if [ -f "$1" ]; then
            process_einstein_output "$1"
        else
            echo "File not found: $1"
            exit 1
        fi
        ;;
esac