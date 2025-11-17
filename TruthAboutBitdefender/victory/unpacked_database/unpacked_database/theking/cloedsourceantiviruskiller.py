import argparse
import os
import sys
import shutil

# ==============================================================================
#  Core De-obfuscation and Verification Logic
# ==============================================================================

def deobfuscate_data(data: bytearray) -> bytearray:
    """
    Performs the chained XOR de-obfuscation IN-PLACE on a bytearray.
    This is a direct Python implementation of the logic in sub_180008090.
    """
    if not data:
        return data
        
    key = 0xAA  # Initial key (-86 signed char)
    for i in range(len(data) - 1, -1, -1):
        original_byte = data[i]
        data[i] ^= key
        key = original_byte
    return data

def is_valid_after_deobfuscation(data: bytearray) -> bool:
    """
    Checks if the de-obfuscated data has the expected footer signature.
    This check is derived from the validation steps in sub_180008090.
    """
    if len(data) < 22: # The C code checks for a size > 0x16 (22)
        return False
    
    # Check for the magic byte: `*(BYTE *)(file_end - 10) == 5`
    footer_magic_byte = data[-10]
    
    # Check for the signature DWORD: `*(DWORD *)(file_end - 6) == -1`
    footer_signature = data[-6:-2] # Slice from end-6 up to (but not including) end-2

    if footer_magic_byte == 0x05 and footer_signature == b'\xff\xff\xff\xff':
        return True
    
    return False

# ==============================================================================
#  File Processing and Main Logic
# ==============================================================================

def process_file(filepath: str, base_input_path: str, output_base_path: str):
    """
    Loads a file, attempts to de-obfuscate it, verifies the result, and saves
    the correct version (either de-obfuscated or original).
    """
    relative_path = os.path.relpath(filepath, base_input_path)
    output_path = os.path.join(output_base_path, relative_path)
    
    print("-" * 70)
    print(f"Processing: {relative_path}")

    try:
        # Ensure the destination directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(filepath, 'rb') as f_in:
            original_data = f_in.read()

        # Create a mutable copy to attempt de-obfuscation on
        working_data = bytearray(original_data)
        
        # Always attempt the de-obfuscation
        deobfuscated_data = deobfuscate_data(working_data)

        # Now, verify if the result is valid
        if is_valid_after_deobfuscation(deobfuscated_data):
            print("  [SUCCESS] Footer signature matched. This file was obfuscated.")
            final_path = output_path + ".dec" # Add .dec to signify it was changed
            with open(final_path, 'wb') as f_out:
                f_out.write(deobfuscated_data)
            print(f"  [SAVE] Saved de-obfuscated content to: {os.path.basename(final_path)}")
        else:
            print("  [INFO] Footer signature mismatch. This file is not obfuscated with this method.")
            shutil.copy2(filepath, output_path)
            print(f"  [COPY] Copied original file to: {os.path.basename(output_path)}")

    except Exception as e:
        print(f"  [ERROR] Failed to process file '{filepath}': {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(
        description="Processes a local folder of Bitdefender files, intelligently de-obfuscating them based on content.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("input_folder", help="Path to the folder containing all the downloaded database files (e.g., 'Plugins').")
    parser.add_argument("-o", "--output", default="database_processed", help="Output directory to save all processed and copied files (default: 'database_processed').")
    
    args = parser.parse_args()

    if not os.path.isdir(args.input_folder):
        print(f"Error: The provided path '{args.input_folder}' is not a valid directory.", file=sys.stderr)
        sys.exit(1)

    input_path = os.path.abspath(args.input_folder)
    output_path = os.path.abspath(args.output)

    if input_path == output_path:
        print("Error: Input and output folders cannot be the same. Please specify a different output folder with -o.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Reading all files from: '{input_path}'")
    print(f"[*] Saving processed files to: '{output_path}'")
    
    for root, _, files in os.walk(input_path):
        for file in sorted(files):
            process_file(os.path.join(root, file), input_path, output_path)

    print("\n" + "=" * 70)
    print("Workflow complete. Your fully processed database is in the '{}' directory.".format(output_path))

if __name__ == "__main__":
    main()