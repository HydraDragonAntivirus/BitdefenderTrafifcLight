import argparse
import os
import sys
import xml.etree.ElementTree as ET
import requests
import gzip
import shutil

# --- Configuration ---
BASE_UPDATE_URL = "http://upgrade.bitdefender.com/"

def deobfuscate_cvd_style(data: bytearray) -> bytearray:
    if not data:
        return data
    print("    [*] Applying chained XOR de-obfuscation...")
    key = 0xAA
    for i in range(len(data) - 1, -1, -1):
        original_byte = data[i]
        data[i] ^= key
        key = original_byte
    print("    [+] De-obfuscation complete.")
    return data

def parse_version_id(filepath: str) -> dict:
    print(f"[*] Parsing manifest file: {os.path.basename(filepath)}")
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        v3_node = root.find('v3')
        if v3_node is None:
            raise ValueError("<v3> tag not found in XML.")
        paths = {
            'id': v3_node.get('id_path'),
            'dat': v3_node.get('dat_path'),
            'sig': v3_node.get('sig_path')
        }
        if not all(paths.values()):
            raise ValueError("One or more required paths are missing in the <v3> tag.")
        print("[+] Manifest parsed successfully.")
        return paths
    except (ET.ParseError, ValueError, FileNotFoundError) as e:
        print(f"Error: Could not parse XML file. {e}", file=sys.stderr)
        sys.exit(1)

def download_file(url: str, output_path: str):
    print(f"[*] Downloading '{os.path.basename(url)}'...")
    try:
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            total_size = int(r.headers.get('content-length', 0))
            block_size = 8192
            with open(output_path, 'wb') as f:
                downloaded_size = 0
                for chunk in r.iter_content(chunk_size=block_size):
                    f.write(chunk)
                    downloaded_size += len(chunk)
                    progress = int(50 * downloaded_size / total_size) if total_size > 0 else 0
                    sys.stdout.write(f"\r    [{'#' * progress}{'.' * (50 - progress)}] {downloaded_size / (1024*1024):.2f} MB")
                    sys.stdout.flush()
        print("\n    [+] Download complete.")
    except requests.exceptions.RequestException as e:
        print(f"\nError: Failed to download file from {url}. {e}", file=sys.stderr)
        if os.path.exists(output_path):
            os.remove(output_path)
        sys.exit(1)

def decompress_gzip_file(gzip_path: str, output_path: str):
    print(f"[*] Decompressing '{os.path.basename(gzip_path)}'...")
    try:
        with gzip.open(gzip_path, 'rb') as f_in:
            with open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        print(f"    [+] Decompressed to '{os.path.basename(output_path)}'.")
    except (gzip.BadGzipFile, IOError) as e:
        print(f"Error: Failed to decompress file. {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Full workflow tool to download, decompress, and deobfuscate Bitdefender database packages from a version.id file.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("version_id_path", help="Path to the 'version.id' XML manifest file.")
    parser.add_argument("-o", "--output", default="unpacked_database", help="Output directory to save all files (default: 'unpacked_database').")
    args = parser.parse_args()

    if not os.path.isfile(args.version_id_path):
        print(f"Error: The provided path '{args.version_id_path}' is not a file. Please provide the path to 'version.id' itself.", file=sys.stderr)
        sys.exit(1)

    file_paths = parse_version_id(args.version_id_path)
    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] All output will be saved in: '{output_dir}'")

    downloaded_files = {}
    for key, remote_path in file_paths.items():
        if not remote_path:
            continue
        
        print("\n" + "-" * 50)
        full_url = BASE_UPDATE_URL + remote_path
        gzipped_filename = os.path.basename(remote_path)
        gzipped_filepath = os.path.join(output_dir, gzipped_filename)
        
        download_file(full_url, gzipped_filepath)
        
        unpacked_filename = gzipped_filename.replace(".gzip", "")
        unpacked_filepath = os.path.join(output_dir, unpacked_filename)
        decompress_gzip_file(gzipped_filepath, unpacked_filepath)
        
        os.remove(gzipped_filepath)
        downloaded_files[key] = unpacked_filepath

    print("\n" + "=" * 70)
    print("Final Processing Stage")
    print("=" * 70)
    
    dat_filepath = downloaded_files.get('dat')
    if dat_filepath:
        print(f"[*] Preparing to de-obfuscate the main data file: {os.path.basename(dat_filepath)}")
        try:
            with open(dat_filepath, 'rb') as f:
                dat_content = bytearray(f.read())
            
            deobfuscated_content = deobfuscate_cvd_style(dat_content)
            
            final_path = dat_filepath + ".dec"
            with open(final_path, 'wb') as f:
                f.write(deobfuscated_content)
            
            print(f"[+] Final de-obfuscated database saved to: {os.path.basename(final_path)}")
            os.remove(dat_filepath)
        except Exception as e:
            print(f"Error during final processing of DAT file: {e}", file=sys.stderr)
            
    print("\nWorkflow complete.")

if __name__ == "__main__":
    main()