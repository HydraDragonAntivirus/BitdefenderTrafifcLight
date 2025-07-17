import requests
import os
import re

def read_data_from_file(filename):
    """
    Reads the raw data content from a specified file.

    Args:
        filename (str): The name of the file to read from.

    Returns:
        str: The content of the file, or None if an error occurs.
    """
    try:
        # Open and read the entire file content.
        # It's good practice to specify encoding. UTF-8 is a safe bet.
        with open(filename, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        # Handle the case where the input file does not exist.
        print(f"Error: The file '{filename}' was not found.")
        print(f"Please make sure '{filename}' is in the same directory as the script.")
        return None
    except Exception as e:
        # Handle other potential file reading errors.
        print(f"An error occurred while reading the file: {e}")
        return None

def parse_urls_from_data(data):
    """
    Parses the raw CSV data to extract the URLs.
    It looks for the URL in the third column of each line.
    """
    urls = []
    # Split the data into individual lines
    lines = data.strip().split('\n')
    for line in lines:
        # Skip comments or empty lines
        if line.startswith('#') or not line.strip():
            continue
        try:
            # Split the CSV by commas, but handle commas within quotes
            parts = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', line)
            # The URL is the 3rd item (index 2). Remove surrounding quotes.
            url = parts[2].strip('"')
            urls.append(url)
        except IndexError:
            print(f"Could not parse line: {line}")
    return urls

def download_files(urls, download_directory="downloaded_malware"):
    """
    Downloads files from a list of URLs into a specified directory.

    Args:
        urls (list): A list of URLs to download from.
        download_directory (str): The name of the directory to save files to.
    """
    # Create the download directory if it doesn't exist
    if not os.path.exists(download_directory):
        os.makedirs(download_directory)
        print(f"Created directory: {download_directory}")

    # --- WARNING ---
    # The files downloaded by this script are from a malware database.
    # DO NOT run or open these files unless you are in a secure, isolated
    # environment (like a virtual machine) for analysis purposes.
    # These files are malicious and can harm your computer.
    print("\n--- SECURITY WARNING ---")
    print("The files being downloaded are potentially malicious.")
    print("DO NOT execute them on your primary machine.\n")

    for i, url in enumerate(urls):
        try:
            # Get the filename from the URL
            filename = url.split('/')[-1]
            if not filename:
                # If URL ends with a slash, create a generic name
                filename = f"file_{i}"

            # Construct the full path to save the file
            filepath = os.path.join(download_directory, filename)

            print(f"Downloading {url} -> {filepath}")

            # Make the request to the URL
            # We use a timeout to prevent the script from hanging indefinitely
            # We also use stream=True to handle large files efficiently
            response = requests.get(url, timeout=10, stream=True, headers={'User-Agent': 'Mozilla/5.0'})
            
            # Check if the request was successful (status code 200)
            response.raise_for_status()

            # Write the content to a local file
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            print(f"Successfully downloaded {filename}")

        except requests.exceptions.RequestException as e:
            # Handle network-related errors (e.g., connection error, timeout)
            print(f"Failed to download {url}. Reason: {e}")
        except Exception as e:
            # Handle other potential errors
            print(f"An unexpected error occurred for {url}. Reason: {e}")

if __name__ == "__main__":
    # Define the input filename
    input_filename = "urlhaus.txt"
    
    # Read the data from the specified file
    raw_data = read_data_from_file(input_filename)
    
    # Proceed only if data was successfully read from the file
    if raw_data:
        # First, parse the data to get the list of URLs
        url_list = parse_urls_from_data(raw_data)
        
        # Check if we have any URLs to process
        if url_list:
            print(f"Found {len(url_list)} URLs to download from '{input_filename}'.")
            # Second, download the files from the extracted URLs
            download_files(url_list)
            print("\nDownload process finished.")
        else:
            print(f"No valid URLs were found in '{input_filename}'.")

