import re
import os

def parse_snort_log(file_path):
    # Regular expression pattern for matching IPv4 addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    
    # Expand the ~ to your actual home directory path (e.g., /home/username/)
    full_path = os.path.expanduser(file_path)
    
    try:
        # Open and read the Snort alert file
        with open(full_path, 'r') as file:
            log_data = file.read()
            # Find all IP matches in the text
            ips = re.findall(ip_pattern, log_data)
            return ips
    except FileNotFoundError:
        print(f"Error: The Snort log file '{full_path}' was not found.")
        return []

if __name__ == "__main__":
    # Pointing directly to the Snort log in the home directory
    target_file = "~/alert_fast.txt" 
    
    print(f"Reading and analyzing Snort log: {target_file}...")
    found_ips = parse_snort_log(target_file)
    
    if found_ips:
        # Filter duplicates by converting the list to a set
        unique_ips = set(found_ips)
        print(f"Extracted {len(unique_ips)} unique IP Addresses from Snort alerts:")
        for ip in unique_ips:
            print(f"- {ip}")
    else:
        print("No IP addresses found or file could not be read.")
