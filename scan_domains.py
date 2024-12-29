import os
import socket
from datetime import datetime
import shodan
import pandas as pd

# Create necessary folders if they don't exist
if not os.path.exists("input"):
    os.makedirs("input")
if not os.path.exists("output"):
    os.makedirs("output")

# Input and output file paths
input_file = "input/input_domains.txt"
output_excel_file = "output/domain_scan_results.xlsx"

# Replace this with your Shodan API key
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"

def resolve_domain(domain):
    """
    Resolves a domain to its IP address.
    """
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

def scan_with_shodan(ip, api):
    """
    Uses Shodan to get information about the IP, including open ports.
    """
    try:
        host = api.host(ip)
        return host
    except shodan.APIError as e:
        return f"Error: {str(e)}"

def main():
    """
    Main script execution.
    """
    if not os.path.exists(input_file):
        print(f"Input file {input_file} not found. Please create it with a list of domains.")
        return

    # Initialize Shodan API
    api = shodan.Shodan(SHODAN_API_KEY)

    # Read domains from input file
    with open(input_file, "r") as file:
        domains = [line.strip() for line in file.readlines() if line.strip()]

    if not domains:
        print(f"No domains found in {input_file}. Please add some domains.")
        return

    # Data to store results
    results = []

    for domain in domains:
        print(f"Scanning domain: {domain}")

        # Resolve domain to IP
        ip = resolve_domain(domain)
        if not ip:
            print(f"Could not resolve domain: {domain}")
            results.append({
                "Domain": domain,
                "IP Address": "Could not resolve",
                "Open Ports": "N/A"
            })
            continue

        print(f"Resolved {domain} to IP: {ip}")

        # Scan with Shodan
        print(f"Scanning IP with Shodan: {ip}")
        host_info = scan_with_shodan(ip, api)

        if isinstance(host_info, str) and host_info.startswith("Error"):
            print(f"Shodan Error for {ip}: {host_info}")
            results.append({
                "Domain": domain,
                "IP Address": ip,
                "Open Ports": f"Error from Shodan: {host_info}"
            })
            continue

        # Collect open ports
        open_ports = []
        if "data" in host_info:
            for service in host_info["data"]:
                port = service["port"]
                service_name = service.get("product", "Unknown Service")
                open_ports.append(f"{port} ({service_name})")

        results.append({
            "Domain": domain,
            "IP Address": ip,
            "Open Ports": ", ".join(open_ports) if open_ports else "No open ports"
        })

    # Save results to Excel
    df = pd.DataFrame(results)
    df.to_excel(output_excel_file, index=False)
    print(f"Results saved to {output_excel_file}")

if __name__ == "__main__":
    main()
