import os
import socket
from datetime import datetime
import shodan

# Create the necessary folders if they don't exist
if not os.path.exists("input"):
    os.makedirs("input")
if not os.path.exists("output"):
    os.makedirs("output")

# Input and output file paths
input_file = "input/input_domains.txt"

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

def parse_exploitable_ports(host_info):
    """
    Identifies exploitable ports based on Shodan data.
    """
    exploitable_ports = []
    vulnerabilities = {
        21: "FTP: Check for anonymous login or weak credentials.",
        22: "SSH: Check for weak credentials or misconfigurations.",
        23: "Telnet: Check for weak credentials or misconfigurations.",
        80: "HTTP: Check for directory traversal, XSS, or misconfigurations.",
        443: "HTTPS: Check for SSL vulnerabilities.",
        3306: "MySQL: Check for weak credentials or misconfigurations.",
        6379: "Redis: Check for misconfigurations or unauthorized access.",
        8080: "HTTP Alt: Check for admin panels or misconfigurations.",
        5900: "VNC: Check for weak passwords.",
        9100: "Printer: Check for remote code execution vulnerabilities."
    }

    if "data" in host_info:
        for service in host_info["data"]:
            port = service["port"]
            if port in vulnerabilities:
                exploitable_ports.append(f"Port {port}: {vulnerabilities[port]}")

    return exploitable_ports

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

    for domain in domains:
        print(f"Scanning domain: {domain}")
        result_file = f"output/{domain}.txt"

        # Resolve domain to IP
        ip = resolve_domain(domain)
        if not ip:
            print(f"Could not resolve domain: {domain}")
            with open(result_file, "w") as file:
                file.write(f"Domain: {domain}\nCould not resolve IP.\n")
            continue

        print(f"Resolved {domain} to IP: {ip}")

        # Scan with Shodan
        print(f"Scanning IP with Shodan: {ip}")
        host_info = scan_with_shodan(ip, api)

        if isinstance(host_info, str) and host_info.startswith("Error"):
            print(f"Shodan Error for {ip}: {host_info}")
            with open(result_file, "w") as file:
                file.write(f"Domain: {domain}\n")
                file.write(f"IP Address: {ip}\n")
                file.write(f"Error from Shodan: {host_info}\n")
            continue

        # Parse exploitable ports
        exploitable_ports = parse_exploitable_ports(host_info)

        # Write results to file
        with open(result_file, "w") as file:
            file.write(f"Domain: {domain}\n")
            file.write(f"IP Address: {ip}\n")
            file.write(f"Scan Date: {datetime.now()}\n\n")
            file.write("--- Shodan Scan Results ---\n")
            if "data" in host_info:
                for service in host_info["data"]:
                    file.write(f"Port: {service['port']}, Service: {service.get('product', 'Unknown')}\n")
            else:
                file.write("No open ports found.\n")
            file.write("\n--- Exploitable Ports ---\n")
            if exploitable_ports:
                file.write("\n".join(exploitable_ports) + "\n")
            else:
                file.write("No exploitable ports found.\n")

        print(f"Results for {domain} written to {result_file}")

if __name__ == "__main__":
    main()
