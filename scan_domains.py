import os
import socket
import subprocess
from datetime import datetime

# Create the necessary folders if they don't exist
if not os.path.exists("input"):
    os.makedirs("input")
if not os.path.exists("output"):
    os.makedirs("output")

# Input and output file paths
input_file = "input/input_domains.txt"

def resolve_domain(domain):
    """
    Resolves a domain to its IP address.
    """
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

def scan_ports(ip):
    """
    Scans the open ports on a given IP using nmap and returns the result.
    """
    try:
        # Run nmap to get open ports
        result = subprocess.check_output(["nmap", "-Pn", "-T4", "-p-", ip], universal_newlines=True)
        return result
    except subprocess.CalledProcessError as e:
        return str(e)

def parse_exploitable_ports(nmap_output):
    """
    Identifies exploitable ports based on nmap output.
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

    for line in nmap_output.split("\n"):
        if "/tcp" in line and "open" in line:
            try:
                port = int(line.split("/")[0])
                if port in vulnerabilities:
                    exploitable_ports.append(f"Port {port}: {vulnerabilities[port]}")
            except ValueError:
                pass

    return exploitable_ports

def main():
    """
    Main script execution.
    """
    if not os.path.exists(input_file):
        print(f"Input file {input_file} not found. Please create it with a list of domains.")
        return

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

        # Scan ports
        print(f"Scanning ports for IP: {ip}")
        nmap_output = scan_ports(ip)

        # Parse exploitable ports
        exploitable_ports = parse_exploitable_ports(nmap_output)

        # Write results to file
        with open(result_file, "w") as file:
            file.write(f"Domain: {domain}\n")
            file.write(f"IP Address: {ip}\n")
            file.write(f"Scan Date: {datetime.now()}\n")
            file.write("\n--- Nmap Scan Results ---\n")
            file.write(nmap_output)
            file.write("\n--- Exploitable Ports ---\n")
            if exploitable_ports:
                file.write("\n".join(exploitable_ports) + "\n")
            else:
                file.write("No exploitable ports found.\n")

        print(f"Results for {domain} written to {result_file}")

if __name__ == "__main__":
    main()
