# Domain Scanner

This tool scans a list of domains for their associated IPs and open ports, highlighting exploitable ports for potential vulnerabilities.

check_vulnerabilities.py
The script check_vulnerabilities.py will scan the specified IP and port using nmap to detect the running service and version.

It then queries the National Vulnerability Database (NVD) API for CVEs associated with the detected service and version.

## Folder Structure

domain-scanner/ ├── README.md ├── scan_domains.py ├── input/ │ └── input_domains.txt ├── output/ │ └── <domain_name>.txt (Generated results for each domain)

## How to Use
1. Install dependencies:
   - Python 3.x
   - `nmap` (Ensure it's installed and added to your PATH)

2. Add your list of domains to `input/input_domains.txt` (one domain per line).

3. Run the script:
   python3 scan_domains.py

   python3 check_vulnerabilities.py <ip address> <port number>

4. Results will be generated in the `output/` folder, one file per domain.

## Features
- Resolves domains to IPs.
- Scans for open ports using `nmap`.
- Identifies exploitable ports (e.g., FTP, HTTP, MySQL, etc.).
