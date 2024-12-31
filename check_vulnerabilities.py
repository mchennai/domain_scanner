import nmap
import requests
import argparse

def scan_target(ip, ports):
    """
    Use nmap to scan the IP address and specified ports to detect running services and versions.
    """
    scanner = nmap.PortScanner()
    detected_services = {}

    try:
        print(f"Scanning {ip} on ports {ports} for open services and versions...")
        # Scan ports and use the `--script banner` option to fetch service banners
        scanner.scan(ip, ports, arguments='-sV --script banner')

        for port in ports.split(','):
            port = int(port.strip())
            if port in scanner[ip]['tcp']:
                service_info = scanner[ip]['tcp'][port]
                service_name = service_info.get('name', 'unknown')
                service_version = service_info.get('version', 'unknown')
                if service_version == 'unknown':
                    # If version is not detected, try to get the product information
                    service_version = service_info.get('product', 'unknown')
                print(f"Port {port}: Detected service {service_name} {service_version}")
                detected_services[port] = (service_name, service_version)
            else:
                print(f"Port {port}: No service detected or port is closed.")
    except Exception as e:
        print(f"Error scanning target: {e}")

    return detected_services

def fetch_cves(service, version):
    """
    Fetch CVEs from the NVD API for a specific service and version.
    """
    if not service or not version:
        print("No service or version detected. Skipping CVE check.")
        return []

    api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    query = f"{service} {version}"
    params = {"keyword": query, "resultsPerPage": 10}
    cve_results = []

    print(f"Querying NVD for CVEs related to {service} {version}...")

    try:
        response = requests.get(api_url, params=params)
        if response.status_code != 200:
            print("Failed to fetch CVEs from NVD API.")
            return []

        cve_data = response.json()
        cve_items = cve_data.get("result", {}).get("CVE_Items", [])

        if not cve_items:
            print(f"No CVEs found for {service} {version}.")
        else:
            print(f"Found {len(cve_items)} CVEs for {service} {version}:")
            for cve in cve_items:
                cve_id = cve['cve']['CVE_data_meta']['ID']
                description = 
