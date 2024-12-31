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
        # Scan ports using enhanced options for version detection and banner grabbing
        scanner.scan(ip, ports, arguments='-sV --script banner -Pn')

        for port in ports.split(','):
            port = int(port.strip())
            if port in scanner[ip]['tcp']:
                service_info = scanner[ip]['tcp'][port]
                service_name = service_info.get('name', 'unknown')
                service_version = service_info.get('version', 'unknown')
                product = service_info.get('product', 'unknown')

                # Fallback to product if version is unknown
                if service_version == 'unknown' and product != 'unknown':
                    service_version = product

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
                description = cve['cve']['description']['description_data'][0]['value']
                cve_results.append((cve_id, description))
                print(f" - {cve_id}: {description}")
    except Exception as e:
        print(f"Error querying CVEs: {e}")

    return cve_results

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Check for CVEs of specific services and versions running on a target IP and ports.")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("ports", help="Comma-separated list of target port numbers")
    args = parser.parse_args()

    target_ip = args.ip
    target_ports = args.ports

    # Scan the target for services and versions on specified ports
    detected_services = scan_target(target_ip, target_ports)

    # Fetch CVEs for each detected service and version
    for port, (service, version) in detected_services.items():
        print(f"\nChecking CVEs for service on port {port} ({service} {version})...")
        fetch_cves(service, version)

if __name__ == "__main__":
    main()
