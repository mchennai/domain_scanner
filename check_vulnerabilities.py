import nmap
import requests
import argparse

def scan_target(ip, port):
    """
    Use nmap to scan the IP address and port to detect running service and version.
    """
    scanner = nmap.PortScanner()

    try:
        print(f"Scanning {ip}:{port} for open ports and service versions...")
        scanner.scan(ip, str(port), arguments='-sV')  # Service version detection

        if port in scanner[ip]['tcp']:
            service_info = scanner[ip]['tcp'][port]
            service_name = service_info.get('name', 'unknown')
            service_version = service_info.get('version', 'unknown')
            print(f"Detected service: {service_name} {service_version}")
            return service_name, service_version
        else:
            print(f"No service detected on {ip}:{port}")
            return None, None
    except Exception as e:
        print(f"Error scanning target: {e}")
        return None, None

def fetch_cves(service, version):
    """
    Fetch CVEs from the NVD API for a specific service and version.
    """
    if not service or not version:
        print("No service or version detected. Skipping CVE check.")
        return

    api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    query = f"{service} {version}"
    params = {"keyword": query, "resultsPerPage": 10}

    print(f"Querying NVD for CVEs related to {service} {version}...")

    try:
        response = requests.get(api_url, params=params)
        if response.status_code != 200:
            print("Failed to fetch CVEs from NVD API.")
            return

        cve_data = response.json()
        cve_items = cve_data.get("result", {}).get("CVE_Items", [])

        if not cve_items:
            print(f"No CVEs found for {service} {version}.")
        else:
            print(f"Found {len(cve_items)} CVEs for {service} {version}:")
            for cve in cve_items:
                cve_id = cve['cve']['CVE_data_meta']['ID']
                description = cve['cve']['description']['description_data'][0]['value']
                print(f" - {cve_id}: {description}")
    except Exception as e:
        print(f"Error querying CVEs: {e}")

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Check for CVEs of a specific service and version running on a target IP and port.")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("port", type=int, help="Target port number")
    args = parser.parse_args()

    target_ip = args.ip
    target_port = args.port

    # Scan the target for service and version
    service, version = scan_target(target_ip, target_port)

    # Fetch CVEs for the detected service and version
    fetch_cves(service, version)

if __name__ == "__main__":
    main()
