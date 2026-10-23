import ipaddress
import subprocess

from scanner import run_nmap_scan

from parser import extract_open_ports

from checks import check_open_ports


def get_target_ip():
    while True:
        target = input("Enter the target IP address: ")

        try:
            target_ip = ipaddress.ip_address(target)
            return str(target_ip)

        except ValueError:
            print("Invalid IP address. Please try again.")


def check_target(target_ip):
    result = subprocess.run(
        ["ping", "-n", "1", target_ip],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("The target is reachable!")
    else:
        print("The target may not be reachable or may be offline.")


def main():
    print("=" * 45)
    print("PROJECT DOOM - SECURITY SCANNER")
    print("=" * 45)

    print("Scanner initialized successfully!")
    print("Purpose: Identify issues and vulnerabilities.")
    print()

    # Get and validate the target IP address
    target_ip = get_target_ip()
    print(f"Target IP accepted: {target_ip}")

    # Identify whether the target is our lab machine
    if target_ip == "192.168.56.102":
        print("This is the LAB IP address.")
    else:
        print("This IP address is not recognized.")

    print()

    # Check whether the target responds to ping
    check_target(target_ip)

    # Run Nmap and receive its XML output
    xml_data = run_nmap_scan(target_ip)

    if xml_data is not None:
        # Extract information about open ports
        open_ports = extract_open_ports(xml_data)

        print("\n" + "=" * 45)
        print("RESULTS")
        print("=" * 45)

        if open_ports:
            for port in open_ports:
                print(f"Port: {port['port']}/{port['protocol']}")
                print(f"Service: {port['service']}")
                print(f"Product: {port['product']}")
                print(f"Version: {port['version']}")
                print("-" * 45)

                findings= check_open_ports(open_ports)

                print("\nSECURITY FINDINGS")   
                print("=" * 45)
                if findings:
                    for finding in findings:
                        print(f"Finding: {finding['title']}")
                        print(f"Severity: {finding['severity']}")
                        print(f"Evidence: {finding['evidence']}")
                        print(f"Recommendation: {finding['recommendation']}")
                        print("-" * 45)
                else:
                    print("No security findings detected.")
        else:
            print("No open ports found.")
    else:
        print("Unable to retrieve scan results.")


if __name__ == "__main__":
    main()
