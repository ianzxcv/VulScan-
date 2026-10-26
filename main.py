import ipaddress
import subprocess

from scanner import run_nmap_scan
from parser import extract_open_ports
from checks import check_open_ports
from ssh_connection import run_ssh_audit
from reporter import display_scan_results, display_ssh_settings, display_findings

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
        # Extract information on open ports
        open_ports = extract_open_ports(xml_data)

        if open_ports is not None:

            display_scan_results(open_ports)

            port_findings =check_open_ports(open_ports)
            
            display_findings(port_findings)
        
    else:
        print("Unable to retrieve scan results.")

    # Run SSH audit for the target
    if target_ip == "192.168.56.102" and xml_data is not None:
        ssh_is_open = any(
            port["port"] == "22"
            and port["protocol"] == "tcp"
            and port["service"] == "ssh"
            for port in open_ports
        )

        if ssh_is_open:
            print("\n")
            print("=" * 45)
            print("SSH CONFIGURATION AUDIT")
            print("=" * 45)

            try:
                ssh_settings, ssh_findings = run_ssh_audit(target_ip)

                display_ssh_settings(ssh_settings)

                display_findings(ssh_findings,"SSH SECURITY FINDINGS")

            except Exception as error:
                print("SSH audit failed.")
                print(error)
        else:
            print("SSH audit skipped: SSH service was not detected.")
    elif target_ip =="192.168.56.102":
        print("SSH audit skipped: Nmap could not complete the scan succcessfully.")


if __name__ == "__main__":
    main()
