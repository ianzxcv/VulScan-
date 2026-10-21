import ipaddress
import subprocess


def get_target_ip():
    while True:
        target = input("Enter the target IP address: ")

        try:
            target_ip = ipaddress.ip_address(target)
            return str(target_ip)

        except ValueError:
            print("Invalid IP address. Please try again.")


def main():

    def run_nmap_scan(target_ip):
        print("Nmap scan starting......")
        print("Started.")

        result = subprocess.run(
            ["nmap", "-sV", "-oX", "-", target_ip],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print(result.stdout)
        else:
            print("Nmap scan failed....")
            print(result.stderr)
    
    def check_target(target_ip):
        result = subprocess.run(
            ["ping", "-n", "1", target_ip],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("The target is reachable!")
        else:
            print("The target may n0t be reachable Or offline...")

    print("=" * 45)
    print("PROJECT DOOM - SECURITY SCANNER")
    print("=" * 45)

    print("Scanner initialized successfully!")
    print("Purpose: Identify issues and vulnerabilities.")
    print()

    target_ip = get_target_ip()
    print(f"Target IP accepted: {target_ip}")

    if target_ip == "192.168.56.102":
        print("This is the LAB IP address.")
    else:
        print("This IP address is not recognized.")

    check_target(target_ip)
    run_nmap_scan(target_ip)

if __name__ == "__main__":
    main()