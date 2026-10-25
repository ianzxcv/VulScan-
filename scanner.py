import subprocess

def run_nmap_scan(target_ip):
    print("Starting Nmap....")

    try:
        result = subprocess.run(
            ["nmap", "-sV", "-oX", "-", target_ip],
            capture_output=True,
            text=True,
            timeout=180
    )

    except FileNotFoundError:
        print("ERROR: Nmap does not exist.")
        print("Check if Nmap is installed and available.")
        return None

    except subprocess.TimeoutExpired:
        print("Error: The Nmap scan exceeded the time limit..")
        print("Try again or check the network connection of the target.")
        return None

    if result.returncode == 0:
        print("Nmap scan completed!")
        return result.stdout

    print("Error: Nmap has failed to complete the scan...")

    if result.stderr.strip():
        print(result.stderr.strip())

    return None