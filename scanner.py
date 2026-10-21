import subprocess

def run_nmap_scan(target_ip):
    print("Nmap is starting....")
    print("Nmap has started.")

    result = subprocess.run(
        ["nmap", "-sV", "-oX", "-", target_ip],
        capture_output=True,
        text=True

    )

    if result.returncode == 0:
        print("Nmap scan completed!")
        return result.stdout

    else:
        print("---Nmap scan has failed!---")
        print(result.stderr)
        return None