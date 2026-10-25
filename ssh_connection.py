import paramiko 
import getpass
import json

from ssh_checks import check_ssh_settings

target_ip = "192.168.56.102"
username = 'user'

password = getpass.getpass("Enter your Ubuntu password: ")

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) #accepts unknown host key automatically

try:
    ssh.connect(
        hostname=target_ip,
        username=username,
        password=password,
        timeout=10,
        look_for_keys=False,
        allow_agent=False
    )

    print("SSH connection is successful..")

    stdin, stdout, stderr = ssh.exec_command("python3 ssh_audit.py")

    output = stdout.read().decode().strip()
    error_output = stderr.read().decode().strip()

    if error_output:
            print("\nREMOTE ERROR!")    
            print("=" * 40)
            print(error_output)

    if not output:
        raise RuntimeError("The SSH Audit returned no output")

    ssh_settings = json.loads(output)

    print("\nSSH Configuration")
    print("=" * 40)

    for setting, value in ssh_settings.items():
        print(f"{setting}:{value}")

    findings = check_ssh_settings(ssh_settings)

    print("\nSSH SECURITY FINDINGS")
    print("=" * 40)
    
    if findings: 
        for finding in findings:
            print("Finding:", finding["title"])
            print("Severity:", finding["severity"])
            print("Evidence", finding["evidence"])
            print("Recommendation:", finding["recommendation"])
            print("-" * 40)

    else:
         print("No Security Findings.")

except Exception as error:
    print("SSH connection failed.")
    print(error)

finally:
    ssh.close() #closes the connection