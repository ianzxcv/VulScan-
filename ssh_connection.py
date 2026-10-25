import paramiko 
import getpass
import json

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
   # print("Ubuntu Hostname:", hostname )

    if output:
        print("\nSSH AUDIT RESULTS")    
        print("=" * 40)
        print(output)

    if error_output:
            print("\nREMOTE ERROR!")    
            print("=" * 40)
            print(error_output)

except Exception as error:
    print("SSH connection failed.")
    print(error)

finally:
    ssh.close() #closes the connection