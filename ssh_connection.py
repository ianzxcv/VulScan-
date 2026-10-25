import paramiko 
import getpass
import json

from ssh_checks import check_ssh_settings

def run_ssh_audit(target_ip,username="user"):
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

        stdin, stdout, stderr = ssh.exec_command(
            "python3 ssh_audit.py"
                )

        output = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()
        exit_code =stdout.channel.recv_exit_status()
        
        if exit_code != 0:
            raise RuntimeError(
                error_output or output or "Remote SSH audit failed."
            )
        
        ssh_settings = json.loads(output)

        findings = check_ssh_settings(ssh_settings)

        return ssh_settings, findings

    finally:
        ssh.close() #closes the connection