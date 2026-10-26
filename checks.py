
def check_open_ports(open_ports):
    findings = []
    
    for port in open_ports:
        port_number = port.get("port")
        protocol = port.get("protocol", "unknown")
        service_name = port.get("service", "unknown")

        try:
             port_number = int(port_number)
        except(ValueError, TypeError):
             continue
        
        if port_number == 23 and protocol == "tcp":
            findings.append({
                "title": "Potential Telnet service detected",
                "severity": "High",
                "evidence": (
                    "TCP Port 23 is open. Detected service: "
                    + service_name
                ),
                "recommendation": (
                    "Verify whether Telnet is running "
                    "Disable Telnet if it is not required. "
                    "Use SSH for secure remote access."
                )
            })

        if port_number == 21 and protocol == "tcp":
            findings.append({
                    "title": "Potential unencrypted FTP exposure.",
                    "severity": "Medium",
                    "evidence": (
                    "TCP Port 21 is open. Detected service: "
                    + service_name
                 ),
                "recommendation": (
                    "Verify whether FTP is required. "
                    "Prefer SFTP or appropriately configured. "
                    "FTPS for secure file transfer."
                )
            })

        if port_number == 80 and protocol == "tcp" and service_name=="http":
            findings.append({
                    "title": "HTTP service detected",
                    "severity": "Low",
                    "evidence": (
                        "TCP Port 80 is open. Detected service: "
                        + service_name
                     ),
                    "recommendation": (
                        "Verify whether sensitive information is transmitted over HTTP. Use HTTPS where encryption is required. "
                    )
                })

    return findings


if __name__ == "__main__":
    test_ports = [
        {
            "port": "21",
            "protocol": "tcp",
            "service": "ftp",
            "product": "unknown",
            "version": "unknown"
        },

        {
            "port": "23",
            "protocol": "tcp",
            "service": "telnet",
            "product": "unknown",
            "version": "unknown"
                },

        {
            "port": "80",
            "protocol": "tcp",
            "service": "http",
            "product": "unknown",
            "version": "unknown"
        }
    ]
        
    findings = check_open_ports(test_ports)

    if findings:
        for finding in findings:
            print(finding)
    else:
            print("No security findings detected.")
