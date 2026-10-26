
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

    return findings


if __name__ == "__main__":
    test_ports = [
        {
            "port": "23",
            "protocol": "tcp",
            "service": "telnet",
            "product": "unknown",
            "version": "unknown"
        },
        {
            "port": "22",
            "protocol": "tcp",
            "service": "ssh",
            "product": "OpenSSH",
            "version": "10.2"
        }
    ]
        
    findings = check_open_ports(test_ports)

    if findings:
        for finding in findings:
            print(finding)
    else:
            print("No security findings detected.")
