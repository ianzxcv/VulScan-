
def check_open_ports(open_ports):
    findings = []

    for port in open_ports:
        port_number = int(port["port"])
        service_name = port["service"]

        if port_number == 23:
            findings.append({
                "title": "Telnet service detected",
                "severity": "High",
                "evidence": (
                    "Port 23 is open and the detected service is "
                    + service_name
                ),
                "recommendation": (
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
        }
    ]

    findings = check_open_ports(test_ports)

    if findings:
        for finding in findings:
            print(finding)
    else:
            print("No security findings detected.")
