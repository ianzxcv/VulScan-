def display_scan_results(open_ports):
    print("\n" + "=" * 45)
    print("SCAN RESULTS")
    print("=" * 45)

    if open_ports:
        for port in open_ports:
            print(f"Port: {port['port']}/{port['protocol']}")
            print(f"Service: {port['service']}")
            print(f"Product: {port['product']}")
            print(f"Version: {port['version']}")
            print("-" * 45)
    else:
        print("No open ports found.")


def display_ssh_settings(ssh_settings):
    print("\n" + "=" * 45)
    print("SSH CONFIGURATION")
    print("=" * 45)

    for setting, value in ssh_settings.items():
        print(f"{setting}: {value}")


def display_findings(findings, section_title="SECURITY FINDINGS"):
    print("\n" + "=" * 45)
    print(section_title)
    print("=" * 45)

    if findings:
        for finding in findings:
            print(f"Finding: {finding['title']}")
            print(f"Severity: {finding['severity']}")
            print(f"Evidence: {finding['evidence']}")
            print(f"Recommendation: {finding['recommendation']}")
            print("-" * 45)
    else:
        print("No security findings detected.")
