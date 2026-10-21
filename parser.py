import xml.etree.ElementTree as ET

def extract_open_ports(xml_data):
    root = ET.fromstring(xml_data)

    open_ports = []

    for port in root.findall(".//port"):
        state = port.find("state")

        if state is not None and state.get("state") == "open":
            service = port.find("service")

            port_info = {
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "service": "unknown",
                "product": "unknown",
                "version": "unknown"
            }

            if service is not None:
                port_info["service"] = service.get("name", "unknown")
                port_info["product"] = service.get("product", "unknown")
                port_info["version"] = service.get("version", "unknown")

            open_ports.append(port_info)

    return open_ports