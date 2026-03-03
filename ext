import subprocess
import xml.etree.ElementTree as ET
import json
import sys


def run_nmap(target):
    print(f"[+] Starte Service-Scan auf {target} ...")

    command = [
        "nmap",
        "-sV",          # Service + Version
        "-p-",          # alle Ports
        "-oX", "-",     # XML Output an stdout
        target
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout


def parse_xml(xml_data):
    root = ET.fromstring(xml_data)
    results = {}

    for host in root.findall("host"):
        address = host.find("address").get("addr")
        results[address] = {"ports": []}

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            state = port.find("state").get("state")
            if state == "open":
                port_id = port.get("portid")
                protocol = port.get("protocol")

                service = port.find("service")
                service_name = service.get("name") if service is not None else "unknown"
                product = service.get("product") if service is not None else ""
                version = service.get("version") if service is not None else ""

                results[address]["ports"].append({
                    "port": int(port_id),
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version
                })

    return results


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 port_service_scan.py <target>")
        sys.exit(1)

    target = sys.argv[1]

    xml_output = run_nmap(target)
    parsed_data = parse_xml(xml_output)

    filename = "scan_result.json"

    with open(filename, "w") as f:
        json.dump(parsed_data, f, indent=4)

    print(f"[+] Scan abgeschlossen. Ergebnisse gespeichert in {filename}")


if __name__ == "__main__":
    main()
