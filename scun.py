import subprocess
import re
import sys


def run_nmap(target):
    print(f"[+] Starte erweiterten Scan auf {target} ...\n")

    command = [
        "nmap",
        "-sS",      # TCP SYN Scan
        "-p-",      # alle Ports
        "-O",       # OS Erkennung
        "-T4",
        "-oN", "-", # normales Output-Format
        target
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout


def parse_output(output):
    hosts = {}
    current_ip = None

    for line in output.splitlines():

        # IP erkennen
        if line.startswith("Nmap scan report for"):
            current_ip = line.split()[-1]
            hosts[current_ip] = {
                "ports": [],
                "os": "Unbekannt"
            }

        # Offene Ports erkennen
        if "/tcp" in line and "open" in line:
            port = line.split("/")[0].strip()
            hosts[current_ip]["ports"].append(port)

        # OS erkennen
        if "OS details:" in line:
            os_info = line.split("OS details:")[1].strip()
            hosts[current_ip]["os"] = os_info

        if "Running:" in line and hosts[current_ip]["os"] == "Unbekannt":
            os_info = line.split("Running:")[1].strip()
            hosts[current_ip]["os"] = os_info

    return hosts


def main():
    if len(sys.argv) != 2:
        print("Usage: sudo python3 nmap_os_scan.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    output = run_nmap(target)
    hosts = parse_output(output)

    print("\n[+] Scan-Ergebnis:\n")

    if not hosts:
        print("Keine Hosts gefunden.")
    else:
        for ip, data in hosts.items():
            print(f"Host: {ip}")
            print(f"OS: {data['os']}")
            print(f"Offene Ports: {', '.join(data['ports']) if data['ports'] else 'Keine'}")
            print("-" * 40)


if __name__ == "__main__":
    main()
