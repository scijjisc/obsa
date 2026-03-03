import subprocess
import re
import sys

def run_nmap(target):
    print(f"[+] Starte Scan auf {target} ...\n")

    # -sS = TCP SYN Scan
    # -p- = alle 65535 Ports
    # -T4 = schneller Scan
    # -oG - = Grepable Output auf stdout
    command = ["nmap", "-sS", "-p-", "-T4", "-oG", "-", target]

    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout


def parse_output(output):
    hosts = {}

    for line in output.splitlines():
        if "Ports:" in line:
            ip_match = re.search(r"Host:\s(\S+)", line)
            ports_match = re.search(r"Ports:\s(.+)", line)

            if ip_match and ports_match:
                ip = ip_match.group(1)
                ports_data = ports_match.group(1)

                open_ports = []
                for port_entry in ports_data.split(","):
                    if "/open/" in port_entry:
                        port = port_entry.split("/")[0]
                        open_ports.append(port)

                hosts[ip] = open_ports

    return hosts


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 nmap_scan.py <target>")
        print("Beispiel: python3 nmap_scan.py 192.168.56.101")
        sys.exit(1)

    target = sys.argv[1]
    output = run_nmap(target)
    hosts = parse_output(output)

    print("\n[+] Scan-Ergebnis:\n")

    if not hosts:
        print("Keine offenen Ports gefunden.")
    else:
        for ip, ports in hosts.items():
            print(f"Host: {ip}")
            print(f"Offene Ports: {', '.join(ports)}\n")


if __name__ == "__main__":
    main()
