import socket
import argparse

def scan_port(target_ip, port, stats, open_ports):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            # print(f"[+] Port {port} is open")
            stats['open'] += 1
            open_ports.append(port)
        else:
            # print(f"[-] Port {port} is closed")
            stats['closed'] += 1
        stats['total'] += 1
        sock.close()
    except Exception as e:
        print(f"[-] Error on port {port}: {e}")

def parse_ports(port_str):
    if not port_str:
        return range(1, 65536)
    if '-' not in port_str:
        return [int(port_str)]
    start, end = port_str.split('-')
    return range(int(start), int(end) + 1)

def print_open_port_info(open_ports):
    print("\n[~] Open Ports Info:")
    for port in open_ports:
        try:
            service = socket.getservbyport(port, 'tcp')
        except:
            service = "Unknown service"
        print(f"    - Port {port}: {service}")

def main():
    parser = argparse.ArgumentParser(description="Mini Nmap - TCP Connect Scanner")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--port", help="Single port (e.g., 22) or port range (e.g., 20-80). If omitted, scans all ports.")

    args = parser.parse_args()
    target = args.target
    ports = parse_ports(args.port)

    print(f"[~] Scanning {target} on ports: {args.port if args.port else '1-65535'}")

    stats = {'total': 0, 'open': 0, 'closed': 0}
    open_ports = []

    for port in ports:
        scan_port(target, port, stats, open_ports)

    print("\n[~] Scan Summary:")
    print(f"    Total ports scanned: {stats['total']}")
    print(f"    Open ports:          {stats['open']}")
    print(f"    Closed ports:        {stats['closed']}")

    if open_ports:
        print_open_port_info(open_ports)
    else:
        print("[~] No open ports found.")

if __name__ == "__main__":
    main()
