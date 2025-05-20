import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

lock = Lock()

def scan_port(target_ip, port, stats, open_ports, banners):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))

        with lock:
            stats['total'] += 1
            if result == 0:
                try:
                    sock.sendall(b"Hello\r\n")  # Send generic probe
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                except:
                    banner = "No banner"
                
                print(f"[+] Port {port} is open — Banner: {banner}")
                stats['open'] += 1
                open_ports.append(port)
                banners[port] = banner
            else:
                print(f"[-] Port {port} is closed")
                stats['closed'] += 1
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

def print_open_port_info(open_ports, banners):
    print("\n[~] Open Ports Info:")
    for port in open_ports:
        try:
            service = socket.getservbyport(port, 'tcp')
        except:
            service = "Unknown service"
        banner = banners.get(port, "No banner")
        print(f"    - Port {port}: {service} | Banner: {banner}")


def main():
    parser = argparse.ArgumentParser(description="Mini Nmap - TCP Connect Scanner")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--port", help="Single port (e.g., 22) or port range (e.g., 20-80). If omitted, scans all ports.")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads to use (default: 100)")

    args = parser.parse_args()
    target = args.target
    ports = parse_ports(args.port)
    banners = {}

    print(f"[~] Scanning {target} on ports: {args.port if args.port else '1-65535'} with {args.threads} threads")

    stats = {'total': 0, 'open': 0, 'closed': 0}
    open_ports = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_port, target, port, stats, open_ports, banners)for port in ports]
        for _ in as_completed(futures):
            pass  # Just wait for all threads to finish

    print("\n[~] Scan Summary:")
    print(f"    Total ports scanned: {stats['total']}")
    print(f"    Open ports:          {stats['open']}")
    print(f"    Closed ports:        {stats['closed']}")

    if open_ports:
        print_open_port_info(open_ports, banners)
    else:
        print("[~] No open ports found.")

if __name__ == "__main__":
    main()
