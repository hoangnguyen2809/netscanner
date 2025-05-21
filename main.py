import socket
import argparse
import threading
import subprocess
import platform
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Event
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
                    sock.sendall(b"Hello\r\n")
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                except:
                    banner = "No banner"
                stats['open'] += 1
                open_ports.append(port)
                banners[port] = banner
            else:
                stats['closed'] += 1
        sock.close()
    except:
        pass  # suppress errors for clean output

def fingerprint_os(target_ip):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        proc = subprocess.run(["ping", param, "1", target_ip], capture_output=True, text=True, timeout=3)
        output = proc.stdout + proc.stderr
        ttl = None

        for line in output.splitlines():
            if "TTL=" in line.upper() or "ttl=" in line:
                ttl_str = [s for s in line.split() if "TTL" in s.upper()]
                if ttl_str:
                    ttl = int(''.join(filter(str.isdigit, ttl_str[0])))
                    break

        if ttl is None:
            return "Unknown"

        # Guess OS based on TTL (very rough)
        if ttl >= 128:
            return "Windows (TTL ~128)"
        elif ttl >= 64:
            return "Linux/Unix (TTL ~64)"
        elif ttl >= 255:
            return "Cisco/Network Device (TTL ~255)"
        else:
            return f"Unknown (TTL={ttl})"
    except Exception as e:
        return f"Unknown (Error: {e})"




def print_scanning_flag(stop_event):
    while not stop_event.is_set():
        print("Scanning...")
        time.sleep(1)

def parse_ports(port_str):
    if not port_str:
        return range(1, 65536)
    if '-' not in port_str:
        return [int(port_str)]
    start, end = port_str.split('-')
    return range(int(start), int(end) + 1)

def main():
    parser = argparse.ArgumentParser(description="Mini Nmap - TCP Connect Scanner")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--port", help="Single port (e.g., 22) or port range (e.g., 20-80). If omitted, scans all ports.")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads to use")
    parser.add_argument("--output", help="Write scan result to file")
    args = parser.parse_args()

    target = args.target
    ports = parse_ports(args.port)
    os_guess = fingerprint_os(target)
    print(f"[~] Scanning {target} on ports: {args.port if args.port else '1-65535'} with {args.threads} threads")

    stats = {"total": 0, "open": 0, "closed": 0}
    open_ports = []
    banners = {}

    # Start spinner AFTER the initial scan message
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=print_scanning_flag, args=(stop_event,))
    spinner_thread.start()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(scan_port, target, port, stats, open_ports, banners)
            for port in ports
        ]
        for _ in as_completed(futures):
            pass

    stop_event.set()
    spinner_thread.join()

    print(f"\n[~] Scan completed: {stats['total']} ports scanned.")
    print(f"\t[~] Opened ports: {stats['open']}")
    print(f"\t[~] Closed ports: {stats['closed']}")
    #print_open_port_info(open_ports, banners)

    output_lines = []
    output_lines.append(f"[+] Scan target: {target}")
    output_lines.append(f"[+] OS Fingerprint: {os_guess}")
    output_lines.append(f"[+] Total scanned ports: {stats['total']}")
    output_lines.append(f"[+] Open ports: {stats['open']}")
    output_lines.append(f"[+] Closed ports: {stats['closed']}")
    if open_ports:
        output_lines.append("\n[~] Open Ports and Services:")
        for port in open_ports:
            service = banners.get(port, "Unknown")
            output_lines.append(f"    - Port {port}: {service}")
    else:
        output_lines.append("\n[~] No open ports found.")

    # Print to screen
    print("\n" + "\n".join(output_lines))

    # Write to file if needed
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write("\n".join(output_lines))
            print(f"\n[+] Results written to: {args.output}")
        except Exception as e:
            print(f"[-] Failed to write output file: {e}")


if __name__ == "__main__":
    main()