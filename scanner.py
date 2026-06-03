import socket
import csv
import logging
import time
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import argparse

# ---------------------------
# Configuration
# ---------------------------

logging.basicConfig(
    filename="scan.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# ---------------------------
# Global Variables
# ---------------------------

results = []
results_lock = threading.Lock()

completed = 0
completed_lock = threading.Lock()

open_count = 0
closed_count = 0

# ---------------------------
# Host Discovery
# ---------------------------

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

# ---------------------------
# Banner Grabber
# ---------------------------

def grab_banner(sock):
    try:
        sock.settimeout(1)
        sock.send(b"\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()

        if banner:
            return banner

    except:
        pass

    return "No Banner"

# ---------------------------
# Port Scanner
# ---------------------------

def scan_port(target_ip, port, timeout, total_ports):
    global completed
    global open_count
    global closed_count

    status = "CLOSED"
    service = "Unknown"
    banner = ""

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((target_ip, port))

        if result == 0:
            status = "OPEN"

            try:
                service = socket.getservbyport(port, "tcp")
            except:
                service = "Unknown"

            banner = grab_banner(sock)

            with results_lock:
                open_count += 1

        else:
            with results_lock:
                closed_count += 1

        sock.close()

    except socket.timeout:
        status = "TIMEOUT"

    except Exception as e:
        status = f"ERROR: {e}"

    with results_lock:
        results.append(
            {
                "port": port,
                "status": status,
                "service": service,
                "banner": banner
            }
        )

    logging.info(
        f"Port={port} Status={status} Service={service}"
    )

    with completed_lock:
        completed += 1
        print(
            f"\rProgress: {completed}/{total_ports}",
            end="",
            flush=True
        )

# ---------------------------
# CSV Export
# ---------------------------

def export_csv():
    with open("results.csv", "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow(
            ["Port", "Status", "Service", "Banner"]
        )

        for entry in sorted(results, key=lambda x: x["port"]):
            writer.writerow(
                [
                    entry["port"],
                    entry["status"],
                    entry["service"],
                    entry["banner"]
                ]
            )

# ---------------------------
# Report Generation
# ---------------------------

def generate_report(
    target,
    target_ip,
    duration,
    start_port,
    end_port
):
    with open("report.txt", "w") as report:

        report.write("TCP PORT SCAN REPORT\n")
        report.write("=" * 50 + "\n")

        report.write(f"Target: {target}\n")
        report.write(f"IP: {target_ip}\n")
        report.write(f"Port Range: {start_port}-{end_port}\n")
        report.write(
            f"Generated: {datetime.now()}\n"
        )

        report.write(
            f"\nDuration: {duration:.2f} seconds\n"
        )

        report.write(
            f"Open Ports: {open_count}\n"
        )

        report.write(
            f"Closed Ports: {closed_count}\n"
        )

        report.write("\nOPEN PORTS\n")
        report.write("-" * 50 + "\n")

        for entry in sorted(
            results,
            key=lambda x: x["port"]
        ):
            if entry["status"] == "OPEN":

                report.write(
                    f"{entry['port']}/tcp "
                    f"{entry['service']} "
                    f"{entry['banner']}\n"
                )

# ---------------------------
# Main
# ---------------------------

def main():

    parser = argparse.ArgumentParser(
        description="Threaded TCP Port Scanner"
    )

    parser.add_argument(
        "target",
        help="Target hostname or IP"
    )

    parser.add_argument(
        "start_port",
        type=int
    )

    parser.add_argument(
        "end_port",
        type=int
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1,
        help="Timeout (default: 1)"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Thread count (default: 100)"
    )

    args = parser.parse_args()

    if (
        args.start_port < 1
        or args.end_port > 65535
        or args.start_port > args.end_port
    ):
        print("Invalid port range.")
        return

    target_ip = resolve_target(args.target)

    if not target_ip:
        print("Unable to resolve target.")
        return

    total_ports = (
        args.end_port
        - args.start_port
        + 1
    )

    print("=" * 60)
    print("TCP PORT SCANNER")
    print("=" * 60)

    print(f"Target     : {args.target}")
    print(f"IP Address : {target_ip}")
    print(
        f"Port Range : {args.start_port}-{args.end_port}"
    )
    print(
        f"Threads    : {args.threads}"
    )

    start_time = time.time()

    with ThreadPoolExecutor(
        max_workers=args.threads
    ) as executor:

        for port in range(
            args.start_port,
            args.end_port + 1
        ):

            executor.submit(
                scan_port,
                target_ip,
                port,
                args.timeout,
                total_ports
            )

    end_time = time.time()

    duration = end_time - start_time

    print("\n\n")

    print("=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)

    for entry in sorted(
        results,
        key=lambda x: x["port"]
    ):
        if entry["status"] == "OPEN":

            print(
                f"Port {entry['port']:<5} "
                f"OPEN "
                f"Service={entry['service']}"
            )

            if entry["banner"] != "No Banner":
                print(
                    f"   Banner: "
                    f"{entry['banner']}"
                )

    print("\nStatistics")
    print("-" * 20)

    print(f"Total Ports : {total_ports}")
    print(f"Open Ports  : {open_count}")
    print(f"Closed Ports: {closed_count}")
    print(
        f"Duration    : {duration:.2f}s"
    )

    export_csv()

    generate_report(
        args.target,
        target_ip,
        duration,
        args.start_port,
        args.end_port
    )

    print("\nFiles Generated:")
    print(" - scan.log")
    print(" - results.csv")
    print(" - report.txt")


if __name__ == "__main__":
    main()
