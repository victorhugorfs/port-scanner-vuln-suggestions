import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from vuln_db import get_service_name, get_vuln_suggestions

parser = argparse.ArgumentParser(description="Simple TCP port scanner")
parser.add_argument("target", help="Target IP or hostname")
parser.add_argument("-p", "--ports", default="1-1024", help="Port range, e.g. 1-1024")
args = parser.parse_args()

target = args.target
ports_text = args.ports

try:
    start_str, end_str = ports_text.split("-")
    start_port = int(start_str)
    end_port = int(end_str)
except ValueError:
    print("Invalid port range. Please use the format 'start-end', e.g., '1-1024'.")
    sys.exit(1)


def grab_banner(sock):
    try:
        sock.settimeout(1.0)
        banner = sock.recv(1024)
        return banner.decode(errors="ignore").strip()
    except Exception:
        return ""


def scan_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    result_data = {
        "port": port,
        "open": False,
        "banner": "",
        "service": "",
        "suggestions": [],
    }

    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            result_data["open"] = True
            result_data["banner"] = grab_banner(sock)
            result_data["service"] = get_service_name(port)
            result_data["suggestions"] = get_vuln_suggestions(port)
    except socket.timeout:
        pass
    except Exception as e:
        print(f"Error occurred while scanning port {port}: {e}")
    finally:
        sock.close()

    return result_data


open_ports = []

with ThreadPoolExecutor(max_workers=100) as executor:
    all_results = executor.map(scan_port, range(start_port, end_port + 1))
    for result_data in all_results:
        if result_data["open"]:
            open_ports.append(result_data)

open_ports.sort(key=lambda r: r["port"])

print("\n" + "=" * 50)
print(f"Scan report for: {target}")
print(f"Open ports found: {len(open_ports)}")
print("=" * 50)

for result_data in open_ports:
    print(f"\nPort {result_data['port']} - {result_data['service']}")
    if result_data["banner"]:
        print(f"  Banner: {result_data['banner']}")
    else:
        print("  Banner: not retrieved")
    print("  Suggestions:")
    for suggestion in result_data["suggestions"]:
        print(f"    - {suggestion}")

print("\nPort scanning completed.")