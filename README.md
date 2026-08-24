# TCP Port Scanner with Vulnerability Suggestions

A simple educational TCP port scanner written in Python. It scans a target
for open ports, attempts to grab service banners, and suggests known
categories of risk/vulnerability associated with commonly found services.

## ⚠️ Ethical use

Only use this tool against hosts you have explicit permission to test —
your own machine/VM, a network you own, or public test targets like
`scanme.nmap.org`. Scanning third parties without authorization may be
illegal depending on your jurisdiction.

## Features

- Multi-threaded TCP connect scan (fast, using `ThreadPoolExecutor`)
- Service banner grabbing
- Port-to-service mapping and known vulnerability category suggestions
- Configurable target and port range via CLI arguments
- Graceful error handling for invalid input and network timeouts

## Requirements

- Python 3.8+ (standard library only, no external dependencies)

## Installation

1. Clone this repository (or download it as a ZIP from the green "Code" button on GitHub):
```bash
   git clone https://github.com/victorhugorfs/port-scanner-vuln-suggestions.git
```

2. Make sure both `scanner.py` and `vuln_db.py` are in the same folder — the scanner imports directly from `vuln_db.py`, so it won't run if they're separated.

3. Make sure you have Python 3.8+ installed (no external dependencies needed — standard library only).

4. Run it from inside that folder:
```bash
   python scanner.py <target> -p <port-range>
```

## Usage

```bash
python scanner.py <target>
python scanner.py <target> -p 1-1024
python scanner.py <target> -p 20-30
```

Example:

```bash
python scanner.py scanme.nmap.org -p 1-1024
```

## Project structure

- `scanner.py` — CLI, threaded scanning logic, banner grabbing, and report output.
- `vuln_db.py` — port-to-service mapping and known vulnerability suggestions.

## How it works

1. `argparse` reads the target and port range from the command line.
2. For each port in range, a thread attempts a TCP connection (`socket.connect_ex`).
3. If the port is open, the script attempts to read the service banner.
4. Port/service is cross-referenced against a local knowledge base of
   common risks (`vuln_db.py`).
5. Once all threads finish, results are sorted by port number and printed
   as a single organized report.

## Possible improvements (v2 ideas)

- Query a public vulnerability database (e.g. NVD API) using the detected
  service/version for real CVE lookups instead of a static list.
- Add UDP scanning support.
- Export results to JSON/HTML.
- Basic OS fingerprinting.

## About this project

This project was built as a hands-on learning exercise for my cybersecurity
portfolio. I worked through it step by step with the help of Claude (Anthropic),
which guided me through the concepts (sockets, threading, argparse, error
handling) while I wrote and debugged the code myself. It helped me get back
up to speed with Python after a while away from coding.
