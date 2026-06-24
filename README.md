# PyRecon

A multi-threaded TCP port scanner built from scratch in Python — no nmap, no shortcuts.
Performs TCP connect scanning, banner grabbing, service fingerprinting, and outputs formatted reports.

## Features

- Raw TCP connect scanning via Python sockets
- Multi-threaded engine using `ThreadPoolExecutor` — 100x faster than sequential
- Banner grabbing with probe support for HTTP, SSH, FTP, SMTP and more
- Service fingerprinting against 40+ known software signatures
- Colored terminal output
- Report export to `.txt`

## Usage

```bash
# Basic scan
python pyrecon.py -t scanme.nmap.org -p 1-1024

# Save report to file
python pyrecon.py -t scanme.nmap.org -p 1-1024 --output report.txt

# Full port range with high thread count
python pyrecon.py -t 192.168.1.1 -p 1-65535 --threads 300 --output full.txt

# Specific ports
python pyrecon.py -t 10.0.0.1 -p 22,80,443

# Sequential mode (debug)
python pyrecon.py -t scanme.nmap.org -p 1-100 --no-threads
```

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-t`, `--target` | Target hostname or IP | required |
| `-p`, `--ports` | Port range, list, or single port | required |
| `--threads` | Concurrent threads | 100 |
| `--timeout` | Per-port timeout (seconds) | 1.0 |
| `--output` | Save report to file | None |
| `--no-threads` | Sequential scan mode | False |

## Installation

```bash
git clone https://github.com/mzuhairkhan3/PyRecon.git
cd PyRecon
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Project Structure

pyrecon/

├── pyrecon.py          # CLI entry point

├── scanner/

│   ├── tcp.py          # Socket logic and threading engine

│   ├── fingerprint.py  # Service map and banner signatures

│   └── report.py       # Report builder and file output

└── requirements.txt


## Legal

Only use against systems you own or have explicit permission to scan.
Unauthorized port scanning may be illegal in your jurisdiction.

## Skills Demonstrated

TCP/IP networking · Python sockets · Concurrent programming ·
Banner grabbing · Service fingerprinting · CLI design · Threat reporting