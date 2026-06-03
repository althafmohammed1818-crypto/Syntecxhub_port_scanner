# TCP Port Scanner

A multithreaded TCP port scanner written in Python for learning socket programming, concurrency, and network service discovery.

## Features

* Host Discovery (DNS Resolution)
* TCP Port Scanning
* Thread Pool Concurrency
* Service Detection
* Banner Grabbing
* Progress Tracking
* Scan Statistics
* Logging
* CSV Export
* Text Report Generation
* Exception Handling

## Requirements

* Python 3.x

## Installation

Clone the repository:

```bash
git clone https://github.com/althafmohammed1818-crypto/Syntecxhub_port_scanner.git
cd Syntecxhub_port_scanner
```

## Usage

Scan ports 1-1000 on localhost:

```bash
python3 scanner.py 127.0.0.1 1 1000
```

Scan a hostname:

```bash
python3 scanner.py scanme.nmap.org 1 1000
```

## Example Output

```text
Target     : 127.0.0.1
IP Address : 127.0.0.1
Port Range : 1-1000

Port 22    OPEN  Service=ssh
Port 80    OPEN  Service=http
Port 443   OPEN  Service=https

Statistics
-----------
Total Ports : 1000
Open Ports  : 3
Closed Ports: 997
Duration    : 2.45s
```

## Output Files

The scanner generates:

* `scan.log` – Scan activity log
* `results.csv` – CSV export of results
* `report.txt` – Scan report

## Technologies Used

* Python
* socket
* threading
* concurrent.futures
* logging
* csv

## Learning Objectives

This project demonstrates:

* Socket Programming
* Multithreading
* Network Service Enumeration
* File Handling
* Logging and Reporting
* Exception Handling

![Scanner Output](https://github.com/althafmohammed1818-crypto/Syntecxhub_port_scanner/blob/38654b3bba67233e5771116f562eaf9f5f9abcd5/screenshots/Screenshot_2026-06-03_10_55_05.png)

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Always obtain permission before scanning systems or networks.
