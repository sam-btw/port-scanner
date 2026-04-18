# 🔍 Port Scanner

A fast, multithreaded TCP port scanner built with Python. Designed for network reconnaissance and security assessments on systems you own or have explicit permission to test.

---

## Features

- **Multithreaded scanning** — scans hundreds of ports in seconds
- **Banner grabbing** — attempts to identify services by reading their response
- **Flexible port input** — scan a range, a list, or common ports
- **Service detection** — maps ports to known service names
- **Clean output** — shows only open ports with service info

---

## Requirements

- Python 3.6+
- No external libraries needed (uses standard library only)

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/port-scanner.git
cd port-scanner
```

---

## Usage

```bash
# Scan common ports (default)
python scanner.py scanme.nmap.org

# Scan a port range
python scanner.py 192.168.1.1 -p 1-1000

# Scan specific ports
python scanner.py 10.0.0.1 -p 22,80,443,3306,8080

# Adjust threads and timeout
python scanner.py 192.168.1.1 -p 1-65535 -t 200 --timeout 0.5
```

### Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `target` | IP address or hostname | required |
| `-p` / `--ports` | Ports: `common`, `1-1000`, `80,443` | `common` |
| `-t` / `--threads` | Number of concurrent threads | `100` |
| `--timeout` | Connection timeout (seconds) | `1.0` |

---

## Example Output

```
=======================================================
  PORT SCANNER
=======================================================
  Target   : scanme.nmap.org (45.33.32.156)
  Ports    : 17 ports
  Threads  : 100
  Started  : 2025-01-01 14:32:01
=======================================================

  [OPEN]  Port 22     SSH            
  [OPEN]  Port 80     HTTP           

=======================================================
  SCAN COMPLETE
=======================================================
  Open ports : 2
  Time taken : 1.43 seconds

  OPEN PORTS SUMMARY:
    22/tcp  ->  SSH
    80/tcp  ->  HTTP
=======================================================
```

---

## Common Ports Scanned by Default

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 445 | SMB |
| 3306 | MySQL |
| 3389 | RDP |
| ... | and more |

---

## Legal Disclaimer

> This tool is intended for **educational purposes** and **authorized testing only**.  
> Scanning systems without permission is **illegal** and unethical.  
> Always get written permission before scanning any network or system.

---

## Author

**Sama Ismael Ahel**  
Engineering Student | Aspiring Cybersecurity Professional    
🔗 [www.linkedin.com/in/sama-ismael]

---

## License

MIT License — see [LICENSE](LICENSE) for details.
