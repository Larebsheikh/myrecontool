# Custom Reconnaissance Tool

## Description
This Python CLI tool performs basic reconnaissance tasks on a target domain:
- WHOIS Lookup
- DNS Enumeration
- Subdomain Enumeration (API & brute-force)
- Port Scanning
- Banner Grabbing

## Usage
```bash
python recon_tool.py corvit.com --whois --dns --subdomains --ports --banner 80 --verbose --report report.txt
```

## Requirements
- Python 3.x
- Modules: `argparse`, `whois`, `dns.resolver`, `requests`

## Output
Generates a report with all gathered information in `report.txt`.

## Author
Generated as part of ITSOLERA Summer Internship Program 2025.
