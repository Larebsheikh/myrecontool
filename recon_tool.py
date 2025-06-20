import argparse
import socket
import whois
import dns.resolver
import requests
from datetime import datetime

# Logger
def log(msg, verbose):
    if verbose:
        print(f"[+] {msg}")

# WHOIS Lookup
def whois_lookup(domain, verbose):
    log(f"Performing WHOIS lookup for {domain}", verbose)
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

# DNS Enumeration
def dns_enum(domain, verbose):
    records = ['A', 'MX', 'TXT', 'NS']
    result = ""
    for record in records:
        try:
            answers = dns.resolver.resolve(domain, record)
            log(f"{record} Records:", verbose)
            result += f"\n{record} Records:\n"
            for rdata in answers:
                result += str(rdata) + "\n"
        except Exception as e:
            result += f"{record} lookup failed: {e}\n"
    return result

# Enhanced Subdomain Enumeration (crt.sh + hackertarget + brute-force)
def subdomain_enum(domain, verbose):
    log(f"[*] Enumerating subdomains for {domain}", verbose)
    subdomains = set()

    # --- 1. crt.sh
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        for entry in r.json():
            for sub in entry.get("name_value", "").split('\n'):
                if domain in sub:
                    subdomains.add(sub.strip())
        log(f"[crt.sh] Found {len(subdomains)} entries", verbose)
    except Exception as e:
        log(f"[!] crt.sh failed: {e}", verbose)

    # --- 2. hackertarget.com
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        if "API count exceeded" not in r.text:
            lines = r.text.splitlines()
            for line in lines:
                parts = line.split(",")
                if len(parts) > 0:
                    subdomains.add(parts[0].strip())
            log(f"[HackerTarget] Found {len(lines)} entries", verbose)
        else:
            log("[!] HackerTarget API rate limit hit", verbose)
    except Exception as e:
        log(f"[!] HackerTarget failed: {e}", verbose)

    # --- 3. Brute-force subdomain guessing
    brute_list = ["www", "mail", "ftp", "test", "dev", "api", "blog", "vpn", "ns1", "ns2"]
    found = 0
    for word in brute_list:
        sub = f"{word}.{domain}"
        try:
            socket.gethostbyname(sub)
            subdomains.add(sub)
            found += 1
        except:
            continue
    log(f"[Brute-force] Found {found} valid subdomains", verbose)

    return "\n".join(sorted(subdomains)) if subdomains else "No subdomains found."

# Port Scanner
def port_scan(domain, ports, verbose):
    try:
        ip = socket.gethostbyname(domain)
        log(f"Scanning ports on {ip}", verbose)
    except Exception as e:
        return f"Port scanning failed: {e}"

    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception:
            continue
    return "Open ports: " + ", ".join(map(str, open_ports)) if open_ports else "No open ports found."

# Banner Grabbing
def banner_grab(domain, port, verbose):
    try:
        log(f"Grabbing banner from {domain}:{port}", verbose)
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((domain, port))
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(1024)
            return banner.decode(errors='ignore')
    except Exception as e:
        return f"Banner grab failed: {e}"

# Report Generator
def generate_report(filename, content):
    with open(filename, "w") as f:
        f.write(f"Recon Report - {datetime.now()}\n")
        f.write("="*60 + "\n\n")
        f.write(content)
    print(f"[✔] Report saved to {filename}")

# Main CLI Entry
def main():
    parser = argparse.ArgumentParser(description="Custom Reconnaissance Tool")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Find subdomains via APIs & brute-force")
    parser.add_argument("--ports", action="store_true", help="Scan common ports")
    parser.add_argument("--banner", type=int, help="Grab banner from a specific port")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--report", default="report.txt", help="Save results to file")

    args = parser.parse_args()
    output = ""

    if args.whois:
        output += "\n=== WHOIS Lookup ===\n"
        output += whois_lookup(args.domain, args.verbose) + "\n"

    if args.dns:
        output += "\n=== DNS Enumeration ===\n"
        output += dns_enum(args.domain, args.verbose) + "\n"

    if args.subdomains:
        output += "\n=== Subdomain Enumeration ===\n"
        output += subdomain_enum(args.domain, args.verbose) + "\n"

    if args.ports:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]
        output += "\n=== Port Scan ===\n"
        output += port_scan(args.domain, common_ports, args.verbose) + "\n"

    if args.banner:
        output += f"\n=== Banner Grabbing on Port {args.banner} ===\n"
        output += banner_grab(args.domain, args.banner, args.verbose) + "\n"

    if output:
        generate_report(args.report, output)
    else:
        print("No modules selected. Use --help for options.")

if __name__ == "__main__":
    main()
