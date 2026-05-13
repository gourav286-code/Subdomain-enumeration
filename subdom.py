#!/usr/bin/env python3
"""
Subdomain Enumeration Tool
Supports multiple methods: brute-force, DNS resolution, and optional API-based enumeration
"""

import dns.resolver
import dns.exception
import requests
import threading
import time
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from typing import List, Set, Optional
import json
from datetime import datetime

class SubdomainEnumerator:
    def __init__(self, domain: str, threads: int = 50, timeout: int = 5, verbose: bool = False):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.found_subdomains: Set[str] = set()
        self.lock = threading.Lock()
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
    def print_verbose(self, message: str):
        """Print verbose messages"""
        if self.verbose:
            print(f"[*] {message}")
    
    def resolve_subdomain(self, subdomain: str) -> Optional[str]:
        """Resolve subdomain to check if it exists"""
        full_domain = f"{subdomain}.{self.domain}"
        try:
            answers = self.resolver.resolve(full_domain, 'A')
            if answers:
                ips = [str(answer) for answer in answers]
                return full_domain, ips
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            pass
        except Exception as e:
            if self.verbose:
                self.print_verbose(f"Error resolving {full_domain}: {str(e)}")
        return None
    
    def brute_force_from_wordlist(self, wordlist_path: str) -> Set[str]:
        """Brute force subdomains from wordlist"""
        try:
            with open(wordlist_path, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Wordlist file not found: {wordlist_path}")
            return set()
        
        self.print_verbose(f"Loaded {len(subdomains)} subdomains to check")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.resolve_subdomain, sub): sub for sub in subdomains}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    full_domain, ips = result
                    with self.lock:
                        self.found_subdomains.add(full_domain)
                        ip_str = ', '.join(ips)
                        print(f"[+] Found: {full_domain} -> {ip_str}")
        
        return self.found_subdomains
    
    def dns_bruteforce(self, subdomains: List[str]) -> Set[str]:
        """Brute force from provided list of subdomains"""
        self.print_verbose(f"Checking {len(subdomains)} potential subdomains")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.resolve_subdomain, sub): sub for sub in subdomains}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    full_domain, ips = result
                    with self.lock:
                        self.found_subdomains.add(full_domain)
                        ip_str = ', '.join(ips)
                        print(f"[+] Found: {full_domain} -> {ip_str}")
        
        return self.found_subdomains
    
    def certificate_transparency_enum(self) -> Set[str]:
        """Enumerate subdomains using Certificate Transparency logs"""
        self.print_verbose("Enumerating from Certificate Transparency logs...")
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        
        try:
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        # Split multiple domains
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub.endswith(self.domain) and sub != self.domain:
                                subdomains.add(sub)
                
                with self.lock:
                    for sub in subdomains:
                        if sub not in self.found_subdomains:
                            self.found_subdomains.add(sub)
                            print(f"[+] (CT): {sub}")
                return subdomains
        except Exception as e:
            self.print_verbose(f"Certificate transparency enumeration failed: {str(e)}")
        
        return set()
    
    def dns_dumpster_enum(self, api_key: Optional[str] = None) -> Set[str]:
        """Enumerate using DNSDumpster API (requires API key)"""
        if not api_key:
            return set()
        
        self.print_verbose("Enumerating from DNSDumpster...")
        url = "https://api.dnsdumpster.com/domain"
        headers = {"X-API-Key": api_key}
        
        try:
            response = requests.post(url, data={"domain": self.domain}, 
                                    headers=headers, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                for entry in data.get('dns_records', {}).get('host', []):
                    sub = entry.get('domain', '').lower()
                    if sub and sub.endswith(self.domain):
                        subdomains.add(sub)
                
                with self.lock:
                    for sub in subdomains:
                        if sub not in self.found_subdomains:
                            self.found_subdomains.add(sub)
                            print(f"[+] (DNSDumpster): {sub}")
                return subdomains
        except Exception as e:
            self.print_verbose(f"DNSDumpster enumeration failed: {str(e)}")
        
        return set()
    
    def common_subdomains_scan(self) -> Set[str]:
        """Scan common subdomains without wordlist"""
        common = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'imap',
            'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns4', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
            'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'download', 'dns', 'piwik',
            'stats', 'dashboard', 'portal', 'manage', 'start', 'info', 'app', 'apps',
            'api', 'svn', 'stage', 'status', 'cloud', 'server', 'files', 'music', 'audio',
            'video', 'mssql', 'db', 'oracle', 'pp', 'members', 'proxy', 'ftp2', 'upload'
        ]
        return self.dns_bruteforce(common)
    
    def save_results(self, output_file: str, format: str = 'txt'):
        """Save enumeration results to file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if format == 'json':
            results = {
                "domain": self.domain,
                "timestamp": timestamp,
                "total_found": len(self.found_subdomains),
                "subdomains": sorted(list(self.found_subdomains))
            }
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
        else:  # txt format
            with open(output_file, 'w') as f:
                f.write(f"Subdomain Enumeration Results for {self.domain}\n")
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"Total found: {len(self.found_subdomains)}\n")
                f.write("-" * 50 + "\n")
                for sub in sorted(self.found_subdomains):
                    f.write(f"{sub}\n")
        
        print(f"[+] Results saved to {output_file}")
    
    def run_full_enumeration(self, wordlist: Optional[str] = None, 
                            use_ct: bool = True,
                            use_dnsdumpster: bool = False,
                            api_key: Optional[str] = None) -> Set[str]:
        """Run complete subdomain enumeration with all methods"""
        print(f"[*] Starting subdomain enumeration for: {self.domain}")
        print(f"[*] Threads: {self.threads}, Timeout: {self.timeout}s")
        print("-" * 60)
        
        start_time = time.time()
        
        # Method 1: Common subdomains
        print("\n[*] Method 1: Scanning common subdomains...")
        self.common_subdomains_scan()
        
        # Method 2: Wordlist brute force
        if wordlist:
            print(f"\n[*] Method 2: Brute forcing from wordlist: {wordlist}")
            self.brute_force_from_wordlist(wordlist)
        
        # Method 3: Certificate Transparency
        if use_ct:
            print("\n[*] Method 3: Certificate Transparency logs...")
            self.certificate_transparency_enum()
        
        # Method 4: DNSDumpster (optional)
        if use_dnsdumpster and api_key:
            print("\n[*] Method 4: DNSDumpster API...")
            self.dns_dumpster_enum(api_key)
        
        elapsed_time = time.time() - start_time
        print("-" * 60)
        print(f"[*] Enumeration completed in {elapsed_time:.2f} seconds")
        print(f"[*] Total unique subdomains found: {len(self.found_subdomains)}")
        
        return self.found_subdomains

def create_default_wordlist():
    """Create a default wordlist file if none exists"""
    default_wordlist = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "ns3", "m", "imap",
        "test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
        "ns4", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
        "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
        "wiki", "web", "media", "email", "images", "img", "download", "dns", "piwik",
        "stats", "dashboard", "portal", "manage", "start", "info", "app", "apps",
        "api", "svn", "stage", "status", "cloud", "server", "files", "music", "audio",
        "video", "mssql", "db", "oracle", "pp", "members", "proxy", "enterprise",
        "forum", "secure", "stage", "staging", "assets", "cdn", "auth", "login"
    ]
    
    with open("default_wordlist.txt", "w") as f:
        for sub in default_wordlist:
            f.write(f"{sub}\n")
    
    return "default_wordlist.txt"

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Subdomain Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subenum.py example.com
  python subenum.py example.com -w wordlist.txt -t 100 -o results.txt
  python subenum.py example.com --ct --dnsdumpster --api-key YOUR_KEY
  python subenum.py example.com --no-ct -v -o results.json -f json
        """
    )
    
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to subdomain wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-f", "--format", choices=['txt', 'json'], default='txt', help="Output format (default: txt)")
    parser.add_argument("--timeout", type=int, default=5, help="DNS timeout in seconds (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--no-ct", action="store_true", help="Disable Certificate Transparency enumeration")
    parser.add_argument("--dnsdumpster", action="store_true", help="Enable DNSDumpster API enumeration")
    parser.add_argument("--api-key", help="API key for DNSDumpster (required if --dnsdumpster is used)")
    parser.add_argument("--create-wordlist", action="store_true", help="Create a default wordlist file")
    
    args = parser.parse_args()
    
    # Create default wordlist if requested
    if args.create_wordlist:
        wordlist_file = create_default_wordlist()
        print(f"[+] Created default wordlist: {wordlist_file}")
        return
    
    # If no wordlist provided, create a temporary one
    wordlist = args.wordlist
    if not wordlist:
        wordlist = create_default_wordlist()
        print(f"[*] Using default wordlist: {wordlist}")
    
    # Check DNSDumpster requirements
    if args.dnsdumpster and not args.api_key:
        print("[!] Warning: DNSDumpster enumeration requires API key. Use --api-key to provide one.")
        args.dnsdumpster = False
    
    # Create enumerator
    enumerator = SubdomainEnumerator(
        domain=args.domain,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    try:
        # Run enumeration
        results = enumerator.run_full_enumeration(
            wordlist=wordlist,
            use_ct=not args.no_ct,
            use_dnsdumpster=args.dnsdumpster,
            api_key=args.api_key
        )
        
        # Save results if output file specified
        if args.output and results:
            enumerator.save_results(args.output, args.format)
        
        # Display summary
        if results:
            print("\n[*] Discovered subdomains:")
            for sub in sorted(results):
                print(f"  - {sub}")
    
    except KeyboardInterrupt:
        print("\n[!] Enumeration interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
