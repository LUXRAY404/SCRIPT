#!/usr/bin/env python3
"""
Advanced Reconnaissance Automation Script
Version: 4.0
Author: Security Automation Team
Python Edition with Enhanced Features
"""

import argparse
import asyncio
import json
import logging
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Set, Optional, Dict
from urllib.parse import urlparse
import shutil

try:
    import aiohttp
    import requests
except ImportError:
    print("[!] Missing required packages. Install with:")
    print("    pip install aiohttp requests")
    sys.exit(1)


# ============================================
# Constants and Configuration
# ============================================
SCRIPT_VERSION = "4.0"
DEFAULT_THREADS = 50
DNS_RESOLUTION_THREADS = 100
TOOL_TIMEOUT = 180
CURL_TIMEOUT = 30
MAX_RETRIES = 3


# ============================================
# Color Constants
# ============================================
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    BOLD = '\033[1m'
    NC = '\033[0m'
    HR = "=" * 60


# ============================================
# Data Classes
# ============================================
@dataclass
class ReconConfig:
    """Configuration for reconnaissance scan"""
    target_domain: Optional[str] = None
    scope_file: Optional[Path] = None
    out_scope_domains: List[str] = field(default_factory=list)
    out_scope_file: Optional[Path] = None
    threads: int = DEFAULT_THREADS
    debug_mode: bool = False
    http_probe: bool = True
    check_takeovers: bool = True
    keep_temp: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"))
    
    def __post_init__(self):
        """Validate configuration after initialization"""
        if self.scope_file and not self.scope_file.exists():
            raise FileNotFoundError(f"Scope file not found: {self.scope_file}")
        if self.out_scope_file and not self.out_scope_file.exists():
            raise FileNotFoundError(f"Out-of-scope file not found: {self.out_scope_file}")


@dataclass
class ScanResults:
    """Container for scan results"""
    targets: Set[str] = field(default_factory=set)
    raw_subdomains: Set[str] = field(default_factory=set)
    filtered_subdomains: Set[str] = field(default_factory=set)
    resolved_subdomains: Set[str] = field(default_factory=set)
    excluded_subdomains: Set[str] = field(default_factory=set)
    http_services: List[Dict] = field(default_factory=list)
    takeovers: List[str] = field(default_factory=list)


# ============================================
# Logging Setup
# ============================================
class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors"""
    
    FORMATS = {
        logging.DEBUG: f"{Colors.MAGENTA}[D] %(asctime)s - %(message)s{Colors.NC}",
        logging.INFO: f"{Colors.BLUE}[*] %(asctime)s - %(message)s{Colors.NC}",
        logging.WARNING: f"{Colors.YELLOW}[!] %(asctime)s - %(message)s{Colors.NC}",
        logging.ERROR: f"{Colors.RED}[-] %(asctime)s - %(message)s{Colors.NC}",
        logging.CRITICAL: f"{Colors.RED}{Colors.BOLD}[!!] %(asctime)s - %(message)s{Colors.NC}",
    }
    
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%H:%M:%S')
        return formatter.format(record)


def setup_logging(working_dir: Path, debug: bool = False) -> logging.Logger:
    """Setup logging with file and console handlers"""
    logger = logging.getLogger('recon')
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    
    # File handler
    fh = logging.FileHandler(working_dir / 'recon.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    
    # Console handler with colors
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if debug else logging.INFO)
    ch.setFormatter(ColoredFormatter())
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    
    return logger


# ============================================
# Utility Functions
# ============================================
def print_banner():
    """Print script banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════╗
║    Advanced Recon Automation v{SCRIPT_VERSION}            ║
║        Professional Python Edition                   ║
╚══════════════════════════════════════════════════════╝
{Colors.NC}
"""
    print(banner)


def check_dependencies(logger: logging.Logger) -> bool:
    """Check if required tools are installed"""
    required_tools = ['subfinder', 'assetfinder', 'dnsx', 'anew']
    recommended_tools = ['subdominator', 'certhunt', 'subjack', 'nuclei', 'httpx']
    
    missing_required = []
    missing_recommended = []
    
    logger.info("Checking dependencies...")
    
    for tool in required_tools:
        if not shutil.which(tool):
            missing_required.append(tool)
    
    for tool in recommended_tools:
        if not shutil.which(tool):
            missing_recommended.append(tool)
    
    if missing_required:
        logger.error(f"Missing required tools: {', '.join(missing_required)}")
        logger.info("Install with: go install -v github.com/<tool>@latest")
        return False
    
    logger.info(f"{Colors.GREEN}✓ Required dependencies available{Colors.NC}")
    
    if missing_recommended:
        logger.warning(f"Missing recommended tools: {', '.join(missing_recommended)}")
    
    return True


def run_command(cmd: List[str], timeout: int = TOOL_TIMEOUT, logger: Optional[logging.Logger] = None) -> Optional[str]:
    """Run a command with timeout and error handling"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            if logger and result.stderr:
                logger.debug(f"Command failed: {' '.join(cmd)}: {result.stderr[:200]}")
            return None
            
    except subprocess.TimeoutExpired:
        if logger:
            logger.debug(f"Command timed out: {cmd[0]}")
        return None
    except Exception as e:
        if logger:
            logger.debug(f"Command error: {cmd[0]}: {str(e)}")
        return None


def clean_domain(domain: str) -> str:
    """Clean and normalize domain name"""
    domain = domain.strip()
    # Remove wildcard prefix
    if domain.startswith('*.'):
        domain = domain[2:]
    # Remove protocol
    domain = re.sub(r'^https?://', '', domain)
    # Remove path
    domain = domain.split('/')[0]
    # Remove port
    domain = domain.split(':')[0]
    # Remove www
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain.lower()


def is_subdomain_of(subdomain: str, domain: str) -> bool:
    """Check if subdomain belongs to domain"""
    subdomain = subdomain.lower()
    domain = domain.lower()
    
    if subdomain == domain:
        return True
    
    return subdomain.endswith('.' + domain)


def matches_wildcard(subdomain: str, pattern: str) -> bool:
    """Check if subdomain matches wildcard pattern"""
    # Convert wildcard pattern to regex
    regex_pattern = pattern.replace('.', r'\.')
    regex_pattern = regex_pattern.replace('*', '.*')
    regex_pattern = f'^{regex_pattern}$'
    
    return bool(re.match(regex_pattern, subdomain, re.IGNORECASE))


# ============================================
# Target and Exclusion Preparation
# ============================================
class TargetManager:
    """Manage targets and exclusions"""
    
    def __init__(self, config: ReconConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.targets: Set[str] = set()
        self.exclusions: Set[str] = set()
        self.wildcard_exclusions: List[str] = []
    
    def prepare_targets(self) -> Set[str]:
        """Prepare and validate target domains"""
        self.logger.info("Preparing target list...")
        
        # Add single domain
        if self.config.target_domain:
            clean = clean_domain(self.config.target_domain)
            self.targets.add(clean)
            self.logger.debug(f"Added domain: {clean}")
        
        # Add from scope file
        if self.config.scope_file:
            with open(self.config.scope_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        clean = clean_domain(line)
                        self.targets.add(clean)
        
        if not self.targets:
            raise ValueError("No valid targets to scan")
        
        self.logger.info(f"{Colors.GREEN}✓ Prepared {len(self.targets)} unique targets{Colors.NC}")
        
        if self.config.debug_mode:
            self.logger.debug("Targets to scan:")
            for target in sorted(self.targets):
                self.logger.debug(f"  - {target}")
        
        return self.targets
    
    def prepare_exclusions(self):
        """Prepare exclusion patterns"""
        self.logger.info("Preparing exclusion list...")
        
        # Add from command line
        for domain in self.config.out_scope_domains:
            domain = domain.strip()
            if '*' in domain:
                self.wildcard_exclusions.append(domain)
            else:
                self.exclusions.add(clean_domain(domain))
        
        # Add from file
        if self.config.out_scope_file:
            with open(self.config.out_scope_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '*' in line:
                            self.wildcard_exclusions.append(line)
                        else:
                            self.exclusions.add(clean_domain(line))
        
        total_exclusions = len(self.exclusions) + len(self.wildcard_exclusions)
        
        if total_exclusions > 0:
            self.logger.info(f"{Colors.GREEN}✓ Prepared {total_exclusions} exclusion rules{Colors.NC}")
            self.logger.debug(f"  Exact: {len(self.exclusions)}, Wildcards: {len(self.wildcard_exclusions)}")
        else:
            self.logger.info("No exclusions specified")
    
    def is_excluded(self, subdomain: str) -> bool:
        """Check if subdomain should be excluded"""
        subdomain = subdomain.lower()
        
        # Check exact matches
        if subdomain in self.exclusions:
            return True
        
        # Check wildcard patterns
        for pattern in self.wildcard_exclusions:
            if matches_wildcard(subdomain, pattern):
                return True
        
        return False


# ============================================
# Subdomain Enumeration
# ============================================
class SubdomainEnumerator:
    """Enumerate subdomains using multiple sources"""
    
    def __init__(self, logger: logging.Logger, threads: int = DEFAULT_THREADS):
        self.logger = logger
        self.threads = threads
    
    def enumerate_passive(self, domain: str) -> Set[str]:
        """Run passive enumeration tools"""
        results = set()
        
        self.logger.debug(f"Starting passive enumeration for: {domain}")
        
        # Subfinder
        output = run_command(
            ['subfinder', '-d', domain, '-all', '-recursive', '-silent'],
            logger=self.logger
        )
        if output:
            subs = set(line.strip() for line in output.split('\n') if line.strip())
            results.update(subs)
            self.logger.debug(f"Subfinder found {len(subs)} subdomains")
        
        # Assetfinder
        output = run_command(
            ['assetfinder', '--subs-only', domain],
            logger=self.logger
        )
        if output:
            subs = set(line.strip() for line in output.split('\n') if line.strip())
            results.update(subs)
            self.logger.debug(f"Assetfinder found {len(subs)} subdomains")
        
        # Subdominator (if available)
        if shutil.which('subdominator'):
            output = run_command(
                ['subdominator', '-d', domain, '-all', '-s'],
                logger=self.logger
            )
            if output:
                subs = set(line.strip() for line in output.split('\n') if line.strip())
                results.update(subs)
                self.logger.debug(f"Subdominator found {len(subs)} subdomains")
        
        return results
    
    def enumerate_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh for subdomains"""
        results = set()
        
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(url, timeout=CURL_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip().replace('*.', '')
                        if subdomain:
                            results.add(subdomain.lower())
                
                self.logger.debug(f"crt.sh found {len(results)} subdomains")
        
        except Exception as e:
            self.logger.debug(f"crt.sh error: {str(e)}")
        
        return results
    
    def enumerate_wayback(self, domain: str) -> Set[str]:
        """Query Wayback Machine for subdomains"""
        results = set()
        
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
            response = requests.get(url, timeout=CURL_TIMEOUT)
            
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if line:
                        # Extract domain from URL
                        parsed = urlparse(line if line.startswith('http') else f'http://{line}')
                        hostname = parsed.netloc or parsed.path.split('/')[0]
                        hostname = hostname.split(':')[0]  # Remove port
                        if hostname:
                            results.add(hostname.lower())
                
                self.logger.debug(f"Wayback Machine found {len(results)} subdomains")
        
        except Exception as e:
            self.logger.debug(f"Wayback Machine error: {str(e)}")
        
        return results
    
    def enumerate_rapiddns(self, domain: str) -> Set[str]:
        """Query RapidDNS for subdomains"""
        results = set()
        
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            response = requests.get(url, timeout=CURL_TIMEOUT)
            
            if response.status_code == 200:
                # Extract subdomains using regex
                pattern = re.compile(r'[a-zA-Z0-9._-]+\.' + re.escape(domain))
                matches = pattern.findall(response.text)
                results.update(match.lower() for match in matches)
                
                self.logger.debug(f"RapidDNS found {len(results)} subdomains")
        
        except Exception as e:
            self.logger.debug(f"RapidDNS error: {str(e)}")
        
        return results
    
    def enumerate_all(self, domains: Set[str]) -> Set[str]:
        """Enumerate subdomains for all targets"""
        all_results = set()
        
        with ThreadPoolExecutor(max_workers=min(len(domains), 5)) as executor:
            futures = {}
            
            for domain in domains:
                # Submit all enumeration tasks
                futures[executor.submit(self.enumerate_passive, domain)] = ('passive', domain)
                futures[executor.submit(self.enumerate_crtsh, domain)] = ('crtsh', domain)
                futures[executor.submit(self.enumerate_wayback, domain)] = ('wayback', domain)
                futures[executor.submit(self.enumerate_rapiddns, domain)] = ('rapiddns', domain)
            
            # Collect results
            for future in as_completed(futures):
                source, domain = futures[future]
                try:
                    results = future.result()
                    all_results.update(results)
                except Exception as e:
                    self.logger.debug(f"Error in {source} for {domain}: {str(e)}")
        
        return all_results


# ============================================
# DNS Resolution
# ============================================
class DNSResolver:
    """Resolve DNS records for subdomains"""
    
    def __init__(self, logger: logging.Logger, threads: int = DNS_RESOLUTION_THREADS):
        self.logger = logger
        self.threads = threads
    
    def resolve(self, subdomains: Set[str], temp_dir: Path) -> Set[str]:
        """Resolve DNS records using dnsx"""
        if not subdomains:
            self.logger.warning("No subdomains to resolve")
            return set()
        
        self.logger.info("Resolving DNS records...")
        
        # Write subdomains to file
        input_file = temp_dir / 'to_resolve.txt'
        with open(input_file, 'w') as f:
            for sub in sorted(subdomains):
                f.write(f"{sub}\n")
        
        # Resolve with dnsx
        output_file = temp_dir / 'resolved.txt'
        cmd = [
            'dnsx',
            '-l', str(input_file),
            '-silent',
            '-threads', str(self.threads),
            '-a',
            '-resp',
            '-o', str(output_file)
        ]
        
        run_command(cmd, logger=self.logger)
        
        # Parse results
        resolved = set()
        if output_file.exists():
            with open(output_file) as f:
                for line in f:
                    # Extract domain from dnsx output (format: domain [IP])
                    parts = line.strip().split()
                    if parts:
                        resolved.add(parts[0])
        
        if resolved:
            resolution_rate = (len(resolved) / len(subdomains)) * 100
            self.logger.info(f"{Colors.GREEN}✓ Resolved {len(resolved)}/{len(subdomains)} "
                           f"subdomains ({resolution_rate:.1f}%){Colors.NC}")
        else:
            self.logger.warning("No subdomains resolved")
        
        return resolved


# ============================================
# Security Checks
# ============================================
class SecurityChecker:
    """Perform security checks on subdomains"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def check_takeovers(self, subdomains: Set[str], temp_dir: Path) -> List[str]:
        """Check for potential subdomain takeovers"""
        if not subdomains:
            return []
        
        self.logger.info("Checking for potential subdomain takeovers...")
        takeovers = []
        
        # Write subdomains to file
        input_file = temp_dir / 'for_takeover_check.txt'
        with open(input_file, 'w') as f:
            for sub in sorted(subdomains):
                f.write(f"{sub}\n")
        
        # Try subjack
        if shutil.which('subjack'):
            output_file = temp_dir / 'subjack.txt'
            cmd = [
                'subjack',
                '-w', str(input_file),
                '-t', '50',
                '-timeout', '30',
                '-ssl',
                '-o', str(output_file)
            ]
            run_command(cmd, logger=self.logger)
            
            if output_file.exists() and output_file.stat().st_size > 0:
                with open(output_file) as f:
                    takeovers.extend(f.readlines())
                self.logger.warning(f"Found {len(takeovers)} potential takeovers with subjack")
        
        # Try nuclei
        if shutil.which('nuclei'):
            output_file = temp_dir / 'nuclei_takeovers.txt'
            cmd = [
                'nuclei',
                '-l', str(input_file),
                '-tags', 'takeover',
                '-silent',
                '-o', str(output_file)
            ]
            run_command(cmd, logger=self.logger)
            
            if output_file.exists() and output_file.stat().st_size > 0:
                with open(output_file) as f:
                    new_takeovers = f.readlines()
                    takeovers.extend(new_takeovers)
                self.logger.warning(f"Found {len(new_takeovers)} potential takeovers with nuclei")
        
        if takeovers:
            self.logger.warning(f"{Colors.RED}Total potential takeovers: {len(takeovers)}{Colors.NC}")
        else:
            self.logger.info(f"{Colors.GREEN}✓ No subdomain takeovers detected{Colors.NC}")
        
        return takeovers
    
    def probe_http(self, subdomains: Set[str], temp_dir: Path) -> List[Dict]:
        """Probe HTTP services"""
        if not subdomains or not shutil.which('httpx'):
            return []
        
        self.logger.info("Running HTTP probing...")
        
        # Write subdomains to file
        input_file = temp_dir / 'for_http_probe.txt'
        with open(input_file, 'w') as f:
            for sub in sorted(subdomains):
                f.write(f"{sub}\n")
        
        output_file = temp_dir / 'http_probes.txt'
        cmd = [
            'httpx',
            '-l', str(input_file),
            '-silent',
            '-threads', '50',
            '-status-code',
            '-title',
            '-tech-detect',
            '-o', str(output_file)
        ]
        
        run_command(cmd, logger=self.logger)
        
        results = []
        if output_file.exists():
            with open(output_file) as f:
                results = f.readlines()
            
            self.logger.info(f"{Colors.GREEN}✓ Probed {len(results)} live HTTP services{Colors.NC}")
        
        return results


# ============================================
# Report Generation
# ============================================
class ReportGenerator:
    """Generate scan reports"""
    
    def __init__(self, config: ReconConfig, results: ScanResults, working_dir: Path, logger: logging.Logger):
        self.config = config
        self.results = results
        self.working_dir = working_dir
        self.logger = logger
    
    def generate(self):
        """Generate and save reports"""
        self.print_summary()
        self.save_markdown_report()
        self.save_json_report()
    
    def print_summary(self):
        """Print summary to console"""
        print(f"\n{Colors.CYAN}{Colors.HR}{Colors.NC}")
        print(f"{Colors.CYAN}{Colors.BOLD}RECONNAISSANCE REPORT{Colors.NC}")
        print(f"{Colors.CYAN}{Colors.HR}{Colors.NC}\n")
        
        print(f"{Colors.BOLD}Scan Summary:{Colors.NC}")
        print(f"  Targets Processed: {len(self.results.targets)}")
        print(f"  Subdomains Discovered: {len(self.results.raw_subdomains)}")
        print(f"  Out-of-Scope Excluded: {len(self.results.excluded_subdomains)}")
        print(f"  Live Subdomains: {len(self.results.resolved_subdomains)}")
        
        if self.results.raw_subdomains:
            in_scope = len(self.results.raw_subdomains) - len(self.results.excluded_subdomains)
            if in_scope > 0:
                resolution_rate = (len(self.results.resolved_subdomains) / in_scope) * 100
                print(f"  Resolution Rate: {resolution_rate:.1f}%")
        
        if self.results.takeovers:
            print(f"  {Colors.RED}Potential Takeovers: {len(self.results.takeovers)}{Colors.NC}")
        else:
            print(f"  Potential Takeovers: 0")
        
        print(f"\n{Colors.BOLD}Files Generated:{Colors.NC}")
        print(f"  Live Subdomains: {self.working_dir / 'subdomains_final.txt'}")
        print(f"  All Subdomains: {self.working_dir / 'all_subdomains.txt'}")
        print(f"  Excluded Subdomains: {self.working_dir / 'exclusions_applied.txt'}")
        print(f"  Scan Logs: {self.working_dir / 'recon.log'}")
        
        if self.results.takeovers:
            print(f"  {Colors.RED}Takeover Alerts: {self.working_dir / 'potential_takeovers.txt'}{Colors.NC}")
        
        if self.results.http_services:
            print(f"  HTTP Probes: {self.working_dir / 'http_probes.txt'}")
        
        print(f"\n{Colors.BOLD}Working Directory:{Colors.NC}")
        print(f"  {self.working_dir}\n")
    
    def save_markdown_report(self):
        """Save markdown report"""
        report_file = self.working_dir / 'report.md'
        
        with open(report_file, 'w') as f:
            f.write(f"# Reconnaissance Report\n\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Script Version:** {SCRIPT_VERSION}\n\n")
            
            f.write(f"## Summary\n\n")
            f.write(f"- Targets Processed: {len(self.results.targets)}\n")
            f.write(f"- Subdomains Discovered: {len(self.results.raw_subdomains)}\n")
            f.write(f"- Out-of-Scope Excluded: {len(self.results.excluded_subdomains)}\n")
            f.write(f"- Live Subdomains: {len(self.results.resolved_subdomains)}\n")
            f.write(f"- Potential Takeovers: {len(self.results.takeovers)}\n\n")
            
            f.write(f"## Input Sources\n\n")
            if self.config.target_domain:
                f.write(f"- Domain: `{self.config.target_domain}`\n")
            if self.config.scope_file:
                f.write(f"- Scope File: `{self.config.scope_file}`\n")
            if self.config.out_scope_domains:
                f.write(f"- CLI Exclusions: `{', '.join(self.config.out_scope_domains)}`\n")
            if self.config.out_scope_file:
                f.write(f"- Exclusion File: `{self.config.out_scope_file}`\n")
            
            f.write(f"\n## Files\n\n")
            f.write(f"- [Live Subdomains](subdomains_final.txt)\n")
            f.write(f"- [All Subdomains](all_subdomains.txt)\n")
            f.write(f"- [Excluded Subdomains](exclusions_applied.txt)\n")
            if self.results.takeovers:
                f.write(f"- [Takeover Alerts](potential_takeovers.txt)\n")
            if self.results.http_services:
                f.write(f"- [HTTP Probes](http_probes.txt)\n")
            f.write(f"- [Logs](recon.log)\n")
        
        self.logger.info(f"Markdown report saved: {report_file}")
    
    def save_json_report(self):
        """Save JSON report"""
        report_file = self.working_dir / 'report.json'
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'version': SCRIPT_VERSION,
            'config': {
                'target_domain': self.config.target_domain,
                'scope_file': str(self.config.scope_file) if self.config.scope_file else None,
                'out_scope_file': str(self.config.out_scope_file) if self.config.out_scope_file else None,
                'threads': self.config.threads,
            },
            'summary': {
                'targets_processed': len(self.results.targets),
                'subdomains_discovered': len(self.results.raw_subdomains),
                'excluded_subdomains': len(self.results.excluded_subdomains),
                'live_subdomains': len(self.results.resolved_subdomains),
                'potential_takeovers': len(self.results.takeovers),
            },
            'targets': sorted(list(self.results.targets)),
            'resolved_subdomains': sorted(list(self.results.resolved_subdomains)),
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"JSON report saved: {report_file}")


# ============================================
# Main Reconnaissance Engine
# ============================================
class ReconEngine:
    """Main reconnaissance engine"""
    
    def __init__(self, config: ReconConfig):
        self.config = config
        self.working_dir = Path(f"recon_{config.timestamp}")
        self.temp_dir = self.working_dir / 'temp'
        self.results = ScanResults()
        
        # Setup
        self.working_dir.mkdir(exist_ok=True)
        self.temp_dir.mkdir(exist_ok=True)
        
        self.logger = setup_logging(self.working_dir, config.debug_mode)
        
    def run(self):
        """Execute reconnaissance scan"""
        try:
            print_banner()
            
            self.logger.info(f"Starting reconnaissance automation v{SCRIPT_VERSION}")
            self.logger.info(f"Working directory: {self.working_dir}")
            
            # Check dependencies
            if not check_dependencies(self.logger):
                return False
            
            # Phase 1: Target Preparation
            self.print_phase_header("PHASE 1: TARGET PREPARATION")
            target_mgr = TargetManager(self.config, self.logger)
            self.results.targets = target_mgr.prepare_targets()
            target_mgr.prepare_exclusions()
            
            # Phase 2: Subdomain Enumeration
            self.print_phase_header("PHASE 2: SUBDOMAIN ENUMERATION")
            enumerator = SubdomainEnumerator(self.logger, self.config.threads)
            self.results.raw_subdomains = enumerator.enumerate_all(self.results.targets)
            self.logger.info(f"{Colors.GREEN}✓ Collected {len(self.results.raw_subdomains)} "
                           f"raw subdomains{Colors.NC}")
            
            # Save all discovered subdomains
            all_subs_file = self.working_dir / 'all_subdomains.txt'
            with open(all_subs_file, 'w') as f:
                for sub in sorted(self.results.raw_subdomains):
                    f.write(f"{sub}\n")
            
            # Phase 3: Out-of-Scope Filtering
            self.print_phase_header("PHASE 3: OUT-OF-SCOPE FILTERING")
            self.results.filtered_subdomains = set()
            
            for subdomain in self.results.raw_subdomains:
                if target_mgr.is_excluded(subdomain):
                    self.results.excluded_subdomains.add(subdomain)
                else:
                    # Verify it's in scope for at least one target
                    for target in self.results.targets:
                        if is_subdomain_of(subdomain, target):
                            self.results.filtered_subdomains.add(subdomain)
                            break
            
            self.logger.info(f"{Colors.GREEN}✓ Filtered to {len(self.results.filtered_subdomains)} "
                           f"in-scope subdomains{Colors.NC}")
            
            if self.results.excluded_subdomains:
                self.logger.info(f"Excluded {len(self.results.excluded_subdomains)} "
                               f"out-of-scope subdomains")
                
                # Save excluded subdomains
                excluded_file = self.working_dir / 'exclusions_applied.txt'
                with open(excluded_file, 'w') as f:
                    for sub in sorted(self.results.excluded_subdomains):
                        f.write(f"{sub}\n")
            
            # Phase 4: DNS Resolution
            self.print_phase_header("PHASE 4: DNS RESOLUTION")
            resolver = DNSResolver(self.logger, DNS_RESOLUTION_THREADS)
            self.results.resolved_subdomains = resolver.resolve(
                self.results.filtered_subdomains,
                self.temp_dir
            )
            
            # Save resolved subdomains
            final_file = self.working_dir / 'subdomains_final.txt'
            with open(final_file, 'w') as f:
                for sub in sorted(self.results.resolved_subdomains):
                    f.write(f"{sub}\n")
            
            # Phase 5: HTTP Probing (Optional)
            if self.config.http_probe and self.results.resolved_subdomains:
                self.print_phase_header("PHASE 5: HTTP PROBING")
                checker = SecurityChecker(self.logger)
                self.results.http_services = checker.probe_http(
                    self.results.resolved_subdomains,
                    self.temp_dir
                )
                
                # Save HTTP probe results
                if self.results.http_services:
                    http_file = self.working_dir / 'http_probes.txt'
                    with open(http_file, 'w') as f:
                        f.writelines(self.results.http_services)
            
            # Phase 6: Takeover Detection (Optional)
            if self.config.check_takeovers and self.results.resolved_subdomains:
                self.print_phase_header("PHASE 6: TAKEOVER DETECTION")
                checker = SecurityChecker(self.logger)
                self.results.takeovers = checker.check_takeovers(
                    self.results.resolved_subdomains,
                    self.temp_dir
                )
                
                # Save takeover results
                if self.results.takeovers:
                    takeover_file = self.working_dir / 'potential_takeovers.txt'
                    with open(takeover_file, 'w') as f:
                        f.writelines(self.results.takeovers)
            
            # Generate Reports
            self.print_phase_header("GENERATING REPORTS")
            report_gen = ReportGenerator(self.config, self.results, self.working_dir, self.logger)
            report_gen.generate()
            
            # Cleanup
            if not self.config.keep_temp:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                self.logger.debug("Cleaned up temporary files")
            
            self.print_phase_header("SCAN COMPLETE")
            self.logger.info(f"{Colors.GREEN}✓ Results saved to {self.working_dir}{Colors.NC}")
            
            return True
            
        except KeyboardInterrupt:
            self.logger.warning("\nScan interrupted by user")
            return False
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}", exc_info=self.config.debug_mode)
            return False
    
    def print_phase_header(self, title: str):
        """Print phase header"""
        print(f"\n{Colors.CYAN}{Colors.HR}{Colors.NC}")
        print(f"{Colors.CYAN}{Colors.BOLD}{title}{Colors.NC}")
        print(f"{Colors.CYAN}{Colors.HR}{Colors.NC}\n")


# ============================================
# CLI Interface
# ============================================
def parse_arguments() -> ReconConfig:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Advanced Reconnaissance Automation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Single domain with CLI exclusions
  %(prog)s -d example.com -ocd "dev.example.com,staging.example.com"
  
  # Scope file with exclusion file
  %(prog)s -sf scope.txt -ocf outofscope.txt
  
  # Both domain and scope file
  %(prog)s -d example.com -sf other_domains.txt -ocd "test.example.com"
  
  # With verbose mode and custom threads
  %(prog)s -d example.com -v -t 100
        '''
    )
    
    # Target specification
    target_group = parser.add_argument_group('Target Specification')
    target_group.add_argument('-d', '--domain', help='Single domain to scan')
    target_group.add_argument('-sf', '--scope-file', type=Path, help='Scope file containing domains')
    
    # Exclusion specification
    exclusion_group = parser.add_argument_group('Out-of-Scope Specification')
    exclusion_group.add_argument('-ocd', '--out-scope-domains', 
                                help='Comma-separated out-of-scope domains')
    exclusion_group.add_argument('-ocf', '--out-scope-file', type=Path,
                                help='File containing out-of-scope domains')
    
    # Options
    options_group = parser.add_argument_group('Options')
    options_group.add_argument('-t', '--threads', type=int, default=DEFAULT_THREADS,
                              help=f'Number of threads (default: {DEFAULT_THREADS})')
    options_group.add_argument('-v', '--verbose', action='store_true',
                              help='Enable verbose/debug mode')
    options_group.add_argument('--no-http-probe', action='store_true',
                              help='Disable HTTP probing')
    options_group.add_argument('--no-takeover-check', action='store_true',
                              help='Disable takeover detection')
    options_group.add_argument('--keep-temp', action='store_true',
                              help='Keep temporary files')
    
    args = parser.parse_args()
    
    # Validate inputs
    if not args.domain and not args.scope_file:
        parser.error("Either -d/--domain or -sf/--scope-file must be provided")
    
    # Parse out-of-scope domains
    out_scope_list = []
    if args.out_scope_domains:
        out_scope_list = [d.strip() for d in args.out_scope_domains.split(',') if d.strip()]
    
    # Create configuration
    config = ReconConfig(
        target_domain=args.domain,
        scope_file=args.scope_file,
        out_scope_domains=out_scope_list,
        out_scope_file=args.out_scope_file,
        threads=args.threads,
        debug_mode=args.verbose,
        http_probe=not args.no_http_probe,
        check_takeovers=not args.no_takeover_check,
        keep_temp=args.keep_temp
    )
    
    return config


# ============================================
# Entry Point
# ============================================
def main():
    """Main entry point"""
    try:
        config = parse_arguments()
        engine = ReconEngine(config)
        success = engine.run()
        sys.exit(0 if success else 1)
    
    except Exception as e:
        print(f"{Colors.RED}[ERROR] {str(e)}{Colors.NC}")
        sys.exit(1)


if __name__ == '__main__':
    main()
