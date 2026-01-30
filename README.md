# Advanced Reconnaissance Automation Tool

**Version:** 4.0 (Python Edition)  
**Professional reconnaissance tool for ethical hacking and security assessments**

## 🚀 Features

- **Multi-Source Enumeration**: Integrates subfinder, assetfinder, crt.sh, Wayback Machine, RapidDNS
- **Intelligent Scope Management**: Supports wildcards and multiple scope files
- **Advanced Exclusion Handling**: Both exact matches and wildcard patterns
- **DNS Resolution**: Fast parallel DNS resolution with dnsx
- **HTTP Probing**: Live service detection with httpx
- **Takeover Detection**: Automatic subdomain takeover checking
- **Professional Reporting**: Generates Markdown and JSON reports
- **Error Handling**: Robust timeout and retry mechanisms
- **Async Operations**: Efficient multi-threaded execution
- **Colored Output**: Clear, readable terminal output

## 📋 Prerequisites

### System Requirements
- Python 3.8+
- Linux/Unix environment (tested on Ubuntu/Debian)
- Internet connection for web-based enumeration

### Required Tools
Install the following Go-based tools:

```bash
# Install Go (if not already installed)
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Install required tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/tomnomnom/anew@latest
```

### Recommended Tools (Optional)
```bash
# For enhanced functionality
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/haccer/subjack@latest
go install -v github.com/crtsh/subdominator@latest
```

### Python Dependencies
```bash
pip install -r requirements.txt
```

## 🔧 Installation

```bash
# Clone or download the script
chmod +x advanced_recon.py

# Install Python dependencies
pip install -r requirements.txt

# Verify dependencies
python3 advanced_recon.py -h
```

## 📖 Usage

### Basic Examples

#### Single Domain Scan
```bash
python3 advanced_recon.py -d example.com
```

#### Scan with CLI Exclusions
```bash
python3 advanced_recon.py -d example.com -ocd "dev.example.com,test.example.com"
```

#### Using Scope File
```bash
python3 advanced_recon.py -sf scope.txt
```

#### Complete Scan with All Features
```bash
python3 advanced_recon.py \
  -d example.com \
  -sf additional_domains.txt \
  -ocd "staging.example.com,*.dev.example.com" \
  -ocf exclusions.txt \
  -t 100 \
  -v
```

### Advanced Examples

#### Bug Bounty Program Scan
```bash
# Create scope file (in-scope.txt)
echo "example.com" > in-scope.txt
echo "*.example.com" >> in-scope.txt
echo "api.example.com" >> in-scope.txt

# Create exclusions file (out-of-scope.txt)
echo "*.staging.example.com" > out-of-scope.txt
echo "*.dev.example.com" >> out-of-scope.txt
echo "internal.example.com" >> out-of-scope.txt

# Run scan
python3 advanced_recon.py -sf in-scope.txt -ocf out-of-scope.txt -v
```

#### Fast Scan (No Probing)
```bash
python3 advanced_recon.py \
  -d target.com \
  --no-http-probe \
  --no-takeover-check \
  -t 200
```

#### Detailed Debug Scan
```bash
python3 advanced_recon.py \
  -d example.com \
  -v \
  --keep-temp
```

## 🎯 Command Line Options

### Target Specification
- `-d, --domain DOMAIN` - Single domain to scan
- `-sf, --scope-file FILE` - File containing in-scope domains

### Exclusion Specification
- `-ocd, --out-scope-domains DOMAINS` - Comma-separated exclusions
- `-ocf, --out-scope-file FILE` - File containing exclusions

### Options
- `-t, --threads NUM` - Number of threads (default: 50)
- `-v, --verbose` - Enable debug mode
- `--no-http-probe` - Disable HTTP probing
- `--no-takeover-check` - Disable takeover detection
- `--keep-temp` - Keep temporary files
- `-h, --help` - Show help message

## 📁 Input File Formats

### Scope File Format
```text
# In-scope domains (one per line)
example.com
*.example.com
api.example.com
app.example.com

# Comments are supported
# Wildcards are supported
```

### Exclusion File Format
```text
# Out-of-scope domains
*.staging.example.com
*.dev.example.com
test.example.com
internal.example.com

# Wildcards and exact matches supported
```

## 📊 Output Structure

```
recon_YYYYMMDD_HHMMSS/
├── subdomains_final.txt       # Live, resolved subdomains
├── all_subdomains.txt          # All discovered subdomains
├── exclusions_applied.txt      # Excluded subdomains
├── http_probes.txt             # HTTP probe results
├── potential_takeovers.txt     # Takeover alerts
├── report.md                   # Markdown report
├── report.json                 # JSON report
├── recon.log                   # Detailed logs
└── temp/                       # Temporary files (if --keep-temp)
```

## 🔍 Features Explained

### Wildcard Support
The tool supports wildcard patterns in exclusions:
- `*.dev.example.com` - Excludes all dev subdomains
- `test-*.example.com` - Excludes test-prefixed subdomains
- Exact matches: `staging.example.com`

### Multi-Source Enumeration
Queries multiple sources in parallel:
- **Passive Tools**: subfinder, assetfinder, subdominator
- **Certificate Transparency**: crt.sh
- **Historical Data**: Wayback Machine
- **DNS Databases**: RapidDNS

### DNS Resolution
- Fast parallel resolution using dnsx
- Configurable thread count
- A record validation
- Resolution rate reporting

### Security Checks
- **HTTP Probing**: Identifies live web services
- **Takeover Detection**: Checks for vulnerable subdomains
- **Technology Detection**: Identifies web technologies

## 🛡️ Security Considerations

### Responsible Usage
- Only scan domains you have permission to test
- Respect rate limits and target infrastructure
- Follow bug bounty program rules
- Use appropriate thread counts

### OPSEC
- The tool generates network traffic
- DNS queries are logged by providers
- HTTP probing is detectable
- Use VPN/proxy if needed

### Rate Limiting
```bash
# Conservative scan
python3 advanced_recon.py -d target.com -t 10

# Aggressive scan
python3 advanced_recon.py -d target.com -t 200
```

## 🐛 Troubleshooting

### Common Issues

#### Missing Dependencies
```bash
# Check if tools are in PATH
which subfinder dnsx httpx

# Reinstall if needed
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

#### Permission Errors
```bash
# Make script executable
chmod +x advanced_recon.py

# Check Python version
python3 --version  # Should be 3.8+
```

#### No Results
```bash
# Enable verbose mode for debugging
python3 advanced_recon.py -d example.com -v

# Check if domain is valid
dig example.com
```

#### Timeout Issues
```bash
# Reduce thread count
python3 advanced_recon.py -d example.com -t 10

# Increase timeout in code if needed
```

## 📈 Performance Tips

### Optimize for Speed
```bash
# Maximum performance (use with caution)
python3 advanced_recon.py \
  -d target.com \
  -t 200 \
  --no-takeover-check
```

### Optimize for Stealth
```bash
# Slower but less detectable
python3 advanced_recon.py \
  -d target.com \
  -t 5 \
  --no-http-probe
```

### Balance Speed and Reliability
```bash
# Recommended settings
python3 advanced_recon.py \
  -d target.com \
  -t 50
```

## 🔄 Updates from Bash Version

### Improvements
- ✅ Better error handling with try-catch blocks
- ✅ Type hints for code clarity
- ✅ Dataclasses for structured data
- ✅ Async-ready architecture
- ✅ JSON report generation
- ✅ Improved logging system
- ✅ Better progress indicators
- ✅ More robust file handling
- ✅ Enhanced exclusion matching
- ✅ Thread pool management

### Breaking Changes
- Command line option format standardized
- Output directory naming changed
- Some tool integrations improved

## 📝 Examples of Output

### Terminal Output
```
╔══════════════════════════════════════════════════════╗
║    Advanced Recon Automation v4.0                    ║
║        Professional Python Edition                   ║
╚══════════════════════════════════════════════════════╝

[*] 10:30:15 Starting reconnaissance automation v4.0
[*] 10:30:15 Working directory: recon_20260130_103015
[*] 10:30:15 Checking dependencies...
[+] 10:30:15 ✓ Required dependencies available

============================================================
PHASE 1: TARGET PREPARATION
============================================================

[*] 10:30:16 Preparing target list...
[+] 10:30:16 ✓ Prepared 3 unique targets
[*] 10:30:16 Preparing exclusion list...
[+] 10:30:16 ✓ Prepared 5 exclusion rules

============================================================
PHASE 2: SUBDOMAIN ENUMERATION
============================================================

[*] 10:30:17 Processing target 1/3: example.com
[+] 10:32:45 ✓ Collected 1,247 raw subdomains
```

### JSON Report Example
```json
{
  "timestamp": "2026-01-30T10:35:22",
  "version": "4.0",
  "summary": {
    "targets_processed": 3,
    "subdomains_discovered": 1247,
    "excluded_subdomains": 89,
    "live_subdomains": 823,
    "potential_takeovers": 2
  },
  "targets": ["example.com", "api.example.com"],
  "resolved_subdomains": ["www.example.com", "mail.example.com"]
}
```

## 🤝 Contributing

Contributions are welcome! Please:
1. Test your changes thoroughly
2. Follow Python PEP 8 style guide
3. Add comments for complex logic
4. Update documentation

## 📜 License

This tool is for educational and authorized security testing only.

## ⚠️ Disclaimer

**USE AT YOUR OWN RISK**

This tool is provided for educational purposes and authorized security testing only. The authors assume no liability for misuse or damage caused by this program. Always ensure you have explicit permission before scanning any target.

## 🙏 Credits

- **Subfinder**: ProjectDiscovery
- **Assetfinder**: TomNomNom  
- **dnsx**: ProjectDiscovery
- **httpx**: ProjectDiscovery
- **nuclei**: ProjectDiscovery
- **subjack**: Haccer

## 📞 Support

For issues or questions:
- Check troubleshooting section
- Enable verbose mode (`-v`)
- Review log files
- Test with simple domains first

---

**Version:** 4.0  
**Last Updated:** January 2026  
**Platform:** Linux/Unix  
**Language:** Python 3.8+
