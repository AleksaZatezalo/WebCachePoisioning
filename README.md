# WebCachePoisioning

# Web Cache Poisoning Tester

A Python-based security testing tool designed to identify and verify web cache poisoning vulnerabilities in web applications. This tool helps security researchers and penetration testers evaluate how web applications handle cached content and custom HTTP headers.

## ⚠️ Legal Disclaimer

This tool is for educational and authorized security testing purposes only. Using this tool against systems without explicit permission may be illegal. The author assumes no liability for misuse or damage caused by this tool.

## Features

- Automated cache behavior detection
- Custom header influence testing
- Concurrent vulnerability scanning
- Cache poisoning verification
- Detailed reporting of findings
- Support for various caching systems
## Usage

Basic usage:
```bash
python cache_poison_tester.py http://example.com
```

With verbose output:
```bash
python cache_poison_tester.py -v http://example.com
```

### Command Line Arguments

- `url`: Target URL to test (required)
- `-v, --verbose`: Enable verbose output
- `-h, --help`: Show help message

## How It Works

The tool operates in three main phases:

1. Cache Detection
   - Analyzes response times
   - Checks for cache-related headers
   - Determines caching behavior

2. Header Influence Testing
   - Tests various HTTP headers
   - Identifies headers that affect responses
   - Concurrent testing for efficiency

3. Vulnerability Verification
   - Attempts to poison cache with safe payloads
   - Verifies if poisoned content is served
   - Reports successful exploitation paths

## Tested Headers

The tool checks for influence from commonly exploitable headers:
- X-Forwarded-Host
- X-Host
- X-Forwarded-Server
- X-HTTP-Host-Override
- X-Forwarded-Proto
- X-Original-URL
- X-Rewrite-URL
- X-Custom-IP-Authorization

## Output Example

```
[*] Testing http://example.com for cache poisoning vulnerability
[*] Detecting cache behavior...
[+] Cache detected:
    Cache-Control: public, max-age=3600
    Cache Hit Indicator: X-Cache: HIT
[*] Testing for header influence...
[+] Found 2 potentially vulnerable headers
[!] Target is VULNERABLE to web cache poisoning!
[!] Vulnerable headers:
    - X-Forwarded-Host
    - X-Host
```

## Error Handling

The script includes robust error handling for:
- Connection timeouts
- Invalid URLs
- Permission errors
- SSL/TLS errors
- Malformed responses

## Best Practices

1. Always obtain explicit permission before testing
2. Use in a controlled environment first
3. Monitor system resources during testing
4. Document all findings and steps
5. Report vulnerabilities responsibly

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
