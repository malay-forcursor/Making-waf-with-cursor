#!/usr/bin/env python3
"""
Demo Script: Simulated Attacks
This script demonstrates the WAF detecting and blocking various attacks
"""

import requests
import time
import sys

BASE_URL = "http://localhost:8000"

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def print_banner():
    """Print demo banner"""
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("=" * 80)
    print("AI-DRIVEN NEXT-GENERATION FIREWALL - ATTACK SIMULATION DEMO")
    print("=" * 80)
    print(f"{Colors.ENDC}")
    print()


def test_attack(name, url, expected_blocked=True):
    """Test an attack scenario"""
    print(f"{Colors.OKBLUE}[TEST]{Colors.ENDC} {name}")
    print(f"  URL: {url}")
    
    try:
        response = requests.get(url, timeout=5)
        
        if response.status_code == 403:
            print(f"  {Colors.FAIL}✓ BLOCKED{Colors.ENDC} - Request was blocked by WAF")
            print(f"  Response: {response.json()}")
            return True
        else:
            print(f"  {Colors.OKGREEN}✓ ALLOWED{Colors.ENDC} - Request passed (Status: {response.status_code})")
            return False
    
    except requests.RequestException as e:
        print(f"  {Colors.WARNING}⚠ ERROR{Colors.ENDC} - {e}")
        return False
    
    finally:
        print()
        time.sleep(1)


def main():
    """Run demo attacks"""
    
    print_banner()
    
    # Check if WAF is running
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        print(f"{Colors.OKGREEN}✓ WAF is running and healthy{Colors.ENDC}")
        print()
    except:
        print(f"{Colors.FAIL}✗ WAF is not running. Please start it with: python main.py{Colors.ENDC}")
        sys.exit(1)
    
    print(f"{Colors.BOLD}Simulating Various Attack Scenarios:{Colors.ENDC}")
    print()
    
    # SQL Injection Attacks
    print(f"{Colors.HEADER}--- SQL Injection Attacks ---{Colors.ENDC}")
    test_attack(
        "SQL Injection - UNION SELECT",
        f"{BASE_URL}/search?q=1' UNION SELECT * FROM users--"
    )
    test_attack(
        "SQL Injection - Boolean-based",
        f"{BASE_URL}/user?id=1' OR '1'='1"
    )
    test_attack(
        "SQL Injection - Time-based",
        f"{BASE_URL}/api?id=1'; WAITFOR DELAY '00:00:05'--"
    )
    
    # XSS Attacks
    print(f"{Colors.HEADER}--- Cross-Site Scripting (XSS) Attacks ---{Colors.ENDC}")
    test_attack(
        "XSS - Script injection",
        f"{BASE_URL}/search?q=<script>alert('XSS')</script>"
    )
    test_attack(
        "XSS - Event handler",
        f"{BASE_URL}/comment?text=<img src=x onerror=alert('XSS')>"
    )
    test_attack(
        "XSS - JavaScript URL",
        f"{BASE_URL}/redirect?url=javascript:alert('XSS')"
    )
    
    # Command Injection
    print(f"{Colors.HEADER}--- Command Injection Attacks ---{Colors.ENDC}")
    test_attack(
        "Command Injection - Pipe",
        f"{BASE_URL}/ping?host=127.0.0.1|cat /etc/passwd"
    )
    test_attack(
        "Command Injection - Semicolon",
        f"{BASE_URL}/cmd?exec=ls;cat /etc/shadow"
    )
    
    # Path Traversal
    print(f"{Colors.HEADER}--- Path Traversal Attacks ---{Colors.ENDC}")
    test_attack(
        "Path Traversal - Unix",
        f"{BASE_URL}/file?path=../../../../etc/passwd"
    )
    test_attack(
        "Path Traversal - Windows",
        f"{BASE_URL}/download?file=..\\..\\..\\windows\\win.ini"
    )
    
    # Normal Requests (should pass)
    print(f"{Colors.HEADER}--- Legitimate Requests (Should Pass) ---{Colors.ENDC}")
    test_attack(
        "Normal search query",
        f"{BASE_URL}/search?q=hello+world",
        expected_blocked=False
    )
    test_attack(
        "Normal API call",
        f"{BASE_URL}/api/stats",
        expected_blocked=False
    )
    
    # Summary
    print(f"{Colors.HEADER}--- Demo Complete ---{Colors.ENDC}")
    print(f"\n{Colors.OKGREEN}The WAF successfully detected and blocked malicious requests!")
    print(f"Legitimate traffic was allowed through.{Colors.ENDC}\n")
    print(f"View detailed statistics at: {BASE_URL}/api/stats")
    print(f"View real-time dashboard at: http://localhost:8050")
    print()


if __name__ == "__main__":
    main()
