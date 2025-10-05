#!/usr/bin/env python3
"""
Demo Script: API Usage Examples
Demonstrates how to use the WAF API programmatically
"""

import requests
import json

BASE_URL = "http://localhost:8000"


def print_section(title):
    """Print section header"""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def main():
    """Demonstrate API usage"""
    
    print_section("AI-NGFW API Demo")
    
    # 1. Authentication
    print_section("1. Authentication")
    auth_response = requests.post(f"{BASE_URL}/api/auth", json={
        "username": "admin",
        "password": "admin123"
    })
    
    if auth_response.status_code == 200:
        token = auth_response.json()["access_token"]
        print("✓ Authentication successful")
        print(f"Token: {token}")
    else:
        print("✗ Authentication failed")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Threat Check
    print_section("2. Threat Detection")
    
    # Test SQL injection
    threat_check = requests.post(f"{BASE_URL}/api/check", 
        json={
            "content": "SELECT * FROM users WHERE id=1 OR 1=1",
            "content_type": "text"
        },
        headers=headers
    )
    
    result = threat_check.json()
    print("Test: SQL Injection")
    print(f"  Malicious: {result['is_malicious']}")
    print(f"  Threat Type: {result.get('threat_type', 'N/A')}")
    print(f"  Confidence: {result['confidence']:.2f}")
    print(f"  Risk Score: {result['risk_score']:.2f}")
    
    # Test normal content
    print("\nTest: Normal Content")
    threat_check = requests.post(f"{BASE_URL}/api/check",
        json={
            "content": "Hello, this is normal text",
            "content_type": "text"
        },
        headers=headers
    )
    
    result = threat_check.json()
    print(f"  Malicious: {result['is_malicious']}")
    print(f"  Confidence: {result['confidence']:.2f}")
    
    # 3. Statistics
    print_section("3. WAF Statistics")
    stats = requests.get(f"{BASE_URL}/api/stats").json()
    
    print(f"Total Requests: {stats['total_requests']}")
    print(f"Blocked Requests: {stats['blocked_requests']}")
    print(f"Block Rate: {stats['block_rate']:.1%}")
    
    print("\nThreats Detected:")
    for threat_type, count in stats['threats_detected'].items():
        print(f"  - {threat_type}: {count}")
    
    print("\nPerformance:")
    print(f"  Avg Latency: {stats['performance']['avg_latency_ms']:.2f}ms")
    print(f"  P95 Latency: {stats['performance']['p95_latency_ms']:.2f}ms")
    print(f"  Throughput: {stats['performance']['throughput_rps']:.1f} req/s")
    
    # 4. Recent Incidents
    print_section("4. Recent Security Incidents")
    incidents = requests.get(f"{BASE_URL}/api/incidents?limit=5").json()
    
    for incident in incidents['incidents'][:5]:
        print(f"\n[{incident['timestamp']}]")
        print(f"  ID: {incident['incident_id']}")
        print(f"  Type: {incident['threat_type']}")
        print(f"  Severity: {incident['severity']}")
        print(f"  Source IP: {incident['source_ip']}")
        print(f"  Action: {incident['action_taken']}")
    
    # 5. Active Rules
    print_section("5. Active WAF Rules")
    rules = requests.get(f"{BASE_URL}/api/rules").json()
    
    for rule in rules['rules']:
        print(f"\n{rule['id']}: {rule['name']}")
        print(f"  Type: {rule['type']}")
        print(f"  Severity: {rule['severity']}")
        print(f"  Status: {'Enabled' if rule['enabled'] else 'Disabled'}")
        print(f"  Patterns: {rule['patterns']}")
    
    # 6. System Health
    print_section("6. System Health")
    health = requests.get(f"{BASE_URL}/api/health/detailed").json()
    
    print(f"Overall Status: {health['status'].upper()}")
    
    print("\nComponents:")
    for component, status in health['components'].items():
        print(f"  - {component}: {status}")
    
    print("\nSystem Resources:")
    print(f"  CPU Usage: {health['system']['cpu_usage']:.1f}%")
    print(f"  Memory Usage: {health['system']['memory_usage_mb']:.1f} MB")
    print(f"  Disk Usage: {health['system']['disk_usage_percent']:.1f}%")
    
    print_section("Demo Complete")
    print("\nFor more information, visit:")
    print(f"  API Documentation: {BASE_URL}/api/docs")
    print(f"  Dashboard: http://localhost:8050")
    print()


if __name__ == "__main__":
    main()
