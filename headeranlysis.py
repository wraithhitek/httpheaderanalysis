import argparse
import requests
import json
from datetime import datetime

SECURITY_HEADERS = [
    ('Strict-Transport-Security', 'Enforce HTTPS with max-age=31536000; includeSubDomains'),
    ('Content-Security-Policy', 'Prevent XSS and data injection attacks'),
    ('X-Content-Type-Options', 'Should be "nosniff" to prevent MIME sniffing'),
    ('X-Frame-Options', 'Prevent clickjacking with "DENY" or "SAMEORIGIN"'),
    ('X-XSS-Protection', 'Use "1; mode=block" to enable XSS protection'),
    ('Referrer-Policy', 'Control referrer information sent in requests'),
    ('Permissions-Policy', 'Control browser features and APIs'),
    # Removed 'Server' from security score calculation
]

def analyze_headers(url, json_output=None):
    try:
        response = requests.get(
            url,
            headers={'User-Agent': 'SecurityHeaderChecker/1.0'},
            timeout=10,
            verify=True
        )
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {e}")
        return

    headers = response.headers
    analysis = []
    
    # Analyze security headers
    for name, recommendation in SECURITY_HEADERS:
        present = name in headers
        value = headers.get(name, 'Not Present')
        analysis.append({
            'header': name,
            'present': present,
            'value': value,
            'recommendation': recommendation,
        })

    # Analyze cookies (fixed)
    cookie_analysis = []
    cookies = headers.get('Set-Cookie', '')
    for cookie in cookies.split(', '):
        if not cookie:
            continue
        secure = 'secure' in cookie.lower()
        http_only = 'httponly' in cookie.lower()
        cookie_name = cookie.split('=')[0].strip()
        cookie_analysis.append({
            'name': cookie_name,
            'secure': secure,
            'http_only': http_only,
            'full_value': cookie
        })

    # Calculate security score (fixed)
    valid_headers = [item for item in analysis if item['present']]
    security_score = len(valid_headers) / len(SECURITY_HEADERS)

    # Generate report
    report = {
        'timestamp': datetime.now().isoformat(),
        'url': url,
        'final_url': response.url,
        'status_code': response.status_code,
        'headers': analysis,
        'cookies': cookie_analysis,
        'security_score': security_score
    }

    if json_output:
        with open(json_output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to {json_output}")
    else:
        print_console_report(report)

def print_console_report(report):
   def print_console_report(report):
    print(f"\n{'='*50}")
    print(f"Security Header Analysis Report")
    print(f"URL: {report['url']}")
    print(f"Final URL: {report['final_url']}")
    print(f"Scan Time: {report['timestamp']}")
    print(f"Status Code: {report['status_code']}")
    print(f"{'='*50}\n")

    # Headers analysis
    print("Security Header Status:")
    for item in report['headers']:
        status = "✓ PRESENT" if item['present'] else "✗ MISSING"
        print(f"\n{status} - {item['header']}")
        print(f"Current Value: {item['value']}")
        print(f"Recommendation: {item['recommendation']}")

    # Cookies analysis
    print("\nCookie Security:")
    for cookie in report['cookies']:
        print(f"\nCookie: {cookie['name']}")
        print(f"Secure: {'✓' if cookie['secure'] else '✗'}")
        print(f"HttpOnly: {'✓' if cookie['http_only'] else '✗'}")
        print(f"Full Value: {cookie['full_value']}")

    # Security score
    print(f"\n{'='*50}")
    print(f"Overall Security Score: {report['security_score']*100:.1f}%")
    print(f"{'='*50}")


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='HTTP Header Security Analyzer')
    parser.add_argument('url', help='URL to analyze')
    parser.add_argument('--json', help='Export results to JSON file', metavar='FILENAME')
    args = parser.parse_args()
    analyze_headers(args.url, args.json)
    