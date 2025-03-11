# HTTP Header Analysis Tool
A security-oriented HTTP headers analyzer with extensive checks for security-related headers, fingerprinting, and compliance with OWASP best practices.

# Requirements
Installation: Requires Python 3.9 or higher

requests lib

# Basic usage
python header_analyzer.py https://example.com

# Save to JSON
python header_analyzer.py https://example.com --json report.json


==================================================
Security Header Analysis Report
URL: https://example.com
Final URL: https://example.com/
Scan Time: 2025-03-11T20:13:45.123456
==================================================

Security Header Status:

✓ PRESENT - Strict-Transport-Security
Current Value: max-age=31536000
Recommendation: Enforce HTTPS with max-age=31536000; includeSubDomains

✗ MISSING - Content-Security-Policy
Current Value: Not Present
Recommendation: Prevent XSS and data injection attacks

...

Cookie Security:

Cookie: session_id
Secure: ✓
HttpOnly: ✓

==================================================
Overall Security Score: 62.5%
==================================================
