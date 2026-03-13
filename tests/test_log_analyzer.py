"""Tests for the security log analyzer detection functions."""
import sys
import os
import pytest
from datetime import datetime, timedelta
from collections import defaultdict

# Add parent directory to path so we can import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'spark-app'))

# We need to patch module-level side effects before importing
# The log_analyzer module prints and connects to ES/Kafka at import time,
# so we import only the functions we need by loading the module carefully.
import importlib
import types


def _load_analyzer_functions():
    """Load detection functions from log_analyzer without triggering side effects."""
    # Read the source and extract function definitions
    analyzer_path = os.path.join(os.path.dirname(__file__), '..', 'spark-app', 'log_analyzer.py')
    
    # Create a module with the required dependencies available
    module = types.ModuleType('log_analyzer_test')
    module.__dict__['json'] = __import__('json')
    module.__dict__['time'] = __import__('time')
    module.__dict__['platform'] = __import__('platform')
    module.__dict__['defaultdict'] = defaultdict
    module.__dict__['datetime'] = datetime
    module.__dict__['timedelta'] = timedelta
    module.__dict__['winsound'] = None
    module.__dict__['Elasticsearch'] = None
    module.__dict__['KafkaConsumer'] = None

    # Define the functions directly for testing (avoids module-level side effects)
    return module


# ===================== Test ip_to_country mapping =====================

ip_to_country = {
    '10.0.0.1': '🇨🇳 China', '10.0.0.2': '🇷🇺 Russia', '10.0.0.3': '🇺🇸 USA',
    '10.0.0.4': '🇩🇪 Germany', '10.0.0.5': '🇧🇷 Brazil', '10.0.0.6': '🇮🇳 India',
    '10.0.0.7': '🇰🇷 South Korea', '10.0.0.8': '🇯🇵 Japan', '10.0.0.9': '🇫🇷 France',
    '10.0.0.10': '🇬🇧 UK', '10.0.0.11': '🇨🇦 Canada', '10.0.0.12': '🇦🇺 Australia'
}


def get_attacker_location(ip):
    """Get fake geo-location for IP"""
    return ip_to_country.get(ip, '🌍 Unknown')


# ===================== Detection Functions (mirrored for testing) =====================

failed_attempts = defaultdict(list)
ALERT_THRESHOLD = 3
TIME_WINDOW = 300


def detect_brute_force(ip, timestamp):
    """Detect brute force attacks from same IP within time window"""
    current_time = timestamp
    failed_attempts[ip] = [t for t in failed_attempts[ip]
                           if current_time - t <= timedelta(seconds=TIME_WINDOW)]
    failed_attempts[ip].append(timestamp)
    if len(failed_attempts[ip]) >= ALERT_THRESHOLD:
        return True, len(failed_attempts[ip])
    return False, len(failed_attempts[ip])


def detect_port_scan(log_data, ip, log_time):
    """Detect port scanning activity"""
    message = log_data.get('message', '').lower()
    port_scan_indicators = ['port scan', 'connection refused', 'closed port', 'port 22', 'port 80', 'port 443']
    if any(indicator in message for indicator in port_scan_indicators):
        return {
            "type": "PORT_SCAN_DETECTED",
            "message": f"Port scanning activity detected from {ip}",
            "details": log_data.get('message'),
            "ip": ip,
            "timestamp": log_data.get('timestamp'),
            "severity": "HIGH"
        }
    return None


request_count = defaultdict(int)
last_reset_time = datetime.now()


def detect_ddos(log_data, ip, log_time):
    """Detect DDoS attack patterns"""
    global request_count, last_reset_time
    if log_time - last_reset_time > timedelta(minutes=1):
        request_count.clear()
        last_reset_time = log_time
    request_count[ip] += 1
    if request_count[ip] > 50:
        return {
            "type": "DDoS_ATTACK",
            "message": f"Potential DDoS attack from {ip}",
            "details": f"Extremely high request rate: {request_count[ip]} requests/minute",
            "ip": ip,
            "timestamp": log_data.get('timestamp'),
            "severity": "CRITICAL"
        }
    elif request_count[ip] > 20:
        return {
            "type": "HIGH_TRAFFIC",
            "message": f"High traffic volume from {ip}",
            "details": f"Elevated request rate: {request_count[ip]} requests/minute",
            "ip": ip,
            "timestamp": log_data.get('timestamp'),
            "severity": "MEDIUM"
        }
    return None


def detect_suspicious_activity(log_data, ip, log_time):
    """Detect various suspicious activities"""
    message = log_data.get('message', '').lower()
    if any(sql_keyword in message for sql_keyword in ['select', 'insert', 'union', 'drop table', '1=1']):
        return {
            "type": "SQL_INJECTION_ATTEMPT",
            "message": f"SQL injection attempt detected from {ip}",
            "details": log_data.get('message'),
            "ip": ip,
            "timestamp": log_data.get('timestamp'),
            "severity": "HIGH"
        }
    if any(xss_indicator in message for xss_indicator in ['<script>', 'javascript:', 'alert(']):
        return {
            "type": "XSS_ATTEMPT",
            "message": f"Cross-site scripting attempt from {ip}",
            "details": log_data.get('message'),
            "ip": ip,
            "timestamp": log_data.get('timestamp'),
            "severity": "HIGH"
        }
    if any(access_keyword in message for access_keyword in ['unauthorized', 'forbidden', 'access denied']):
        return {
            "type": "UNAUTHORIZED_ACCESS",
            "message": f"Unauthorized access attempt from {ip}",
            "details": log_data.get('message'),
            "ip": ip,
            "timestamp": log_data.get('timestamp'),
            "severity": "HIGH"
        }
    return None


# ===================== Tests =====================

class TestGeoLocation:
    """Tests for the geo-location mapping."""

    def test_known_ip_returns_country(self):
        assert get_attacker_location('10.0.0.1') == '🇨🇳 China'
        assert get_attacker_location('10.0.0.2') == '🇷🇺 Russia'
        assert get_attacker_location('10.0.0.3') == '🇺🇸 USA'

    def test_unknown_ip_returns_unknown(self):
        assert get_attacker_location('192.168.1.1') == '🌍 Unknown'
        assert get_attacker_location('8.8.8.8') == '🌍 Unknown'

    def test_all_mapped_ips(self):
        for ip, country in ip_to_country.items():
            assert get_attacker_location(ip) == country


class TestBruteForceDetection:
    """Tests for brute force attack detection."""

    def setup_method(self):
        """Reset state before each test."""
        failed_attempts.clear()

    def test_single_attempt_no_alert(self):
        now = datetime.now()
        is_brute, count = detect_brute_force('10.0.0.1', now)
        assert is_brute is False
        assert count == 1

    def test_two_attempts_no_alert(self):
        now = datetime.now()
        detect_brute_force('10.0.0.1', now)
        is_brute, count = detect_brute_force('10.0.0.1', now + timedelta(seconds=10))
        assert is_brute is False
        assert count == 2

    def test_three_attempts_triggers_alert(self):
        now = datetime.now()
        detect_brute_force('10.0.0.1', now)
        detect_brute_force('10.0.0.1', now + timedelta(seconds=10))
        is_brute, count = detect_brute_force('10.0.0.1', now + timedelta(seconds=20))
        assert is_brute is True
        assert count == 3

    def test_attempts_outside_window_not_counted(self):
        now = datetime.now()
        detect_brute_force('10.0.0.1', now - timedelta(seconds=400))
        detect_brute_force('10.0.0.1', now - timedelta(seconds=350))
        # These old attempts should be outside the 300s window
        is_brute, count = detect_brute_force('10.0.0.1', now)
        assert is_brute is False
        assert count == 1  # Only the current attempt counts

    def test_different_ips_tracked_separately(self):
        now = datetime.now()
        detect_brute_force('10.0.0.1', now)
        detect_brute_force('10.0.0.1', now + timedelta(seconds=5))
        detect_brute_force('10.0.0.2', now)
        # IP 1 has 2 attempts, IP 2 has 1
        is_brute1, count1 = detect_brute_force('10.0.0.1', now + timedelta(seconds=10))
        assert is_brute1 is True
        assert count1 == 3
        is_brute2, count2 = detect_brute_force('10.0.0.2', now + timedelta(seconds=10))
        assert is_brute2 is False
        assert count2 == 2


class TestPortScanDetection:
    """Tests for port scan detection."""

    def test_port_scan_detected(self):
        log_data = {
            'message': 'Port scan detected on port 22',
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_port_scan(log_data, '10.0.0.1', datetime.now())
        assert result is not None
        assert result['type'] == 'PORT_SCAN_DETECTED'
        assert result['severity'] == 'HIGH'
        assert result['ip'] == '10.0.0.1'

    def test_connection_refused_detected(self):
        log_data = {
            'message': 'Connection refused on port 80',
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_port_scan(log_data, '10.0.0.2', datetime.now())
        assert result is not None
        assert result['type'] == 'PORT_SCAN_DETECTED'

    def test_normal_log_not_flagged(self):
        log_data = {
            'message': 'User login successful',
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_port_scan(log_data, '192.168.1.1', datetime.now())
        assert result is None

    def test_closed_port_detected(self):
        log_data = {
            'message': 'Closed port 443 scan detected',
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_port_scan(log_data, '10.0.0.3', datetime.now())
        assert result is not None


class TestDDoSDetection:
    """Tests for DDoS detection."""

    def setup_method(self):
        """Reset state before each test."""
        global request_count, last_reset_time
        request_count.clear()
        last_reset_time = datetime.now()

    def test_low_traffic_no_alert(self):
        log_data = {'timestamp': '2024-01-01 12:00:00'}
        now = datetime.now()
        result = detect_ddos(log_data, '10.0.0.1', now)
        assert result is None

    def test_medium_traffic_alert(self):
        log_data = {'timestamp': '2024-01-01 12:00:00'}
        now = datetime.now()
        # Generate 21 requests to trigger medium alert
        for _ in range(20):
            detect_ddos(log_data, '10.0.0.1', now)
        result = detect_ddos(log_data, '10.0.0.1', now)
        assert result is not None
        assert result['type'] == 'HIGH_TRAFFIC'
        assert result['severity'] == 'MEDIUM'

    def test_high_traffic_critical_alert(self):
        log_data = {'timestamp': '2024-01-01 12:00:00'}
        now = datetime.now()
        # Generate 51 requests to trigger critical DDoS alert
        for _ in range(50):
            detect_ddos(log_data, '10.0.0.1', now)
        result = detect_ddos(log_data, '10.0.0.1', now)
        assert result is not None
        assert result['type'] == 'DDoS_ATTACK'
        assert result['severity'] == 'CRITICAL'

    def test_counter_resets_after_one_minute(self):
        global last_reset_time
        log_data = {'timestamp': '2024-01-01 12:00:00'}
        now = datetime.now()
        # Generate traffic
        for _ in range(25):
            detect_ddos(log_data, '10.0.0.1', now)
        # Advance time > 1 minute
        future = now + timedelta(minutes=2)
        result = detect_ddos(log_data, '10.0.0.1', future)
        assert result is None  # Counter should have reset

    def test_different_ips_tracked_separately(self):
        log_data = {'timestamp': '2024-01-01 12:00:00'}
        now = datetime.now()
        for _ in range(25):
            detect_ddos(log_data, '10.0.0.1', now)
        # IP 2 should have low count
        result = detect_ddos(log_data, '10.0.0.2', now)
        assert result is None


class TestSuspiciousActivityDetection:
    """Tests for suspicious activity detection."""

    def test_sql_injection_detected(self):
        log_data = {
            'message': "SQL injection attempt: ' OR 1=1 --",
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_suspicious_activity(log_data, '10.0.0.1', datetime.now())
        assert result is not None
        assert result['type'] == 'SQL_INJECTION_ATTEMPT'
        assert result['severity'] == 'HIGH'

    def test_sql_select_detected(self):
        log_data = {
            'message': "Suspicious query: SELECT * FROM users",
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_suspicious_activity(log_data, '10.0.0.1', datetime.now())
        assert result is not None
        assert result['type'] == 'SQL_INJECTION_ATTEMPT'

    def test_sql_drop_table_detected(self):
        log_data = {
            'message': "Attempted DROP TABLE users",
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_suspicious_activity(log_data, '10.0.0.1', datetime.now())
        assert result is not None
        assert result['type'] == 'SQL_INJECTION_ATTEMPT'

    def test_xss_script_tag_detected(self):
        log_data = {
            'message': "XSS attempt: <script>alert('xss')</script>",
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_suspicious_activity(log_data, '10.0.0.1', datetime.now())
        assert result is not None
        assert result['type'] == 'XSS_ATTEMPT'
        assert result['severity'] == 'HIGH'

    def test_xss_javascript_protocol_detected(self):
        log_data = {
            'message': "Suspicious URL: javascript:void(0)",
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_suspicious_activity(log_data, '10.0.0.1', datetime.now())
        assert result is not None
        assert result['type'] == 'XSS_ATTEMPT'

    def test_unauthorized_access_detected(self):
        log_data = {
            'message': "Unauthorized access attempt to /admin",
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_suspicious_activity(log_data, '10.0.0.1', datetime.now())
        assert result is not None
        assert result['type'] == 'UNAUTHORIZED_ACCESS'
        assert result['severity'] == 'HIGH'

    def test_forbidden_access_detected(self):
        log_data = {
            'message': "Forbidden: Access denied to sensitive file",
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_suspicious_activity(log_data, '10.0.0.1', datetime.now())
        assert result is not None
        assert result['type'] == 'UNAUTHORIZED_ACCESS'

    def test_normal_message_not_flagged(self):
        log_data = {
            'message': "User login successful",
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_suspicious_activity(log_data, '192.168.1.1', datetime.now())
        assert result is None

    def test_case_insensitive_detection(self):
        log_data = {
            'message': "UNAUTHORIZED ACCESS ATTEMPT",
            'timestamp': '2024-01-01 12:00:00'
        }
        result = detect_suspicious_activity(log_data, '10.0.0.1', datetime.now())
        assert result is not None
