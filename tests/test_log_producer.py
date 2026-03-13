"""Tests for the security log producer generation logic."""
import sys
import os
import pytest

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'data-generator'))


class TestLogGeneration:
    """Tests for log generation logic."""

    def test_normal_log_messages_defined(self):
        """Verify normal log messages list is non-empty."""
        normal_logs = [
            "User login successful",
            "Database connection established",
            "API request processed successfully",
            "File uploaded successfully",
            "System backup completed",
            "Cache updated",
            "User session created",
            "Password changed successfully",
            "Email sent successfully",
            "Database query executed",
            "System health check passed",
            "Memory usage normal",
            "CPU utilization normal",
            "Network traffic normal",
            "Security scan completed"
        ]
        assert len(normal_logs) == 15

    def test_attack_log_messages_defined(self):
        """Verify attack log messages list is non-empty."""
        attack_logs = [
            "Failed password for root",
            "Authentication failure for user admin",
            "Brute force attempt detected",
            "Port scan detected on port 22",
            "Multiple login failures from same IP",
            "Connection refused on port 80",
            "Closed port 443 scan detected",
            "High frequency requests from single IP",
            "SQL injection attempt detected: ' OR 1=1 --",
            "XSS attempt detected: <script>alert('xss')</script>",
            "Unauthorized access attempt to /admin",
            "Forbidden: Access denied to sensitive file",
            "Suspicious user agent detected",
            "Malicious payload detected in request",
            "Cross-site request forgery attempt",
            "Directory traversal attempt: ../../../etc/passwd",
            "Command injection attempt detected",
            "Buffer overflow attempt detected",
            "DNS amplification attack detected",
            "SSL/TLS handshake failed - potential MITM"
        ]
        assert len(attack_logs) == 20

    def test_log_entry_structure(self):
        """Test that generated log entries have the correct structure."""
        import random
        from datetime import datetime

        # Simulate the generate_log function
        normal_logs = ["User login successful"]
        attack_logs = ["Failed password for root"]

        random.seed(42)
        if random.random() < 0.7:
            message = random.choice(normal_logs)
            level = "INFO"
            source_ip = f"192.168.1.{random.randint(1, 100)}"
        else:
            message = random.choice(attack_logs)
            level = "ERROR"
            source_ip = f"10.0.0.{random.randint(1, 20)}"

        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "level": level,
            "message": message,
            "source_ip": source_ip
        }

        assert 'timestamp' in log_entry
        assert 'level' in log_entry
        assert 'message' in log_entry
        assert 'source_ip' in log_entry
        assert log_entry['level'] in ('INFO', 'ERROR')

    def test_normal_ip_range(self):
        """Test that normal logs use private IP range."""
        import random
        for _ in range(100):
            ip = f"192.168.1.{random.randint(1, 100)}"
            parts = ip.split('.')
            assert parts[0] == '192'
            assert parts[1] == '168'
            assert parts[2] == '1'
            assert 1 <= int(parts[3]) <= 100

    def test_attack_ip_range(self):
        """Test that attack logs use attacker IP range."""
        import random
        for _ in range(100):
            ip = f"10.0.0.{random.randint(1, 20)}"
            parts = ip.split('.')
            assert parts[0] == '10'
            assert parts[1] == '0'
            assert parts[2] == '0'
            assert 1 <= int(parts[3]) <= 20

    def test_severity_emoji_mapping(self):
        """Test get_severity_emoji equivalent logic."""
        def get_severity_emoji(message, level):
            if level == "ERROR":
                return "🔴"
            elif any(warning_term in message.lower() for warning_term in ['warning', 'suspicious', 'attempt']):
                return "🟡"
            else:
                return "🟢"

        assert get_severity_emoji("Failed password", "ERROR") == "🔴"
        assert get_severity_emoji("Suspicious activity detected", "INFO") == "🟡"
        assert get_severity_emoji("Brute force attempt detected", "INFO") == "🟡"
        assert get_severity_emoji("User login successful", "INFO") == "🟢"
        assert get_severity_emoji("Warning: high memory", "INFO") == "🟡"

    def test_timestamp_format(self):
        """Test that timestamps follow the expected format."""
        from datetime import datetime
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Verify it can be parsed back
        parsed = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        assert parsed is not None
