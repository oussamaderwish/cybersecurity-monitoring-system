from kafka import KafkaProducer
import json
import time
import random
from datetime import datetime

# ==================== ADD COLOR CLASS ====================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'

print("=" * 80)
print("🚀 SUPER-CHARGED SECURITY LOG GENERATOR")
print("=" * 80)
print("📝 Generating: Normal logs + Multiple attack types")
print("🎯 Attacks: Brute Force, Port Scans, DDoS, SQL Injection, XSS")
print("💡 Features: Color-coded output, Live counter, Enhanced visuals")
print("⏹️  Press Ctrl+C to stop generator")
print("=" * 80)

# Create Kafka producer
producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# Enhanced log messages with more variety
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

def generate_log():
    # 70% normal logs, 30% attack logs for more realistic testing
    if random.random() < 0.7:
        message = random.choice(normal_logs)
        level = "INFO"
        # Normal IPs in private range
        source_ip = f"192.168.1.{random.randint(1, 100)}"
    else:
        message = random.choice(attack_logs) 
        level = "ERROR"
        # Attacker IPs in different range
        source_ip = f"10.0.0.{random.randint(1, 20)}"
    
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "level": level,
        "message": message,
        "source_ip": source_ip
    }
    
    return log_entry, level  # Return both log and level

def get_severity_emoji(message, level):
    """Get appropriate emoji based on log severity"""
    if level == "ERROR":
        return "🔴"
    elif any(warning_term in message.lower() for warning_term in ['warning', 'suspicious', 'attempt']):
        return "🟡"
    else:
        return "🟢"

print("Starting enhanced log generator...")
try:
    log_count = 0
    start_time = time.time()
    
    while True:
        log, level = generate_log()  # Now unpack both values
        producer.send('security-logs', log)
        log_count += 1
        
        emoji = get_severity_emoji(log['message'], level)
        level_color = Colors.RED if level == "ERROR" else Colors.GREEN
        
        # Live counter display
        elapsed = time.time() - start_time
        live_stats = f"{Colors.CYAN}[{log_count} logs in {elapsed:.0f}s]{Colors.END}"
        
        print(f"{emoji} {level_color}{log_count:03d}{Colors.END} {level_color}{level}{Colors.END} - {log['message'][:55]}... {Colors.BLUE}(IP: {log['source_ip']}){Colors.END} {live_stats}")
        
        time.sleep(1.5)  # Slightly faster for more data
  
except KeyboardInterrupt:
    print(f"\n{Colors.YELLOW}🛑 Stopping log generator{Colors.END}")
    print(f"{Colors.CYAN}📊 Total logs generated: {log_count}{Colors.END}")
    print(f"{Colors.GREEN}🎯 Start the security analyzer to monitor these logs!{Colors.END}")
    
finally:
    producer.close()