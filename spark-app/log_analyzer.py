import json
import time
import winsound  # Built-in Windows library - NO INSTALL NEEDED
from kafka import KafkaConsumer
from collections import defaultdict
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

# ==================== ADD COLOR CLASS ====================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'

print("=" * 100)
print("🚀 SUPER-CHARGED REAL-TIME SECURITY MONITORING SYSTEM")
print("=" * 100)
print("📡 Monitoring: Kafka Topic 'security-logs'")
print("🎯 Detecting: Brute Force, Port Scanning, DDoS Attacks & More")
print("💾 Storing: All alerts in Elasticsearch for Kibana Dashboard")
print("🔔 Features: Sound Alerts, Color-coded Output, Live Stats, Geo-location")
print("⏹️  Press Ctrl+C to stop monitoring")
print("=" * 100)

# ==================== ENHANCEMENT: GEO-LOCATION DATA ====================
ip_to_country = {
    '10.0.0.1': '🇨🇳 China', '10.0.0.2': '🇷🇺 Russia', '10.0.0.3': '🇺🇸 USA',
    '10.0.0.4': '🇩🇪 Germany', '10.0.0.5': '🇧🇷 Brazil', '10.0.0.6': '🇮🇳 India',
    '10.0.0.7': '🇰🇷 South Korea', '10.0.0.8': '🇯🇵 Japan', '10.0.0.9': '🇫🇷 France',
    '10.0.0.10': '🇬🇧 UK', '10.0.0.11': '🇨🇦 Canada', '10.0.0.12': '🇦🇺 Australia'
}

# Connect to Elasticsearch with compatible settings
try:
    es = Elasticsearch(
        ['http://localhost:9200'],
        timeout=30,
        max_retries=3,
        retry_on_timeout=True
    )
    
    # Test connection
    if es.ping():
        print(f"{Colors.GREEN}✅ Connected to Elasticsearch successfully!{Colors.END}")
        
        # Create index if it doesn't exist
        if not es.indices.exists(index="security-alerts"):
            # Create index with proper mapping
            index_body = {
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"},
                        "alert_type": {"type": "keyword"},
                        "message": {"type": "text"},
                        "details": {"type": "text"},
                        "source_ip": {"type": "ip"},
                        "severity": {"type": "keyword"},
                        "processed_at": {"type": "date"},
                        "country": {"type": "keyword"}  # Added for geo-location
                    }
                }
            }
            es.indices.create(index="security-alerts", body=index_body)
            print(f"{Colors.GREEN}✅ Created 'security-alerts' index with enhanced mapping{Colors.END}")
        else:
            print(f"{Colors.GREEN}✅ 'security-alerts' index already exists{Colors.END}")
    else:
        print(f"{Colors.RED}❌ Cannot connect to Elasticsearch{Colors.END}")
        es = None
        
except Exception as e:
    print(f"{Colors.RED}❌ Elasticsearch connection failed: {e}{Colors.END}")
    print(f"{Colors.YELLOW}💡 Starting in monitoring-only mode (alerts won't be saved){Colors.END}")
    es = None

# Track failed login attempts per IP (for brute force detection)
failed_attempts = defaultdict(list)
ALERT_THRESHOLD = 3  # Alert after 3 failed attempts
TIME_WINDOW = 300    # 5 minutes in seconds

# DDoS tracking
request_count = defaultdict(int)
last_reset_time = datetime.now()

# ==================== ENHANCEMENT: SOUND ALERTS ====================
def play_alert_sound(alert):
    """Play sound for critical alerts"""
    if alert['severity'] == 'CRITICAL':
        try:
            winsound.PlaySound("SystemExclamation", winsound.SND_ALIAS)
            print(f"    {Colors.RED}🔔 CRITICAL ALERT SOUND PLAYED!{Colors.END}")
        except:
            print(f"    {Colors.YELLOW}🔔 Sound alert (simulated){Colors.END}")

# ==================== ENHANCEMENT: GEO-LOCATION ====================
def get_attacker_location(ip):
    """Get fake geo-location for IP"""
    return ip_to_country.get(ip, '🌍 Unknown')

# ==================== ENHANCEMENT: LIVE STATS ====================
def display_live_stats(message_count, alert_count, start_time):
    """Show live statistics"""
    elapsed = time.time() - start_time
    stats = f"{Colors.CYAN}📊 LIVE: {message_count} logs | {alert_count} threats | {elapsed:.0f}s{Colors.END}"
    print(f"\r{stats}", end="", flush=True)

# ==================== EXISTING DETECTION FUNCTIONS (Keep as-is) ====================
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

def analyze_security_log(log_data):
    """Analyze log entry for security threats"""
    alerts = []
    ip = log_data.get('source_ip')
    
    # Convert string timestamp to datetime object
    try:
        log_time = datetime.strptime(log_data.get('timestamp'), '%Y-%m-%d %H:%M:%S')
    except:
        log_time = datetime.now()
    
    # ==================== ENHANCEMENT: ADD GEO-LOCATION ====================
    country = get_attacker_location(ip)
    
    # 1. Check for ERROR level logs (immediate security alert)
    if log_data.get('level') == 'ERROR':
        alerts.append({
            "type": "SECURITY_ALERT",
            "message": f"High severity security event detected",
            "details": log_data.get('message'),
            "ip": ip,
            "timestamp": log_data.get('timestamp'),
            "severity": "HIGH",
            "country": country  # Added geo-location
        })
    
    # 2. Check for failed login patterns (brute force detection)
    message = log_data.get('message', '')
    is_failed_login = 'Failed password' in message or 'Authentication failure' in message
    
    if is_failed_login:
        is_brute_force, attempt_count = detect_brute_force(ip, log_time)
        
        if is_brute_force:
            alerts.append({
                "type": "BRUTE_FORCE_ATTACK",
                "message": f"Brute force attack detected from IP {ip}",
                "details": f"{attempt_count} failed login attempts in 5 minutes",
                "ip": ip,
                "timestamp": log_data.get('timestamp'),
                "severity": "CRITICAL",
                "country": country  # Added geo-location
            })
        else:
            # Just log the failed attempt (no alert yet)
            print(f"    {Colors.YELLOW}⚠️  Failed login attempt #{attempt_count} from {ip}{Colors.END}")
    
    # 3. Detect port scanning
    port_scan_alert = detect_port_scan(log_data, ip, log_time)
    if port_scan_alert:
        port_scan_alert["country"] = country  # Add geo-location
        alerts.append(port_scan_alert)
    
    # 4. Detect DDoS attacks
    ddos_alert = detect_ddos(log_data, ip, log_time)
    if ddos_alert:
        ddos_alert["country"] = country  # Add geo-location
        alerts.append(ddos_alert)
    
    # 5. Detect suspicious activities
    suspicious_alert = detect_suspicious_activity(log_data, ip, log_time)
    if suspicious_alert:
        suspicious_alert["country"] = country  # Add geo-location
        alerts.append(suspicious_alert)
    
    return alerts

def save_alert_to_elasticsearch(alert):
    """Save alert to Elasticsearch for Kibana dashboard"""
    if es is not None:
        try:
            es.index(
                index="security-alerts",
                body={
                    "alert_type": alert['type'],
                    "message": alert['message'],
                    "details": alert['details'],
                    "source_ip": alert['ip'],
                    "timestamp": alert['timestamp'],
                    "severity": alert.get('severity', 'MEDIUM'),
                    "country": alert.get('country', 'Unknown'),  # Added geo-location
                    "processed_at": datetime.now().isoformat()
                }
            )
            return True
        except Exception as e:
            print(f"    {Colors.RED}❌ Failed to save to Elasticsearch: {e}{Colors.END}")
            return False
    else:
        print(f"    {Colors.YELLOW}ℹ️  Elasticsearch not available - alert not saved{Colors.END}")
        return False

def main():
    try:
        print(f"{Colors.BLUE}🔄 Connecting to Kafka...{Colors.END}")
        
        # Create Kafka consumer
        consumer = KafkaConsumer(
            'security-logs',
            bootstrap_servers='localhost:9092',
            auto_offset_reset='latest',  # Start from latest messages
            value_deserializer=lambda x: json.loads(x.decode('utf-8')),
            consumer_timeout_ms=30000  # Timeout after 30 seconds of no messages
        )

        print(f"{Colors.GREEN}✅ Connected to Kafka successfully!{Colors.END}")
        print(f"{Colors.CYAN}👂 Listening for security logs...{Colors.END}")
        print(f"{Colors.PURPLE}💡 Enhanced features: Sound alerts, Geo-location, Live stats{Colors.END}")
        print("-" * 100)

        message_count = 0
        alert_count = 0
        start_time = time.time()
        
        # Process messages from Kafka
        for message in consumer:
            log_data = message.value
            message_count += 1
            
            # ==================== ENHANCEMENT: LIVE STATS ====================
            display_live_stats(message_count, alert_count, start_time)
            
            # Display the incoming log with colors
            level_color = Colors.RED if log_data['level'] == 'ERROR' else Colors.GREEN
            print(f"\n{Colors.BLUE}📨 [{log_data['timestamp']}]{Colors.END} {level_color}{log_data['level']}{Colors.END} - {log_data['message']}")
            print(f"   {Colors.CYAN}📍 Source IP: {log_data['source_ip']}{Colors.END}")
            
            # Analyze for security threats
            alerts = analyze_security_log(log_data)
            
            # Display any security alerts
            for alert in alerts:
                alert_count += 1
                severity_color = Colors.RED if alert['severity'] == 'CRITICAL' else Colors.YELLOW
                print(f"{severity_color}🚨 ALERT #{alert_count}: {alert['type']}{Colors.END}")
                print(f"   {Colors.CYAN}📢 {alert['message']}{Colors.END}")
                print(f"   {Colors.YELLOW}📋 {alert['details']}{Colors.END}")
                print(f"   {Colors.PURPLE}🌍 {alert.get('country', 'Unknown')}{Colors.END}")  # Geo-location
                print(f"   {Colors.GREEN}🕒 {alert['timestamp']}{Colors.END}")
                print(f"   {severity_color}⚠️  Severity: {alert.get('severity', 'MEDIUM')}{Colors.END}")
                
                # ==================== ENHANCEMENT: SOUND ALERTS ====================
                play_alert_sound(alert)
                
                # Save to Elasticsearch
                if save_alert_to_elasticsearch(alert):
                    print(f"   {Colors.GREEN}💾 Alert saved to Elasticsearch{Colors.END}")
                
                print("   " + "🔴" * 30)
            
            print("-" * 80)

    except KeyboardInterrupt:
        print(f"\n\n{Colors.CYAN}" + "=" * 100)
        print(f"📊 SUPER-CHARGED MONITORING SUMMARY:{Colors.END}")
        print(f"   {Colors.GREEN}📨 Messages processed: {message_count}{Colors.END}")
        print(f"   {Colors.RED}🚨 Security alerts detected: {alert_count}{Colors.END}")
        if es:
            print(f"   {Colors.PURPLE}💾 Alerts stored in Elasticsearch: {alert_count}{Colors.END}")
            print(f"   {Colors.CYAN}🎯 Open Kibana at: http://localhost:5601 to view the dashboard{Colors.END}")
        print(f"   {Colors.YELLOW}🛑 Monitoring stopped by user{Colors.END}")
        print("=" * 100)
        
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.END}")
        print(f"{Colors.YELLOW}💡 Troubleshooting tips:{Colors.END}")
        print("   1. Make sure Docker is running: docker ps")
        print("   2. Check Kafka: docker exec spark-project-kafka-1 kafka-topics --list")
        print("   3. Verify Elasticsearch: http://localhost:9200")

if __name__ == "__main__":
    main()