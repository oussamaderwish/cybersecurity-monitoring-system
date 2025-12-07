from flask import Flask, render_template, jsonify
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import json

app = Flask(__name__)

print("=" * 80)
print("🚀 STARTING SECURITY DASHBOARD WEB INTERFACE")
print("=" * 80)
print("🌐 Dashboard will be available at: http://localhost:5000")
print("📊 Displaying: Real-time security alerts from Elasticsearch")
print("🎯 Features: Live alerts, Threat statistics, Geo-location map")
print("=" * 80)

def get_es_connection():
    """Connect to Elasticsearch"""
    try:
        es = Elasticsearch(['http://localhost:9200'], timeout=30)
        if es.ping():
            return es
        return None
    except:
        return None

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/alerts')
def get_alerts():
    """Get recent security alerts from Elasticsearch"""
    es = get_es_connection()
    
    if not es:
        return jsonify({"error": "Elasticsearch not available"})
    
    try:
        # Get last 50 alerts
        result = es.search(
            index="security-alerts",
            body={
                "size": 50,
                "sort": [{"timestamp": "desc"}],
                "query": {"match_all": {}}
            }
        )
        
        alerts = []
        for hit in result['hits']['hits']:
            alert = hit['_source']
            alert['id'] = hit['_id']
            alerts.append(alert)
        
        return jsonify(alerts)
    
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/stats')
def get_stats():
    """Get security statistics"""
    es = get_es_connection()
    
    if not es:
        return jsonify({
            "total_alerts": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0},
            "by_country": {},
            "by_type": {}
        })
    
    try:
        # Total alerts count
        total_result = es.count(index="security-alerts")
        total_alerts = total_result['count']
        
        # Alerts by severity
        severity_agg = es.search(
            index="security-alerts",
            body={
                "size": 0,
                "aggs": {
                    "by_severity": {
                        "terms": {"field": "severity.keyword"}
                    }
                }
            }
        )
        
        severity_stats = {}
        for bucket in severity_agg['aggregations']['by_severity']['buckets']:
            severity_stats[bucket['key']] = bucket['doc_count']
        
        # Alerts by country
        country_agg = es.search(
            index="security-alerts", 
            body={
                "size": 0,
                "aggs": {
                    "by_country": {
                        "terms": {"field": "country.keyword"}
                    }
                }
            }
        )
        
        country_stats = {}
        for bucket in country_agg['aggregations']['by_country']['buckets']:
            country_stats[bucket['key']] = bucket['doc_count']
        
        # Alerts by type
        type_agg = es.search(
            index="security-alerts",
            body={
                "size": 0,
                "aggs": {
                    "by_type": {
                        "terms": {"field": "alert_type.keyword"}
                    }
                }
            }
        )
        
        type_stats = {}
        for bucket in type_agg['aggregations']['by_type']['buckets']:
            type_stats[bucket['key']] = bucket['doc_count']
        
        return jsonify({
            "total_alerts": total_alerts,
            "by_severity": severity_stats,
            "by_country": country_stats,
            "by_type": type_stats
        })
    
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/api/recent-attacks')
def recent_attacks():
    """Get recent attack patterns"""
    es = get_es_connection()
    
    if not es:
        return jsonify([])
    
    try:
        # Get attacks from last 1 hour
        one_hour_ago = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        
        result = es.search(
            index="security-alerts",
            body={
                "size": 20,
                "sort": [{"timestamp": "desc"}],
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": one_hour_ago
                        }
                    }
                }
            }
        )
        
        attacks = []
        for hit in result['hits']['hits']:
            attack = hit['_source']
            attack['id'] = hit['_id']
            attacks.append(attack)
        
        return jsonify(attacks)
    
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    print("🎯 Starting Flask web server...")
    app.run(debug=True, host='0.0.0.0', port=5000)