"""Tests for the web dashboard Flask application."""
import sys
import os
import pytest
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'web-dashboard'))

from app import app


@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


class TestDashboardRoute:
    """Tests for the main dashboard page."""

    def test_dashboard_returns_200(self, client):
        """Test that the dashboard page loads successfully."""
        response = client.get('/')
        assert response.status_code == 200

    def test_dashboard_contains_title(self, client):
        """Test that the dashboard contains the expected title."""
        response = client.get('/')
        assert b'SECURITY OPERATIONS CENTER' in response.data


class TestAlertsAPI:
    """Tests for the /api/alerts endpoint."""

    @patch('app.get_es_connection')
    def test_alerts_returns_json(self, mock_es_conn, client):
        """Test that alerts endpoint returns JSON."""
        mock_es_conn.return_value = None
        response = client.get('/api/alerts')
        assert response.status_code == 200
        assert response.content_type == 'application/json'

    @patch('app.get_es_connection')
    def test_alerts_without_elasticsearch(self, mock_es_conn, client):
        """Test alerts endpoint when Elasticsearch is not available."""
        mock_es_conn.return_value = None
        response = client.get('/api/alerts')
        data = response.get_json()
        assert 'error' in data
        assert data['error'] == 'Elasticsearch not available'

    @patch('app.get_es_connection')
    def test_alerts_with_elasticsearch(self, mock_es_conn, client):
        """Test alerts endpoint with mocked Elasticsearch data."""
        mock_es = MagicMock()
        mock_es.search.return_value = {
            'hits': {
                'hits': [
                    {
                        '_id': 'test-id-1',
                        '_source': {
                            'alert_type': 'BRUTE_FORCE_ATTACK',
                            'message': 'Brute force attack detected',
                            'severity': 'CRITICAL',
                            'source_ip': '10.0.0.1',
                            'timestamp': '2024-01-01 12:00:00'
                        }
                    }
                ]
            }
        }
        mock_es_conn.return_value = mock_es
        response = client.get('/api/alerts')
        data = response.get_json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]['alert_type'] == 'BRUTE_FORCE_ATTACK'
        assert data[0]['id'] == 'test-id-1'


class TestStatsAPI:
    """Tests for the /api/stats endpoint."""

    @patch('app.get_es_connection')
    def test_stats_without_elasticsearch(self, mock_es_conn, client):
        """Test stats endpoint when Elasticsearch is not available."""
        mock_es_conn.return_value = None
        response = client.get('/api/stats')
        data = response.get_json()
        assert data['total_alerts'] == 0
        assert data['by_severity'] == {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0}
        assert data['by_country'] == {}
        assert data['by_type'] == {}

    @patch('app.get_es_connection')
    def test_stats_returns_json(self, mock_es_conn, client):
        """Test that stats endpoint returns JSON."""
        mock_es_conn.return_value = None
        response = client.get('/api/stats')
        assert response.status_code == 200
        assert response.content_type == 'application/json'


class TestRecentAttacksAPI:
    """Tests for the /api/recent-attacks endpoint."""

    @patch('app.get_es_connection')
    def test_recent_attacks_without_elasticsearch(self, mock_es_conn, client):
        """Test recent attacks endpoint when Elasticsearch is not available."""
        mock_es_conn.return_value = None
        response = client.get('/api/recent-attacks')
        data = response.get_json()
        assert data == []

    @patch('app.get_es_connection')
    def test_recent_attacks_returns_json(self, mock_es_conn, client):
        """Test that recent attacks endpoint returns JSON."""
        mock_es_conn.return_value = None
        response = client.get('/api/recent-attacks')
        assert response.status_code == 200
        assert response.content_type == 'application/json'

    @patch('app.get_es_connection')
    def test_recent_attacks_with_data(self, mock_es_conn, client):
        """Test recent attacks endpoint with mocked data."""
        mock_es = MagicMock()
        mock_es.search.return_value = {
            'hits': {
                'hits': [
                    {
                        '_id': 'attack-1',
                        '_source': {
                            'alert_type': 'DDoS_ATTACK',
                            'message': 'DDoS attack from 10.0.0.1',
                            'severity': 'CRITICAL',
                            'source_ip': '10.0.0.1',
                            'timestamp': '2024-01-01 12:00:00',
                            'country': '🇨🇳 China'
                        }
                    }
                ]
            }
        }
        mock_es_conn.return_value = mock_es
        response = client.get('/api/recent-attacks')
        data = response.get_json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]['alert_type'] == 'DDoS_ATTACK'
