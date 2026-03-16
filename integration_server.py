"""
Integration Server - REST API + WebSocket
Connects all firewall components
Version: 2.0
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import time
import numpy as np
from datetime import datetime
from collections import deque

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")


class FirewallServer:
    def __init__(self):
        self.is_running = False
        self.stats = {
            'total_packets': 0,
            'blocked_packets': 0,
            'threats_detected': 0,
            'anomalies_detected': 0,
            'start_time': None
        }
        self.alerts = deque(maxlen=100)
        self.traffic_history = deque(maxlen=60)
        self.blocked_ips = set()
        self.whitelist_ips = set()
        self.monitor_thread = None
    
    def start_monitoring(self):
        if self.is_running:
            return {"success": False, "message": "Already running"}
        
        self.is_running = True
        self.stats['start_time'] = datetime.now().isoformat()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        return {"success": True, "message": "Started"}
    
    def stop_monitoring(self):
        self.is_running = False
        return {"success": True, "message": "Stopped"}
    
    def _monitor_loop(self):
        while self.is_running:
            try:
                self._simulate_traffic()
                socketio.emit('stats_update', self.get_stats())
                
                if np.random.random() > 0.7:
                    alert = self._generate_alert()
                    self.alerts.appendleft(alert)
                    socketio.emit('new_alert', alert)
                
                time.sleep(1)
            except Exception as e:
                print(f"[!] Error: {e}")
    
    def _simulate_traffic(self):
        pkts = np.random.randint(10, 50)
        blkd = np.random.randint(0, 5)
        
        self.stats['total_packets'] += pkts
        self.stats['blocked_packets'] += blkd
        
        if np.random.random() > 0.8:
            self.stats['threats_detected'] += 1
        if np.random.random() > 0.9:
            self.stats['anomalies_detected'] += 1
        
        self.traffic_history.append({
            'timestamp': datetime.now().isoformat(),
            'allowed': pkts - blkd,
            'blocked': blkd
        })
    
    def _generate_alert(self):
        threats = ['SQL_INJECTION', 'XSS', 'NETWORK_ANOMALY', 'RATE_LIMIT', 'PORT_SCAN']
        ips = ['203.0.113.50', '198.51.100.25', '192.0.2.100']
        
        return {
            'id': int(time.time() * 1000),
            'timestamp': datetime.now().isoformat(),
            'src_ip': str(np.random.choice(ips)),
            'dst_ip': '10.0.0.1',
            'threat_type': str(np.random.choice(threats)),
            'severity': str(np.random.choice(['HIGH', 'MEDIUM', 'LOW'], p=[0.3, 0.5, 0.2])),
            'action': 'BLOCKED'
        }
    
    def get_stats(self):
        uptime = None
        if self.stats['start_time']:
            start = datetime.fromisoformat(self.stats['start_time'])
            uptime = (datetime.now() - start).total_seconds()
        
        block_rate = 0
        if self.stats['total_packets'] > 0:
            block_rate = (self.stats['blocked_packets'] / self.stats['total_packets']) * 100
        
        return {
            'stats': self.stats,
            'block_rate': round(block_rate, 2),
            'uptime': uptime,
            'is_running': self.is_running
        }
    
    def get_alerts(self, limit=50):
        return list(self.alerts)[:limit]
    
    def get_traffic_history(self):
        return list(self.traffic_history)
    
    def block_ip(self, ip):
        self.blocked_ips.add(ip)
        return {"success": True, "message": f"Blocked {ip}"}
    
    def whitelist_ip(self, ip):
        self.whitelist_ips.add(ip)
        return {"success": True, "message": f"Whitelisted {ip}"}
    
    def get_threat_distribution(self):
        threat_counts = {}
        for alert in self.alerts:
            t = alert['threat_type']
            threat_counts[t] = threat_counts.get(t, 0) + 1
        return [{'name': k, 'value': v} for k, v in threat_counts.items()]


server = FirewallServer()


# ═══ REST API ═══════════════════════════════════════════════

@app.route('/')
def index():
    return jsonify({
        'name': 'AI Firewall API v2.0',
        'status': 'running',
        'endpoints': {
            'GET /api/status': 'Status',
            'GET /api/stats': 'Statistics',
            'GET /api/alerts': 'Alerts',
            'POST /api/start': 'Start monitoring',
            'POST /api/stop': 'Stop monitoring'
        }
    })

@app.route('/api/status')
def get_status():
    return jsonify({
        'is_running': server.is_running,
        'uptime': server.get_stats().get('uptime'),
        'blocked_ips': list(server.blocked_ips)
    })

@app.route('/api/stats')
def get_statistics():
    return jsonify(server.get_stats())

@app.route('/api/alerts')
def get_alerts():
    limit = request.args.get('limit', 50, type=int)
    return jsonify({
        'alerts': server.get_alerts(limit),
        'total': len(server.alerts)
    })

@app.route('/api/traffic')
def get_traffic():
    return jsonify({'traffic': server.get_traffic_history()})

@app.route('/api/threats')
def get_threats():
    return jsonify({'distribution': server.get_threat_distribution()})

@app.route('/api/start', methods=['POST'])
def start_monitoring():
    return jsonify(server.start_monitoring())

@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    return jsonify(server.stop_monitoring())

@app.route('/api/block', methods=['POST'])
def block_ip():
    data = request.json
    ip = data.get('ip') if data else None
    if not ip:
        return jsonify({'success': False, 'message': 'IP required'}), 400
    return jsonify(server.block_ip(ip))

@app.route('/api/whitelist', methods=['POST'])
def whitelist_ip():
    data = request.json
    ip = data.get('ip') if data else None
    if not ip:
        return jsonify({'success': False, 'message': 'IP required'}), 400
    return jsonify(server.whitelist_ip(ip))


# ═══ WebSocket ══════════════════════════════════════════════

@socketio.on('connect')
def handle_connect():
    print('[*] Client connected')
    emit('connection_response', {'status': 'connected'})
    emit('stats_update', server.get_stats())

@socketio.on('disconnect')
def handle_disconnect():
    print('[*] Client disconnected')

@socketio.on('start_monitoring')
def handle_start():
    emit('monitoring_status', server.start_monitoring(), broadcast=True)

@socketio.on('stop_monitoring')
def handle_stop():
    emit('monitoring_status', server.stop_monitoring(), broadcast=True)


# ═══ MAIN ═══════════════════════════════════════════════════

if __name__ == '__main__':
    print("="*60)
    print("🛡️  AI Firewall - Integration Server v2.0")
    print("="*60)
    print("\n  API:  http://localhost:5000")
    print("  WS:   ws://localhost:5000/socket.io")
    print("\nEndpoints:")
    print("  GET  /api/status | /api/stats | /api/alerts")
    print("  POST /api/start  | /api/stop  | /api/block")
    print("="*60 + "\n")
    
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n[*] Server stopped")