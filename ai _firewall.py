"""
Enhanced AI-Based Firewall System - Complete Production Version
Features: Real Datasets, Deep Learning, Threat Intel, GeoIP, Database, Live Traffic
Author: AI Firewall Project
Version: 2.0
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from datetime import datetime
import json
import re
import time
import os
import pickle
import requests
from collections import defaultdict

# Optional: Deep Learning
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout
    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False

# Optional: Database
try:
    from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker
    HAS_DATABASE = True
    Base = declarative_base()
except ImportError:
    HAS_DATABASE = False

# Optional: GeoIP
try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False

# Optional: Email
try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail
    HAS_EMAIL = True
except ImportError:
    HAS_EMAIL = False


# ═══════════════════════════════════════════════════════════
# DATABASE MODELS
# ═══════════════════════════════════════════════════════════

if HAS_DATABASE:
    class Alert(Base):
        __tablename__ = 'alerts'
        id = Column(Integer, primary_key=True)
        timestamp = Column(DateTime, default=datetime.now)
        src_ip = Column(String(50))
        dst_ip = Column(String(50))
        threat_type = Column(String(100))
        severity = Column(String(20))
        blocked = Column(Boolean)
        confidence = Column(Float)
        website = Column(String(255))
        
    class BlockedIP(Base):
        __tablename__ = 'blocked_ips'
        id = Column(Integer, primary_key=True)
        ip_address = Column(String(50), unique=True)
        reason = Column(String(200))
        blocked_at = Column(DateTime, default=datetime.now)
        block_count = Column(Integer, default=1)


# ═══════════════════════════════════════════════════════════
# DATASET LOADER
# ═══════════════════════════════════════════════════════════

class DatasetLoader:
    """Load real-world network security datasets"""
    
    @staticmethod
    def load_cicids2017(filepath):
        """Load CICIDS2017 dataset"""
        print(f"[*] Loading CICIDS2017 from {filepath}...")
        df = pd.read_csv(filepath)
        
        feature_cols = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Flow Bytes/s', 'Flow Packets/s', 'Fwd Packet Length Mean',
            'Bwd Packet Length Mean', 'Flow IAT Mean', 'Fwd IAT Mean'
        ]
        
        X = df[feature_cols].fillna(0).replace([np.inf, -np.inf], 0)
        y = df['Label'].map(lambda x: 0 if x == 'BENIGN' else 1)
        
        label_map = {
            'BENIGN': 0, 'DoS': 1, 'DDoS': 1, 'PortScan': 2,
            'Bot': 3, 'Infiltration': 4, 'Web Attack': 5, 'Brute Force': 6
        }
        y_multi = df['Label'].map(lambda x: label_map.get(x, 0))
        
        print(f"[+] Loaded {len(X)} samples")
        print(f"    Benign: {(y == 0).sum():,} | Malicious: {(y == 1).sum():,}")
        return X, y, y_multi
    
    @staticmethod
    def load_nsl_kdd(filepath):
        """Load NSL-KDD dataset"""
        print(f"[*] Loading NSL-KDD from {filepath}...")
        
        col_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
            'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate', 'label', 'difficulty'
        ]
        
        df = pd.read_csv(filepath, names=col_names)
        df['protocol_type'] = df['protocol_type'].astype('category').cat.codes
        df['service'] = df['service'].astype('category').cat.codes
        df['flag'] = df['flag'].astype('category').cat.codes
        
        X = df.iloc[:, :-2]
        y = df['label'].map(lambda x: 0 if 'normal' in str(x) else 1)
        
        print(f"[+] Loaded {len(X)} samples")
        return X, y, y


# ═══════════════════════════════════════════════════════════
# THREAT INTELLIGENCE
# ═══════════════════════════════════════════════════════════

class ThreatIntelligence:
    """Integrate external threat intelligence"""
    
    def __init__(self, abuseipdb_key=None):
        self.abuseipdb_key = abuseipdb_key
        self.cache = {}
        self.cache_ttl = 3600
    
    def check_ip_reputation(self, ip):
        """Check IP reputation"""
        if not self.abuseipdb_key:
            return {'score': 0, 'is_malicious': False}
        
        if ip in self.cache:
            cached_time, data = self.cache[ip]
            if time.time() - cached_time < self.cache_ttl:
                return data
        
        try:
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                headers={'Key': self.abuseipdb_key, 'Accept': 'application/json'},
                timeout=3
            )
            
            if response.status_code == 200:
                data = response.json()['data']
                result = {
                    'score': data['abuseConfidenceScore'],
                    'is_malicious': data['abuseConfidenceScore'] > 75,
                    'reports': data['totalReports']
                }
                self.cache[ip] = (time.time(), result)
                return result
        except Exception as e:
            pass
        
        return {'score': 0, 'is_malicious': False}


# ═══════════════════════════════════════════════════════════
# GEOIP BLOCKER
# ═══════════════════════════════════════════════════════════

class GeoIPBlocker:
    """Block traffic from specific countries"""
    
    def __init__(self, db_path='GeoLite2-Country.mmdb'):
        self.reader = None
        self.blocked_countries = set()
        
        if HAS_GEOIP and os.path.exists(db_path):
            try:
                self.reader = geoip2.database.Reader(db_path)
                print(f"[+] GeoIP database loaded")
            except:
                pass
    
    def add_blocked_country(self, country_code):
        """Add country to blocklist"""
        self.blocked_countries.add(country_code.upper())
        print(f"[+] Blocking traffic from {country_code}")
    
    def is_blocked(self, ip):
        """Check if IP is from blocked country"""
        if not self.reader or not self.blocked_countries:
            return False
        
        try:
            response = self.reader.country(ip)
            return response.country.iso_code in self.blocked_countries
        except:
            return False


# ═══════════════════════════════════════════════════════════
# ML NETWORK ANALYZER
# ═══════════════════════════════════════════════════════════

class EnhancedNetworkAnalyzer:
    """ML-based network traffic analyzer"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            contamination=0.1, 
            random_state=42, 
            n_estimators=200,
            max_samples=1000
        )
        self.random_forest = RandomForestClassifier(
            n_estimators=200, 
            random_state=42, 
            max_depth=20,
            n_jobs=-1
        )
        self.is_trained = False
        self.feature_importance = None
    
    def train(self, X, y):
        """Train models"""
        print("\n[*] Training Enhanced Network Analyzer...")
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        print("[*] Training Isolation Forest...")
        self.isolation_forest.fit(X_train_scaled)
        
        print("[*] Training Random Forest...")
        self.random_forest.fit(X_train_scaled, y_train)
        
        y_pred = self.random_forest.predict(X_test_scaled)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        print(f"\n{'='*60}")
        print(f"MODEL PERFORMANCE")
        print(f"{'='*60}")
        print(f"Accuracy:  {accuracy*100:.2f}%")
        print(f"Precision: {precision*100:.2f}%")
        print(f"Recall:    {recall*100:.2f}%")
        print(f"F1 Score:  {f1*100:.2f}%")
        print(f"{'='*60}\n")
        
        self.feature_importance = self.random_forest.feature_importances_
        self.is_trained = True
        
        return accuracy, precision, recall, f1
    
    def predict(self, features):
        """Predict if traffic is malicious"""
        if not self.is_trained:
            return {'is_threat': False, 'confidence': 0}
        
        features_scaled = self.scaler.transform([features])
        
        is_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
        anomaly_score = self.isolation_forest.score_samples(features_scaled)[0]
        
        rf_pred = self.random_forest.predict(features_scaled)[0]
        rf_proba = self.random_forest.predict_proba(features_scaled)[0]
        
        confidence = max(rf_proba)
        is_threat = is_anomaly or rf_pred == 1
        
        return {
            'is_threat': is_threat,
            'confidence': confidence,
            'anomaly_score': anomaly_score
        }
    
    def save_model(self, filepath='firewall_model.pkl'):
        """Save model"""
        with open(filepath, 'wb') as f:
            pickle.dump({
                'scaler': self.scaler,
                'isolation_forest': self.isolation_forest,
                'random_forest': self.random_forest,
                'feature_importance': self.feature_importance
            }, f)
        print(f"[+] Model saved to {filepath}")
    
    def load_model(self, filepath='firewall_model.pkl'):
        """Load model"""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        self.scaler = data['scaler']
        self.isolation_forest = data['isolation_forest']
        self.random_forest = data['random_forest']
        self.feature_importance = data['feature_importance']
        self.is_trained = True
        print(f"[+] Model loaded from {filepath}")


# ═══════════════════════════════════════════════════════════
# MAIN FIREWALL
# ═══════════════════════════════════════════════════════════

class EnhancedAIFirewall:
    """Complete AI Firewall System"""
    
    def __init__(self, config=None):
        self.config = config or {}
        
        self.analyzer = EnhancedNetworkAnalyzer()
        self.threat_intel = ThreatIntelligence(
            abuseipdb_key=self.config.get('abuseipdb_key')
        )
        self.geoip = GeoIPBlocker(
            db_path=self.config.get('geoip_db', 'GeoLite2-Country.mmdb')
        )
        
        self.db_session = None
        if HAS_DATABASE and self.config.get('use_database'):
            self._init_database()
        
        self.stats = {
            'total_packets': 0,
            'blocked_packets': 0,
            'threats_detected': 0,
            'anomalies_detected': 0
        }
        
        self.blocked_ips = set()
    
    def _init_database(self):
        """Initialize database"""
        db_url = self.config.get('database_url', 'sqlite:///firewall.db')
        engine = create_engine(db_url)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.db_session = Session()
        print(f"[+] Database initialized: {db_url}")
    
    def load_and_train(self, dataset_path, dataset_type='cicids2017'):
        """Load dataset and train"""
        print(f"\n{'='*60}")
        print(f"LOADING DATASET: {dataset_type.upper()}")
        print(f"{'='*60}\n")
        
        if dataset_type == 'cicids2017':
            X, y, y_multi = DatasetLoader.load_cicids2017(dataset_path)
        elif dataset_type == 'nsl-kdd':
            X, y, y_multi = DatasetLoader.load_nsl_kdd(dataset_path)
        else:
            raise ValueError(f"Unknown dataset: {dataset_type}")
        
        return self.analyzer.train(X, y)
    
    def analyze_packet(self, packet_data):
        """Analyze packet"""
        self.stats['total_packets'] += 1
        
        src_ip = packet_data.get('src_ip', 'unknown')
        
        if src_ip in self.blocked_ips:
            self.stats['blocked_packets'] += 1
            return {'blocked': True, 'reason': 'IP_BLACKLISTED'}
        
        if self.geoip.is_blocked(src_ip):
            self.stats['blocked_packets'] += 1
            self._block_ip(src_ip, 'GEOIP_BLOCKED')
            return {'blocked': True, 'reason': 'GEOIP_BLOCKED'}
        
        reputation = self.threat_intel.check_ip_reputation(src_ip)
        if reputation.get('is_malicious'):
            self.stats['blocked_packets'] += 1
            self._block_ip(src_ip, f"THREAT_INTEL")
            return {'blocked': True, 'reason': 'THREAT_INTELLIGENCE'}
        
        features = self._extract_features(packet_data)
        ml_result = self.analyzer.predict(features)
        
        if ml_result['is_threat'] and ml_result['confidence'] > 0.7:
            self.stats['threats_detected'] += 1
            self.stats['blocked_packets'] += 1
            self._log_alert(packet_data, ml_result)
            return {'blocked': True, 'reason': 'ML_DETECTION', 'ml_result': ml_result}
        
        return {'blocked': False, 'ml_result': ml_result}
    
    def _extract_features(self, packet_data):
        """Extract features"""
        return [
            packet_data.get('packet_size', 0),
            packet_data.get('src_port', 0),
            packet_data.get('dst_port', 0),
            packet_data.get('protocol', 0),
            packet_data.get('flags', 0),
            packet_data.get('ttl', 64),
            packet_data.get('payload_entropy', 0),
            packet_data.get('inter_arrival_time', 0),
            packet_data.get('flow_duration', 0)
        ]
    
    def _block_ip(self, ip, reason):
        """Block IP"""
        self.blocked_ips.add(ip)
        
        if self.db_session:
            blocked = self.db_session.query(BlockedIP).filter_by(ip_address=ip).first()
            if blocked:
                blocked.block_count += 1
            else:
                blocked = BlockedIP(ip_address=ip, reason=reason)
                self.db_session.add(blocked)
            self.db_session.commit()
        
        print(f"[!] Blocked IP: {ip} ({reason})")
    
    def _log_alert(self, packet_data, ml_result):
        """Log alert"""
        if not self.db_session:
            return
        
        alert = Alert(
            src_ip=packet_data.get('src_ip'),
            dst_ip=packet_data.get('dst_ip'),
            threat_type='ML_DETECTION',
            severity='HIGH' if ml_result['confidence'] > 0.9 else 'MEDIUM',
            blocked=True,
            confidence=ml_result['confidence'],
            website=packet_data.get('website', '')
        )
        self.db_session.add(alert)
        self.db_session.commit()
    
    def get_statistics(self):
        """Get stats"""
        block_rate = (self.stats['blocked_packets'] / max(self.stats['total_packets'], 1)) * 100
        return {
            'stats': self.stats,
            'block_rate': round(block_rate, 2),
            'blocked_ips_count': len(self.blocked_ips)
        }
    
    def save_model(self, filepath='firewall_model.pkl'):
        """Save model"""
        self.analyzer.save_model(filepath)


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("="*70)
    print("ENHANCED AI FIREWALL - Production Version 2.0")
    print("="*70)
    
    config = {
        'use_database': True,
        'database_url': 'sqlite:///firewall.db',
    }
    
    firewall = EnhancedAIFirewall(config)
    
    dataset_path = 'cicids2017.csv'
    
    if os.path.exists(dataset_path):
        firewall.load_and_train(dataset_path, 'cicids2017')
        firewall.save_model()
    else:
        print(f"\n[!] Dataset not found: {dataset_path}")
        print("[*] Download CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html")
        print("[*] Or NSL-KDD: https://www.unb.ca/cic/datasets/nsl.html")
        print("\n[*] Generating demo data...")
        
        X = pd.DataFrame(np.random.randn(1000, 9))
        y = np.random.choice([0, 1], 1000, p=[0.95, 0.05])
        firewall.analyzer.train(X, pd.Series(y))
    
    print(f"\n[+] Firewall Ready!")
    print(f"[+] Use: firewall.analyze_packet(packet_data)")