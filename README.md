# 🛡️ AI Firewall System

An advanced **AI-powered firewall and network monitoring system** that combines **Machine Learning, Threat Intelligence, Real-time Traffic Analysis, and Web-based Visualization** to detect and prevent cyber threats.

---

## 🚀 Features

- 🔍 Real-Time Network Traffic Monitoring  
- 🤖 Machine Learning-Based Threat Detection  
- 🌐 Website & Domain Monitoring (Browser + DNS)  
- 🚫 Automatic IP & Domain Blocking  
- 🧠 Anomaly Detection (Isolation Forest)  
- 📊 Live Dashboard & GUI  
- 🔗 REST API + WebSocket Integration  
- 🌍 GeoIP Blocking (Optional)  
- 📡 Threat Intelligence Integration (AbuseIPDB)  
- 🗄️ Database Logging (SQLite)  
- 📈 Traffic Statistics & Alerts  

---

## 📁 Project Structure

```
AI-FIREWALL/
│
├── ai_firewall.py
├── firewall_checker.py
├── firewall_gui.py
├── integration_server.py
├── packet_capture.py
├── firewall.db
├── venv/
```

---

## ⚙️ Installation

### 1. Clone the Repository
```bash
git clone <your-repo-url>
cd AI-FIREWALL
```

### 2. Create Virtual Environment
```bash
python -m venv venv
```

### 3. Activate Environment

**Windows**
```bash
venv\Scripts\activate
```

**Linux/Mac**
```bash
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

If no requirements file:
```bash
pip install numpy pandas scikit-learn flask flask-cors flask-socketio requests scapy sqlalchemy tensorflow geoip2
```

---

## ▶️ How to Run

### 1. Start Backend Server
```bash
python integration_server.py
```

Access API at:
```
http://localhost:5000
```

---

### 2. Launch GUI
```bash
python firewall_gui.py
```

---

### 3. Start Packet Capture (Optional)
```bash
sudo python packet_capture.py
```

---

### 4. Run AI Firewall Engine
```bash
python ai_firewall.py
```

---

### 5. Check System Status
```bash
python firewall_checker.py
```

---

## 🧠 AI & Detection

- Random Forest → Threat classification  
- Isolation Forest → Anomaly detection  
- LSTM (optional) → Deep learning  
- Pattern-based detection → Phishing & malware  
- Google Safe Browsing (optional)  

---

## 🌐 API Endpoints

| Method | Endpoint            | Description |
|--------|--------------------|------------|
| GET    | /api/status        | Server status |
| GET    | /api/stats         | Traffic stats |
| GET    | /api/alerts        | Alerts |
| GET    | /api/traffic       | Traffic history |
| GET    | /api/threats       | Threat distribution |
| POST   | /api/start         | Start monitoring |
| POST   | /api/stop          | Stop monitoring |
| POST   | /api/block         | Block IP |
| POST   | /api/whitelist     | Whitelist IP |

---

## 🖥️ GUI Capabilities

- Reads real browser history  
- Detects phishing & malicious domains  
- Blocks domains via hosts file  
- Live monitoring and logs  

---

## 📡 Packet Capture

- Captures HTTP / HTTPS / DNS traffic  
- Extracts visited websites  
- Uses Scapy for packet inspection  

---

## 🔐 Security Features

- IP Blocking (Firewall rules)  
- Domain Blocking (Hosts file)  
- Threat Intelligence (AbuseIPDB)  
- GeoIP Filtering  
- Auto-block high severity threats  

---

## ⚠️ Requirements

- Python 3.8+  
- Admin/root privileges (for capture & blocking)  
- OS: Windows / Linux / macOS  

---

## 🛠️ Future Improvements

- Web dashboard (React)  
- Cloud deployment  
- Advanced deep learning models  
- Authentication system  

---

## 📌 Notes

Some features are optional:
- TensorFlow → Deep learning  
- GeoIP → Country blocking  
- SendGrid → Email alerts  

---

## 👨‍💻 Author

AI Firewall Project v2.0  

---

## 📄 License

For educational and research purposes only.  
Use responsibly.

---