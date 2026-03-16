"""
AI Firewall - Status Checker
Quickly verify all components are running correctly
"""

import requests
import socket
import subprocess
import sys
import platform
from datetime import datetime


class FirewallChecker:
    def __init__(self):
        self.api_url = "http://localhost:5000"
        self.results = {}

    def header(self):
        print("=" * 65)
        print("🛡️   AI Firewall System — Status Checker")
        print("=" * 65)
        print(f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Platform : {platform.system()} {platform.release()}")
        print("=" * 65 + "\n")

    def check_port(self, port=5000):
        print(f"[1] Checking port {port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex(('localhost', port))
            s.close()
            if result == 0:
                print(f"    ✅ Port {port} is OPEN\n")
                self.results['port'] = True
            else:
                print(f"    ❌ Port {port} is CLOSED\n")
                self.results['port'] = False
        except Exception as e:
            print(f"    ❌ Error: {e}\n")
            self.results['port'] = False

    def check_api(self):
        print("[2] Checking API response...")
        try:
            r = requests.get(f"{self.api_url}/api/status", timeout=3)
            if r.status_code == 200:
                data = r.json()
                print(f"    ✅ API is RESPONDING")
                print(f"       Running : {data.get('is_running')}")
                print(f"       Uptime  : {round(data.get('uptime') or 0, 1)}s\n")
                self.results['api'] = True
            else:
                print(f"    ❌ API returned: {r.status_code}\n")
                self.results['api'] = False
        except requests.exceptions.ConnectionError:
            print("    ❌ Cannot connect — server not running\n")
            self.results['api'] = False
        except Exception as e:
            print(f"    ❌ Error: {e}\n")
            self.results['api'] = False

    def check_monitoring(self):
        print("[3] Checking monitoring status...")
        try:
            r = requests.get(f"{self.api_url}/api/stats", timeout=3)
            data = r.json()
            running = data.get('is_running', False)
            s = data['stats']
            if running:
                print("    ✅ Monitoring is ACTIVE")
            else:
                print("    ⚠️  Monitoring is IDLE (not started)")
            print(f"       Total Packets : {s['total_packets']}")
            print(f"       Blocked       : {s['blocked_packets']}")
            print(f"       Threats       : {s['threats_detected']}")
            print(f"       Block Rate    : {data.get('block_rate', 0):.2f}%\n")
            self.results['monitoring'] = running
        except Exception as e:
            print(f"    ❌ Error: {e}\n")
            self.results['monitoring'] = False

    def check_endpoints(self):
        print("[4] Checking all API endpoints...")
        endpoints = [
            ('GET', '/api/status'),
            ('GET', '/api/stats'),
            ('GET', '/api/alerts'),
            ('GET', '/api/traffic'),
            ('GET', '/api/threats'),
        ]
        ok = 0
        for method, ep in endpoints:
            try:
                r = requests.get(f"{self.api_url}{ep}", timeout=2)
                if r.status_code == 200:
                    print(f"    ✅ {method} {ep}")
                    ok += 1
                else:
                    print(f"    ❌ {method} {ep}  [{r.status_code}]")
            except:
                print(f"    ❌ {method} {ep}  [no response]")
        print(f"\n    {ok}/{len(endpoints)} endpoints OK\n")
        self.results['endpoints'] = (ok == len(endpoints))

    def check_process(self):
        print("[5] Checking running processes...")
        try:
            if platform.system() == "Windows":
                out = subprocess.run(['tasklist'], capture_output=True, text=True).stdout
                found = 'python' in out.lower()
            else:
                out = subprocess.run(['ps', 'aux'], capture_output=True, text=True).stdout
                found = 'integration_server' in out or 'python' in out
            if found:
                print("    ✅ Python process detected\n")
            else:
                print("    ⚠️  No Python server process found\n")
            self.results['process'] = found
        except Exception as e:
            print(f"    ⚠️  Cannot check processes: {e}\n")
            self.results['process'] = None

    def summary(self):
        print("=" * 65)
        print("📋  SUMMARY")
        print("=" * 65)

        all_ok = all([
            self.results.get('port'),
            self.results.get('api'),
            self.results.get('endpoints')
        ])

        if all_ok:
            print("\n  🎉 All systems OPERATIONAL!\n")
            print("  Quick Links:")
            print("    • API Status : http://localhost:5000/api/status")
            print("    • API Stats  : http://localhost:5000/api/stats")
            print("    • API Alerts : http://localhost:5000/api/alerts")
            if not self.results.get('monitoring'):
                print("\n  ⚠️  Tip: Monitoring not started yet.")
                print("     Start it via the GUI or run:")
                print("     curl -X POST http://localhost:5000/api/start")
        else:
            print("\n  ❌ System NOT running properly\n")
            print("  Fix steps:")
            if not self.results.get('port'):
                print("  1. Start the server:")
                if platform.system() == "Windows":
                    print("     python integration_server.py  (as Administrator)")
                else:
                    print("     sudo python3 integration_server.py")
            if not self.results.get('api'):
                print("  2. Check for errors in the server terminal window")
            if not self.results.get('endpoints'):
                print("  3. Wait a few seconds and re-run this checker")

        print("\n" + "=" * 65)

    def run(self):
        self.header()
        self.check_port()
        self.check_api()
        if self.results.get('api'):
            self.check_monitoring()
            self.check_endpoints()
        self.check_process()
        self.summary()
        return self.results.get('api', False)


if __name__ == "__main__":
    try:
        import requests
    except ImportError:
        print("Error: requests not installed.")
        print("Run: pip install requests")
        sys.exit(1)

    checker = FirewallChecker()
    try:
        ok = checker.run()
    except KeyboardInterrupt:
        print("\n\n[*] Checker interrupted")
        ok = False

    sys.exit(0 if ok else 1)