"""
Live WiFi/Internet Traffic Capture
Captures real network traffic and extracts website names
Version: 2.0
"""

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, get_if_list
except ImportError:
    print("Error: Install scapy with: pip install scapy")
    exit(1)

import threading
import queue
import json
from datetime import datetime
import socket
import platform
import sys
import os
from collections import defaultdict


class LiveTrafficCapture:
    """Capture real network traffic from WiFi/Ethernet"""
    
    def __init__(self, firewall=None):
        self.firewall = firewall
        self.capture_queue = queue.Queue(maxsize=5000)
        self.is_capturing = False
        self.packet_count = 0
        
        # DNS cache
        self.dns_cache = {}
        self.reverse_dns_cache = {}
        
        # Stats
        self.stats = {
            'total_packets': 0,
            'http_packets': 0,
            'https_packets': 0,
            'dns_packets': 0,
            'websites_visited': set()
        }
        
        self.interface = self._get_active_interface()
    
    def _get_active_interface(self):
        """Auto-detect active network interface"""
        interfaces = get_if_list()
        
        print(f"\n[*] Available interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"    {i}. {iface}")
        
        # Auto-select
        if platform.system() == "Windows":
            for iface in interfaces:
                if any(k in iface.lower() for k in ['wifi', 'wireless', 'ethernet', 'wi-fi']):
                    if 'loopback' not in iface.lower():
                        print(f"\n[+] Selected: {iface}")
                        return iface
        else:
            for iface in interfaces:
                if any(k in iface.lower() for k in ['wlan', 'wifi', 'eth', 'en0', 'wlp']):
                    if 'lo' not in iface.lower():
                        print(f"\n[+] Selected: {iface}")
                        return iface
        
        # Fallback
        for iface in interfaces:
            if 'lo' not in iface.lower() and 'loopback' not in iface.lower():
                print(f"\n[+] Using: {iface}")
                return iface
        
        return interfaces[0] if interfaces else None
    
    def parse_dns(self, packet):
        """Extract DNS info"""
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            if query:
                self.stats['websites_visited'].add(query)
                print(f"[DNS] Query: {query}")
                return {'type': 'dns_query', 'domain': query}
        
        if packet.haslayer(DNSRR):
            query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            answer = packet[DNSRR].rdata
            
            if answer and query:
                self.dns_cache[answer] = query
                self.reverse_dns_cache[query] = answer
                print(f"[DNS] {query} -> {answer}")
                return {'type': 'dns_response', 'domain': query, 'ip': answer}
        
        return None
    
    def get_website_name(self, ip):
        """Get website for IP"""
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = hostname
            return hostname
        except:
            return None
    
    def parse_http(self, packet):
        """Extract HTTP info"""
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                decoded = payload.decode('utf-8', errors='ignore')
                
                if decoded.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD')):
                    lines = decoded.split('\r\n')
                    parts = lines[0].split(' ')
                    
                    if len(parts) >= 2:
                        method = parts[0]
                        path = parts[1]
                        
                        host = None
                        for line in lines[1:]:
                            if line.lower().startswith('host:'):
                                host = line.split(':', 1)[1].strip()
                                break
                        
                        if host:
                            self.stats['websites_visited'].add(host)
                            return {
                                'type': 'http',
                                'method': method,
                                'website': f"{host}{path}",
                                'host': host,
                                'path': path
                            }
            except:
                pass
        return None
    
    def parse_packet(self, packet):
        """Parse packet"""
        packet_data = {
            'timestamp': datetime.now().isoformat(),
            'packet_size': len(packet),
            'website': None,
            'domain': None,
            'protocol_name': 'Unknown'
        }
        
        if packet.haslayer(IP):
            ip = packet[IP]
            packet_data.update({
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'protocol': ip.proto,
                'ttl': ip.ttl
            })
            
            dst_website = self.get_website_name(ip.dst)
            if dst_website:
                packet_data['website'] = dst_website
                packet_data['domain'] = dst_website
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            packet_data.update({
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'flags': tcp.flags,
                'protocol_name': 'TCP'
            })
            
            if tcp.dport == 80 or tcp.sport == 80:
                packet_data['service'] = 'HTTP'
                packet_data['is_http'] = True
                self.stats['http_packets'] += 1
                
                http_info = self.parse_http(packet)
                if http_info:
                    packet_data.update(http_info)
            
            elif tcp.dport == 443 or tcp.sport == 443:
                packet_data['service'] = 'HTTPS'
                packet_data['is_https'] = True
                self.stats['https_packets'] += 1
        
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            packet_data.update({
                'src_port': udp.sport,
                'dst_port': udp.dport,
                'protocol_name': 'UDP'
            })
            
            if udp.dport == 53 or udp.sport == 53:
                packet_data['service'] = 'DNS'
                self.stats['dns_packets'] += 1
                dns_info = self.parse_dns(packet)
                if dns_info:
                    packet_data.update(dns_info)
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            packet_data['payload'] = payload
            packet_data['payload_length'] = len(payload)
            packet_data['payload_entropy'] = self._calculate_entropy(payload)
        
        return packet_data
    
    def _calculate_entropy(self, data):
        """Shannon entropy"""
        if not data:
            return 0
        import math
        entropy = 0
        for x in range(256):
            p = data.count(bytes([x])) / len(data)
            if p > 0:
                entropy += -p * math.log2(p)
        return entropy
    
    def packet_handler(self, packet):
        """Handle packet"""
        try:
            self.packet_count += 1
            self.stats['total_packets'] += 1
            
            packet_data = self.parse_packet(packet)
            
            if not self.capture_queue.full():
                self.capture_queue.put(packet_data)
            
            if packet_data.get('website'):
                print(f"[{self.packet_count}] {packet_data.get('service', 'Traffic')} -> {packet_data['website']}")
            elif packet_data.get('domain'):
                print(f"[{self.packet_count}] DNS -> {packet_data['domain']}")
            
            if self.firewall:
                result = self.firewall.analyze_packet(packet_data)
                if result.get('blocked'):
                    print(f"    [!] BLOCKED: {result.get('reason')}")
            
            if self.packet_count % 100 == 0:
                self._print_stats()
        
        except Exception as e:
            pass
    
    def _print_stats(self):
        """Print stats"""
        print(f"\n{'='*60}")
        print(f"Live Traffic Stats")
        print(f"{'='*60}")
        print(f"Total:    {self.stats['total_packets']:,}")
        print(f"HTTP:     {self.stats['http_packets']:,}")
        print(f"HTTPS:    {self.stats['https_packets']:,}")
        print(f"DNS:      {self.stats['dns_packets']:,}")
        print(f"Websites: {len(self.stats['websites_visited'])}")
        
        if self.stats['websites_visited']:
            print(f"\nRecent sites:")
            for site in list(self.stats['websites_visited'])[-5:]:
                print(f"  • {site}")
        print(f"{'='*60}\n")
    
    def start_capture(self):
        """Start capture"""
        if not self.interface:
            print("[!] No interface found!")
            return
        
        self.is_capturing = True
        
        print(f"\n{'='*60}")
        print(f"LIVE TRAFFIC CAPTURE STARTED")
        print(f"{'='*60}")
        print(f"Interface: {self.interface}")
        print(f"Capturing: HTTP, HTTPS, DNS, all TCP/UDP")
        print(f"Press Ctrl+C to stop")
        print(f"{'='*60}\n")
        
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=False, filter="ip")
        except KeyboardInterrupt:
            print("\n\n[*] Stopping...")
        except PermissionError:
            print("\n[!] Permission denied!")
            print("[!] Windows: Run as Administrator")
            print("[!] Linux/Mac: Run with sudo")
        except Exception as e:
            print(f"\n[!] Error: {e}")
        finally:
            self.is_capturing = False
            self._print_stats()
            self._print_summary()
    
    def _print_summary(self):
        """Final summary"""
        print(f"\n{'='*60}")
        print(f"Capture Summary")
        print(f"{'='*60}")
        print(f"Total packets: {self.packet_count:,}")
        print(f"\nAll websites visited:")
        
        if self.stats['websites_visited']:
            for i, site in enumerate(sorted(self.stats['websites_visited']), 1):
                print(f"{i:3}. {site}")
        else:
            print("  None")
        print(f"{'='*60}")
    
    def get_captured_packets(self, count=10):
        """Get recent packets"""
        packets = []
        while not self.capture_queue.empty() and len(packets) < count:
            try:
                packets.append(self.capture_queue.get_nowait())
            except:
                break
        return packets
    
    def get_websites_visited(self):
        """Get websites list"""
        return sorted(list(self.stats['websites_visited']))
    
    def save_capture(self, filename='live_traffic.json'):
        """Save capture"""
        packets = []
        while not self.capture_queue.empty():
            try:
                p = self.capture_queue.get_nowait()
                if 'payload' in p:
                    p['payload'] = str(p['payload'][:100])
                packets.append(p)
            except:
                break
        
        with open(filename, 'w') as f:
            json.dump({
                'time': datetime.now().isoformat(),
                'total': self.stats['total_packets'],
                'websites': list(self.stats['websites_visited']),
                'packets': packets
            }, f, indent=2)
        
        print(f"[+] Saved to {filename}")


if __name__ == "__main__":
    print("="*60)
    print("Live WiFi/Internet Traffic Capture v2.0")
    print("="*60)
    
    # Check privileges
    if platform.system() == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("\n[!] ERROR: Run as Administrator")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("\n[!] ERROR: Run with sudo")
            sys.exit(1)
    
    print("\n[+] Privileges OK")
    print("\n[*] This captures ALL WiFi/Ethernet traffic")
    print("[*] Open browser and visit websites to see them here!")
    print()
    
    capture = LiveTrafficCapture()
    
    try:
        capture.start_capture()
    except KeyboardInterrupt:
        print("\n[*] Stopped")
    finally:
        save = input("\nSave data? (y/n): ").strip().lower()
        if save == 'y':
            capture.save_capture()
        print("\n[+] Done!")