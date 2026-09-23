import time
import math
from collections import defaultdict
from PyQt6.QtCore import QThread, pyqtSignal
import logging
# Suppress scapy internal verbose warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class AIIDSEngine(QThread):
    """
    Multi-Vector AI Intrusion Detection Engine.
    High-performance, non-blocking packet analysis engine with adaptive baseline learning.
    """
    log_signal = pyqtSignal(str, bool)  # message, is_suspicious

    def __init__(self):
        super().__init__()
        self.running = False
        
        # Sub-vector toggles
        self.detect_port_scan = True
        self.detect_syn_flood = True
        self.detect_packet_anomaly = True
        self.detect_payload_entropy = True
        self.enable_ai_classifier = True

        # State tracking
        self.ip_syn_counter = defaultdict(int)
        self.ip_port_tracker = defaultdict(set)
        self.last_reset = time.time()

        # Legitimate high-entropy or compressed application ports
        # 8080, 8000 frequently carry gzip/deflate compressed HTTP or WebSockets
        self.high_entropy_exempt_ports = {22, 443, 8443, 990, 993, 995, 8080, 8000}

        # Calibrated Heuristic Thresholds
        self.port_scan_threshold = 20
        self.syn_flood_threshold = 40

        # Lazy ML state (initialized in background thread to guarantee fast GUI boot)
        self.model = None
        self.np = None
        self.training_buffer = []
        self.is_trained = False

    def _init_ml_engine(self):
        """Lazy loads ML libraries in worker thread to eliminate startup lag."""
        if self.model is None:
            try:
                import numpy as np
                from sklearn.ensemble import IsolationForest
                self.np = np
                self.model = IsolationForest(
                    n_estimators=100, 
                    contamination=0.01, 
                    random_state=42, 
                    warm_start=True
                )
            except Exception as e:
                self.log_signal.emit(f"[*] ML Module initialization bypassed: {e}", False)

    def calculate_entropy(self, data: bytes) -> float:
        if not data or len(data) < 64:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        for count in byte_counts:
            if count > 0:
                p_x = count / length
                entropy -= p_x * math.log2(p_x)
        return entropy

    def run(self):
        from scapy.all import sniff, IP, TCP, UDP, Raw, conf

        # Set scapy verbosity to 0
        conf.verb = 0
        self.running = True
        self.log_signal.emit("[*] AI-IDS Core initializing background worker...", False)
        
        self._init_ml_engine()
        self.log_signal.emit("[*] AI-IDS Core activated. Sniffing live traffic...", False)

        try:
            from scapy.all import sniff, IP, TCP, UDP, Raw, conf
            from scapy.layers.inet import conf as inet_conf

            # Fallback to Layer 3 native socket if Npcap/WinPcap is not installed
            if conf.L3socket is not None:
                conf.L3socket = inet_conf.L3socket
            def process_packet(packet):
                if not self.running:
                    return

                # Reset rate trackers every 5 seconds
                current_time = time.time()
                if current_time - self.last_reset > 5.0:
                    self.ip_syn_counter.clear()
                    self.ip_port_tracker.clear()
                    self.last_reset = current_time

                if not packet.haslayer(IP):
                    return

                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                pkt_len = len(packet)
                proto = packet[IP].proto
                sport = packet.sport if hasattr(packet, 'sport') else 0
                dport = packet.dport if hasattr(packet, 'dport') else 0

                is_anomaly = False
                reasons = []

                # 1. Port Scan Detection (Tracks unique destination ports accessed per IP)
                if self.detect_port_scan and dport:
                    self.ip_port_tracker[src_ip].add(dport)
                    if len(self.ip_port_tracker[src_ip]) > self.port_scan_threshold:
                        is_anomaly = True
                        reasons.append(f"Port-Scan Sweep (>{self.port_scan_threshold} targets)")

                # 2. SYN Flood Heuristic (Monitors rapid half-open TCP states)
                if self.detect_syn_flood and packet.haslayer(TCP):
                    flags = packet[TCP].flags
                    # Check exclusively for SYN flag without ACK
                    if flags == 'S' or flags == 0x02:
                        self.ip_syn_counter[src_ip] += 1
                        if self.ip_syn_counter[src_ip] > self.syn_flood_threshold:
                            is_anomaly = True
                            reasons.append(f"SYN Flood Signature (>{self.syn_flood_threshold} SYNs/5s)")

                # 3. Payload Entropy Inspection (Checks for obfuscated shellcode/c2 beacons)
                if self.detect_payload_entropy and packet.haslayer(Raw):
                    if dport not in self.high_entropy_exempt_ports and sport not in self.high_entropy_exempt_ports:
                        payload = packet[Raw].load
                        entropy = self.calculate_entropy(payload)
                        # Threshold tuned to 7.75 bits (pure randomness/raw encrypted shellcode)
                        if entropy > 7.75:
                            is_anomaly = True
                            reasons.append(f"Suspicious Shellcode Entropy ({entropy:.2f} bits)")

                # 4. Adaptive IsolationForest Anomaly Detection
                if self.enable_ai_classifier and self.model is not None:
                    feat = [pkt_len, min(dport, 65535), proto]
                    if not self.is_trained:
                        self.training_buffer.append(feat)
                        if len(self.training_buffer) >= 60:
                            train_matrix = self.np.array(self.training_buffer)
                            self.model.fit(train_matrix)
                            self.is_trained = True
                            self.training_buffer.clear()
                    else:
                        features = self.np.array([feat])
                        prediction = self.model.predict(features)[0]
                        if prediction == -1 and (pkt_len > 1460 or pkt_len < 28):
                            is_anomaly = True
                            reasons.append("ML IsolationForest Anomaly Vector")

                # Emit structured telemetry
                if is_anomaly:
                    msg = f"[ALERT] INTRUSION DETECTED | {src_ip}:{sport} -> {dst_ip}:{dport} | Reason: {', '.join(reasons)}"
                    self.log_signal.emit(msg, True)
                else:
                    msg = f"[NORMAL] {src_ip}:{sport} -> {dst_ip}:{dport} | Proto: {proto} | Size: {pkt_len}B"
                    self.log_signal.emit(msg, False)

            # Continuous live sniffing loop
            while self.running:
                sniff(
                    prn=process_packet, 
                    store=False, 
                    stop_filter=lambda _: not self.running, 
                    timeout=1.0,
                    L2socket=conf.L3socket  # Fallback to Layer 3 socket
                )

        except PermissionError:
            self.log_signal.emit("[!] Access Denied: Administrator/Root privileges required for live packet sniffing.", True)
        except Exception as e:
            self.log_signal.emit(f"[!] Live Sniffer Interface Error: {str(e)}", True)
            self.log_signal.emit("[*] Ensure Npcap (Windows) or libpcap (Linux) is installed and active.", False)

    def stop(self):
        self.running = False
        self.wait(1000)