import logging
import math
import socket
import threading
import time
from collections import defaultdict, deque

from PyQt6.QtCore import QThread, pyqtSignal

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class AIIDSEngine(QThread):
    """
    Stateful, low-overhead intrusion detection engine for Vigil.

    The engine deliberately favors multiple corroborating signals over a single
    packet property. It observes live IP traffic, maintains short rolling
    windows, suppresses duplicate alerts, and exposes a safe response action
    (Windows Firewall blocking) to the UI.
    """

    # Kept compatible with the existing IDSView.
    log_signal = pyqtSignal(str, bool)

    # Emitted only for a real threat event. The UI can turn this into a toast
    # and an in-app action card without changing the permanent dashboard layout.
    intrusion_signal = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.running = False
        self._state_lock = threading.RLock()

        # Existing feature toggles.
        self.detect_port_scan = True
        self.detect_syn_flood = True
        self.detect_packet_anomaly = True
        self.detect_payload_entropy = True
        self.enable_ai_classifier = True

        # Detection windows. Short windows make the engine responsive while
        # avoiding the false positives caused by a single packet.
        self.window_seconds = 8.0
        self.port_scan_threshold = 12
        self.port_scan_burst_threshold = 20
        self.syn_flood_threshold = 35
        self.syn_burst_threshold = 60
        self.entropy_threshold = 7.85

        # source -> deque[(timestamp, destination_ip, destination_port)]
        self.port_activity = defaultdict(deque)
        # source -> deque[timestamp] for SYN-only packets
        self.syn_activity = defaultdict(deque)
        # (source, attack_type, target) -> last alert time
        self.alert_cooldowns = {}
        self.alert_cooldown_seconds = 12.0

        self._last_cleanup = time.monotonic()
        self._last_safe_log = 0.0
        self.safe_log_interval = 1.5

        self.local_ips = self._discover_local_ips()

        # Optional ML layer. It is intentionally secondary to deterministic
        # network signals, not the sole reason an alert is raised.
        self.model = None
        self.np = None
        self.training_buffer = []
        self.is_trained = False
        self._ml_last_prediction = 0.0
        self._init_ml_requested = False

        self.high_entropy_exempt_ports = {
            22, 443, 465, 587, 853, 873, 993, 995, 8443, 9443, 8080, 8000
        }

    # ------------------------------------------------------------------
    # Environment / utility helpers
    # ------------------------------------------------------------------

    def _discover_local_ips(self):
        ips = {"127.0.0.1", "::1"}
        try:
            hostname = socket.gethostname()
            for ip in socket.gethostbyname_ex(hostname)[2]:
                ips.add(ip)
        except Exception:
            pass

        # psutil is optional. If installed, it gives a much more complete
        # picture when the machine has Wi-Fi, Ethernet, VPNs, etc.
        try:
            import psutil
            for addresses in psutil.net_if_addrs().values():
                for address in addresses:
                    if address.family == socket.AF_INET:
                        ips.add(address.address)
        except Exception:
            pass
        return ips

    def _is_local_ip(self, ip):
        return ip in self.local_ips

    def _safe_log(self, message, now):
        """Keep ordinary traffic readable without flooding the QTextEdit."""
        if now - self._last_safe_log >= self.safe_log_interval:
            self._last_safe_log = now
            self.log_signal.emit(f"Safe activity — {message}", False)

    @staticmethod
    def _friendly_endpoint(ip, port):
        if port:
            return f"{ip} on service port {port}"
        return ip

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data or len(data) < 96:
            return 0.0

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        length = len(data)
        entropy = 0.0
        for count in byte_counts:
            if count:
                probability = count / length
                entropy -= probability * math.log2(probability)
        return entropy

    def _prune(self, now):
        if now - self._last_cleanup < 1.0:
            return

        cutoff = now - self.window_seconds

        for source, events in list(self.port_activity.items()):
            while events and events[0][0] < cutoff:
                events.popleft()
            if not events:
                self.port_activity.pop(source, None)

        for source, events in list(self.syn_activity.items()):
            while events and events[0] < cutoff:
                events.popleft()
            if not events:
                self.syn_activity.pop(source, None)

        # Prevent unbounded cooldown growth during a long-running session.
        for key, timestamp in list(self.alert_cooldowns.items()):
            if now - timestamp > self.alert_cooldown_seconds * 4:
                self.alert_cooldowns.pop(key, None)

        self._last_cleanup = now

    def _should_alert(self, source, attack_type, target, now):
        key = (source, attack_type, target)
        previous = self.alert_cooldowns.get(key, 0.0)
        if now - previous < self.alert_cooldown_seconds:
            return False
        self.alert_cooldowns[key] = now
        return True

    def _emit_intrusion(
        self,
        *,
        attack_type,
        source_ip,
        destination_ip,
        destination_port,
        severity,
        summary,
        details,
        now,
    ):
        target = destination_ip or "network"
        if not self._should_alert(source_ip, attack_type, target, now):
            return

        event = {
            "attack_type": attack_type,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": int(destination_port or 0),
            "severity": severity,
            "summary": summary,
            "details": details,
            "timestamp": time.time(),
        }

        # The log is deliberately human-readable. Technical details are kept
        # in the extra information shown only for a threat.
        log_message = (
            f"Threat detected — {summary}. "
            f"Source: {source_ip}. "
            f"Extra information: {details}"
        )
        self.log_signal.emit(log_message, True)
        self.intrusion_signal.emit(event)

    # ------------------------------------------------------------------
    # Optional adaptive model
    # ------------------------------------------------------------------

    def _init_ml_engine(self):
        if self.model is not None or self._init_ml_requested:
            return

        self._init_ml_requested = True
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest

            self.np = np
            self.model = IsolationForest(
                n_estimators=80,
                contamination=0.015,
                random_state=42,
                n_jobs=-1,
            )
        except Exception:
            # ML is an enhancement, not a requirement for the IDS.
            self.model = None

    def _ml_check(self, pkt_len, dport, proto, now):
        """
        Returns True only when the optional model has learned a baseline and
        the packet is unusual enough to merit a secondary signal.

        The prediction is rate-limited because running ML for every packet is
        unnecessary overhead on a busy interface.
        """
        if not self.enable_ai_classifier or self.model is None:
            return False

        feature = [pkt_len, min(int(dport or 0), 65535), int(proto)]

        if not self.is_trained:
            self.training_buffer.append(feature)
            if len(self.training_buffer) >= 120:
                try:
                    self.model.fit(self.np.asarray(self.training_buffer))
                    self.is_trained = True
                    self.training_buffer.clear()
                except Exception:
                    self.is_trained = False
                    self.training_buffer.clear()
            return False

        if now - self._ml_last_prediction < 0.05:
            return False
        self._ml_last_prediction = now

        try:
            prediction = self.model.predict(self.np.asarray([feature]))[0]
            # Do not alert on ML alone. This is deliberately conservative.
            return prediction == -1 and (pkt_len > 1450 or pkt_len < 40)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Packet analysis
    # ------------------------------------------------------------------

    def _process_packet(self, packet, IP, TCP, UDP, Raw):
        if not self.running or not packet.haslayer(IP):
            return

        now = time.monotonic()
        self._prune(now)

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        pkt_len = len(packet)
        proto = int(ip_layer.proto)

        sport = 0
        dport = 0
        if packet.haslayer(TCP):
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            sport = int(packet[UDP].sport)
            dport = int(packet[UDP].dport)

        source_is_local = self._is_local_ip(src_ip)
        destination_is_local = self._is_local_ip(dst_ip)

        # --------------------------------------------------------------
        # 1. Port scan: require a burst of distinct ports against the same
        # target, or a broader sweep across several local destinations.
        # This avoids flagging normal web browsing as a scan.
        # --------------------------------------------------------------
        if (
            self.detect_port_scan
            and dport
            and not source_is_local
            and destination_is_local
        ):
            events = self.port_activity[src_ip]
            events.append((now, dst_ip, dport))

            unique_ports_same_target = {
                port for timestamp, target, port in events
                if target == dst_ip and timestamp >= now - self.window_seconds
            }
            unique_targets = {
                target for timestamp, target, port in events
                if timestamp >= now - self.window_seconds
            }

            is_scan = (
                len(unique_ports_same_target) >= self.port_scan_threshold
                or (
                    len(events) >= self.port_scan_burst_threshold
                    and len(unique_targets) >= 3
                )
            )

            if is_scan:
                target_count = len(unique_ports_same_target)
                self._emit_intrusion(
                    attack_type="port_scan",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    destination_port=dport,
                    severity="high",
                    summary="A device is rapidly checking many network services on your computer.",
                    details=(
                        f"The source contacted {target_count} different service ports "
                        f"on {dst_ip} within about {self.window_seconds:.0f} seconds. "
                        "This pattern is consistent with reconnaissance or a port scan."
                    ),
                    now=now,
                )
                return

        # --------------------------------------------------------------
        # 2. SYN burst: count SYN packets from a remote source in a rolling
        # window. A single SYN is normal; a sustained burst is not.
        # --------------------------------------------------------------
        if (
            self.detect_syn_flood
            and packet.haslayer(TCP)
            and not source_is_local
            and destination_is_local
        ):
            flags = int(packet[TCP].flags)
            syn_only = bool(flags & 0x02) and not bool(flags & 0x10)

            if syn_only:
                events = self.syn_activity[src_ip]
                events.append(now)

                recent_count = len(events)
                if (
                    recent_count >= self.syn_flood_threshold
                    or recent_count >= self.syn_burst_threshold
                ):
                    self._emit_intrusion(
                        attack_type="syn_flood",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        destination_port=dport,
                        severity="critical",
                        summary="A device is repeatedly trying to start connections with your computer.",
                        details=(
                            f"Detected {recent_count} connection attempts from {src_ip} "
                            f"in about {self.window_seconds:.0f} seconds. "
                            "The volume is consistent with a SYN-flood/connection-exhaustion attack."
                        ),
                        now=now,
                    )
                    return

        # --------------------------------------------------------------
        # 3. Payload entropy: use as supporting evidence, not a standalone
        # verdict. High entropy is common in encryption/compression.
        # --------------------------------------------------------------
        if (
            self.detect_payload_entropy
            and packet.haslayer(Raw)
            and destination_is_local
            and not source_is_local
            and dport not in self.high_entropy_exempt_ports
            and sport not in self.high_entropy_exempt_ports
        ):
            payload = bytes(packet[Raw].load)
            entropy = self.calculate_entropy(payload)

            # Require a reasonably sized payload; tiny packets naturally have
            # unstable entropy values.
            if len(payload) >= 128 and entropy >= self.entropy_threshold:
                self._emit_intrusion(
                    attack_type="suspicious_payload",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    destination_port=dport,
                    severity="medium",
                    summary="Network data has an unusually random-looking payload.",
                    details=(
                        f"The payload measured {entropy:.2f}/8.00 on the randomness "
                        "scale. This can indicate encrypted or compressed data, "
                        "but can also occur in legitimate applications, so Vigil "
                        "treats it as supporting evidence rather than proof of malware."
                    ),
                    now=now,
                )
                # Continue; another detector may provide stronger evidence.

        # --------------------------------------------------------------
        # 4. Optional adaptive anomaly signal. It never creates a standalone
        # alert because generic packet oddness is too noisy.
        # --------------------------------------------------------------
        ml_anomaly = self._ml_check(pkt_len, dport, proto, now)

        if ml_anomaly and self.detect_packet_anomaly and not source_is_local:
            # Only surface it if the packet is directed at the local machine.
            if destination_is_local:
                self._emit_intrusion(
                    attack_type="network_anomaly",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    destination_port=dport,
                    severity="medium",
                    summary="Traffic from a remote device looks unusual compared with recent network activity.",
                    details=(
                        f"Packet size was {pkt_len} bytes on protocol {proto}. "
                        "Vigil's adaptive model marked this as unusual; this signal "
                        "is not by itself proof of an attack."
                    ),
                    now=now,
                )
                return

        # --------------------------------------------------------------
        # Human-friendly safe telemetry. Do not expose raw protocol numbers
        # or packet sizes on every line.
        # --------------------------------------------------------------
        if destination_is_local and not source_is_local:
            if dport:
                self._safe_log(
                    f"Incoming network activity from {self._friendly_endpoint(src_ip, dport)} was observed.",
                    now,
                )
            else:
                self._safe_log(
                    f"Incoming network activity from {src_ip} was observed.",
                    now,
                )
        elif source_is_local:
            if dport:
                self._safe_log(
                    f"Your computer is communicating with {self._friendly_endpoint(dst_ip, dport)}.",
                    now,
                )
            else:
                self._safe_log(
                    f"Your computer is communicating with {dst_ip}.",
                    now,
                )
        else:
            self._safe_log("Network traffic was observed between other devices.", now)

    # ------------------------------------------------------------------
    # Worker lifecycle
    # ------------------------------------------------------------------

    def run(self):
        self.running = True
        self.local_ips = self._discover_local_ips()

        self.log_signal.emit(
            "Vigil IDS is starting — watching network traffic for suspicious activity.",
            False,
        )

        try:
            from scapy.all import IP, TCP, UDP, Raw, conf, sniff

            conf.verb = 0

            # Importing the optional ML stack here keeps GUI startup fast.
            self._init_ml_engine()

            self.log_signal.emit(
                "IDS is active — monitoring the network in real time.",
                False,
            )

            def process_packet(packet):
                self._process_packet(packet, IP, TCP, UDP, Raw)

            # Prefer all working Npcap interfaces so Vigil does not silently
            # miss traffic when the machine has Wi-Fi + Ethernet + VPN adapters.
            try:
                from scapy.all import get_working_ifaces
                interfaces = list(get_working_ifaces())
            except Exception:
                interfaces = None

            if interfaces:
                self.log_signal.emit(
                    f"IDS is watching {len(interfaces)} active network interface(s).",
                    False,
                )

            while self.running:
                try:
                    sniff(
                        iface=interfaces or None,
                        filter="ip",
                        prn=process_packet,
                        store=False,
                        timeout=0.75,
                    )
                except Exception:
                    # If a single interface becomes unavailable (VPN/Wi-Fi
                    # reconnect, adapter change, etc.), refresh the list
                    # instead of killing the IDS worker.
                    try:
                        interfaces = list(get_working_ifaces())
                    except Exception:
                        interfaces = None
                    time.sleep(0.05)

        except PermissionError:
            self.log_signal.emit(
                "IDS could not start — Windows blocked network monitoring. "
                "Run Vigil with administrator permission.",
                True,
            )
        except Exception as exc:
            error = str(exc).strip() or "unknown network capture error"
            self.log_signal.emit(
                f"IDS could not monitor the network: {error}. "
                "Check that Npcap is installed and its Windows service is available.",
                True,
            )
        finally:
            self.running = False

    # ------------------------------------------------------------------
    # Response / containment
    # ------------------------------------------------------------------

    def block_remote_ip(self, remote_ip):
        """
        Add a Windows Defender Firewall block for a remote IP.

        Returns:
            (success: bool, message: str)

        The method only targets the supplied remote IP. It does not change
        Vigil's other UI or alter unrelated firewall rules.
        """
        if not remote_ip:
            return False, "No remote address was supplied."

        try:
            import ipaddress
            address = ipaddress.ip_address(remote_ip)
            if address.is_loopback or str(address) in self.local_ips:
                return False, "Vigil will not block one of this computer's own addresses."
        except ValueError:
            return False, "The supplied network address is not valid."

        if not hasattr(__import__("sys"), "platform"):
            return False, "Unsupported operating system."

        if __import__("sys").platform != "win32":
            return False, "Automatic firewall blocking is currently implemented for Windows."

        import subprocess

        rule_name = f"Vigil IDS Block {remote_ip}"
        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={remote_ip}",
            "profile=any",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as exc:
            return False, f"Vigil could not create the firewall rule: {exc}"

        if result.returncode == 0:
            return True, f"Vigil blocked incoming connections from {remote_ip}."

        stderr = (result.stderr or result.stdout or "").strip()
        if "access is denied" in stderr.lower() or "requires elevation" in stderr.lower():
            return False, "Windows requires administrator permission before Vigil can block this address."

        return False, f"Windows could not create the block rule: {stderr or 'unknown firewall error'}"

    def stop(self):
        self.running = False
        if self.isRunning():
            self.wait(1500)
