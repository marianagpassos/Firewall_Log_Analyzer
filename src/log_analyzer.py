#!/usr/bin/env python3

"""
Main firewall log analysis module.
Contains the LogAnalyzer class responsible for threat detection.

Supported detections:
  - SSH Brute Force
  - Port Scanning
  - Anomalous NetBIOS Traffic
  - SMB Exploitation Attempts
  - ICMP Sweep (network mapping)
"""

import os
import csv
import ipaddress
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Tuple


class LogAnalyzer:
    """
    Firewall log analyzer with threat detection capabilities.

    Supports both historical log analysis and real-time processing.

    Detects:
    - SSH Brute Force
    - Port Scanning
    - Anomalous NetBIOS Traffic
    - SMB Exploitation Attempts
    - ICMP Sweep (network reconnaissance)
    """

    def __init__(self, time_window: int = 60, brute_threshold: int = 3,
                 port_threshold: int = 3, icmp_threshold: int = 3):
        """
        Initializes the analyzer with configurable detection parameters.

        Args:
            time_window:      Time window in seconds used for event correlation.
            brute_threshold:  Number of failed attempts before triggering a brute-force alert.
            port_threshold:   Number of distinct ports before triggering a port scan alert.
            icmp_threshold:   Number of distinct ICMP targets before triggering a sweep alert.
        """
        self.time_window = time_window
        self.brute_threshold = brute_threshold
        self.port_threshold = port_threshold
        self.icmp_threshold = icmp_threshold

        # --- Tracking data structures ---
        # Maps source IP → list of epoch timestamps of SSH failed attempts
        self.brute_force_attempts: Dict[str, List[float]] = defaultdict(list)

        # Maps source IP → list of (epoch, destination port) tuples for port scan tracking
        self.port_scan_attempts: Dict[str, List[Tuple[float, str]]] = defaultdict(list)

        # Maps source IP → list of (epoch, target IP) tuples for ICMP sweep tracking
        self.icmp_sweep_attempts: Dict[str, List[Tuple[float, str]]] = defaultdict(list)

        # --- Results ---
        self.parsed_logs: List[Dict[str, Any]] = []      # All successfully parsed log entries
        self.incidents: List[Dict[str, Any]] = []         # Detected security incidents
        self.reported_incidents: Set[str] = set()         # IDs of already-reported incidents (deduplication)
        self._incident_counter: int = 0                   # Auto-incrementing incident counter

        # Pre-defined mitigation guidance per attack type
        self.mitigation_methods = self._init_mitigation_methods()

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _init_mitigation_methods(self) -> Dict[str, Dict[str, List[str]]]:
        """
        Builds the mitigation knowledge base.

        Returns a dictionary keyed by incident type, each containing
        three lists: prevention, detection, and response actions.
        """
        return {
            "SSH Brute Force Attack": {
                "prevention": [
                    "Implement rate-limiting (max 5 attempts/min per IP)",
                    "Use SSH key-based authentication instead of passwords",
                    "Change the default SSH port (22 → non-standard port)",
                ],
                "detection": [
                    "Monitor authentication logs for repeated failures",
                    "Set threshold-based alerts per source IP",
                    "Correlate attempts over time to identify patterns",
                ],
                "response": [
                    "Temporarily block the offending IP at the firewall",
                    "Add IP to the internal reputation block-list",
                    "Notify the security team immediately",
                ],
            },
            "Port Scanning": {
                "prevention": [
                    "Deploy an Intrusion Prevention System (IPS)",
                    "Configure firewalls to detect and block sweep behaviour",
                    "Use port-knocking for sensitive services",
                ],
                "detection": [
                    "Monitor connections to multiple ports on the same host",
                    "Detect sequential port patterns from a single source",
                    "Analyse SYN packets without completed three-way handshakes",
                ],
                "response": [
                    "Temporarily block the offending IP",
                    "Log the event for forensic analysis",
                    "Increase monitoring on the targeted host",
                ],
            },
            "Anomalous Traffic - External NetBIOS": {
                "prevention": [
                    "Block legacy protocols at the network perimeter",
                    "Implement network segmentation (VLANs)",
                    "Disable NetBIOS on externally exposed interfaces",
                ],
                "detection": [
                    "Monitor NetBIOS traffic at the network edge",
                    "Alert on unexpected protocols from external sources",
                    "Analyse external sources targeting internal broadcast addresses",
                ],
                "response": [
                    "Block the anomalous traffic immediately",
                    "Check for internal host compromise",
                    "Investigate potential data exfiltration",
                ],
            },
            "SMB Exploitation Attempt": {
                "prevention": [
                    "Keep Windows systems fully patched",
                    "Disable SMBv1 and other vulnerable SMB versions",
                    "Restrict SMB access to internal IP ranges only",
                ],
                "detection": [
                    "Monitor external SMB connection attempts",
                    "Detect known exploitation signatures (e.g. EternalBlue)",
                    "Analyse malformed SMB packets",
                ],
                "response": [
                    "Block the source IP immediately",
                    "Inspect internal systems on the same subnet",
                    "Verify whether remote code execution occurred",
                ],
            },
            "ICMP Sweep - Network Mapping": {
                "prevention": [
                    "Limit ICMP traffic at the perimeter firewall",
                    "Apply ICMP rate-limiting rules",
                    "Deploy honeypots to detect reconnaissance",
                ],
                "detection": [
                    "Monitor spikes in ICMP Echo Request traffic",
                    "Detect sequential IP patterns in ICMP traffic",
                    "Correlate sweeps with other suspicious activity",
                ],
                "response": [
                    "Block the sweep source IP",
                    "Document as a reconnaissance phase indicator",
                    "Increase monitoring of the internal network",
                ],
            },
        }

    # ------------------------------------------------------------------
    # Log loading
    # ------------------------------------------------------------------

    def load_logs(self, filepath: str) -> Optional[str]:
        """
        Reads a log file from disk and returns its contents as a string.

        Args:
            filepath: Path to the firewall log file.

        Returns:
            File contents as a string, or None on error.
        """
        print(f"[*] Loading logs from: {filepath}")

        if not os.path.isfile(filepath):
            print(f"[!] ERROR: File '{filepath}' not found.")
            return None

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            print(f"[*] File loaded successfully ({len(content.splitlines())} lines).")
            return content
        except Exception as e:
            print(f"[!] ERROR reading file: {e}")
            return None

    # ------------------------------------------------------------------
    # Log parsing
    # ------------------------------------------------------------------

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single log line into a structured dictionary.

        Expected format (pipe-separated):
          timestamp | firewall_ip | action | protocol | src_ip:port | dst_ip:port | message

        Args:
            line: Raw log line string.

        Returns:
            Dictionary with parsed fields, or None if the line is malformed.
        """
        parts = line.strip().split(' | ')
        if len(parts) < 7:
            return None  # Skip lines that don't match the expected format

        try:
            # Parse timestamp and convert to epoch seconds for time-window calculations
            timestamp_str = parts[0]
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            epoch = timestamp.timestamp()

            # Parse source address (IP:port)
            src_parts = parts[4].split(':')
            src_ip = src_parts[0]
            src_port = src_parts[1] if len(src_parts) > 1 else '0'

            # Parse destination address (IP:port)
            dst_parts = parts[5].split(':')
            dst_ip = dst_parts[0]
            dst_port = dst_parts[1] if len(dst_parts) > 1 else '0'

            return {
                'timestamp':   timestamp_str,
                'epoch':       epoch,        # Seconds since Unix epoch — used for time-window maths
                'firewall_ip': parts[1],
                'action':      parts[2].upper(),   # Normalise to uppercase: ALLOW / DENY
                'protocol':    parts[3].lower(),   # Normalise to lowercase: tcp / udp / icmp
                'src_ip':      src_ip,
                'src_port':    src_port,
                'dst_ip':      dst_ip,
                'dst_port':    dst_port,
                'message':     parts[6],
            }
        except Exception:
            return None  # Silently skip unparseable lines

    # ------------------------------------------------------------------
    # Threat detection rules
    # ------------------------------------------------------------------

    def analyze_ssh_bruteforce(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detects SSH brute-force attacks by counting failed login attempts
        from the same source IP within the configured time window.

        NOTE: Uses entry['epoch'] (log timestamp) instead of time.time()
        so that historical log files are analysed correctly.

        Args:
            entry: Parsed log entry dictionary.

        Returns:
            Incident dictionary if threshold is exceeded, otherwise None.
        """
        msg_lower = entry['message'].lower()

        # Only consider denied TCP connections to port 22 with a "failed password" message
        if ("failed password" in msg_lower and
                entry['protocol'] == "tcp" and
                entry['dst_port'] == '22'):

            src_ip = entry['src_ip']
            current_time = entry['epoch']

            # Record this attempt
            self.brute_force_attempts[src_ip].append(current_time)

            # Slide the window: discard attempts older than time_window seconds
            self.brute_force_attempts[src_ip] = [
                ts for ts in self.brute_force_attempts[src_ip]
                if current_time - ts <= self.time_window
            ]

            # Trigger an alert if the threshold is reached
            if len(self.brute_force_attempts[src_ip]) >= self.brute_threshold:
                incident_id = f"SSH_Brute_{src_ip}"

                # Deduplicate: only report each source IP once per analysis run
                if incident_id not in self.reported_incidents:
                    self.reported_incidents.add(incident_id)
                    return {
                        'type':        "SSH Brute Force Attack",
                        'timestamp':   entry['timestamp'],
                        'src_ip':      src_ip,
                        'dst_ip':      entry['dst_ip'],
                        'protocol':    entry['protocol'],
                        'description': "Multiple failed SSH login attempts detected on port 22",
                        'details':     (f"{len(self.brute_force_attempts[src_ip])} attempts "
                                        f"within {self.time_window}s"),
                    }
        return None

    def analyze_port_scan(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detects port scanning by tracking the number of distinct destination ports
        contacted by the same source IP within the time window.

        NOTE: Uses entry['epoch'] for correct historical log analysis.

        Args:
            entry: Parsed log entry dictionary.

        Returns:
            Incident dictionary if threshold is exceeded, otherwise None.
        """
        msg_lower = entry['message'].lower()

        if "port scan" in msg_lower:
            src_ip = entry['src_ip']
            dst_port = entry['dst_port']
            current_time = entry['epoch']

            # Record (time, port) pair for this source
            self.port_scan_attempts[src_ip].append((current_time, dst_port))

            # Slide the window
            self.port_scan_attempts[src_ip] = [
                (ts, port) for ts, port in self.port_scan_attempts[src_ip]
                if current_time - ts <= self.time_window
            ]

            # Count unique destination ports within the window
            unique_ports = set(port for _, port in self.port_scan_attempts[src_ip])

            if len(unique_ports) >= self.port_threshold:
                incident_id = f"PortScan_{src_ip}_{entry['dst_ip']}"

                if incident_id not in self.reported_incidents:
                    self.reported_incidents.add(incident_id)

                    # Sort ports numerically where possible for readability
                    try:
                        ports_list = sorted(unique_ports, key=int)
                    except ValueError:
                        ports_list = sorted(unique_ports)

                    return {
                        'type':        "Port Scanning",
                        'timestamp':   entry['timestamp'],
                        'src_ip':      src_ip,
                        'dst_ip':      entry['dst_ip'],
                        'protocol':    entry['protocol'],
                        'description': "Multiple port sweep detected from a single source",
                        'details':     (f"{len(unique_ports)} ports scanned: "
                                        f"{', '.join(ports_list)}"),
                    }
        return None

    def analyze_netbios(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detects anomalous NetBIOS traffic originating from external (public) IP addresses.

        NetBIOS is a legacy LAN protocol; inbound NetBIOS from the internet is always suspicious.

        Args:
            entry: Parsed log entry dictionary.

        Returns:
            Incident dictionary if anomalous, otherwise None.
        """
        msg_lower = entry['message'].lower()

        if ("netbios" in msg_lower and
                entry['protocol'] == "udp" and
                entry['action'] == 'DENY'):
            try:
                src_ip_obj = ipaddress.ip_address(entry['src_ip'])

                # Only flag traffic from non-private (public) IP addresses
                if not src_ip_obj.is_private:
                    incident_id = f"NetBIOS_{entry['src_ip']}_{int(entry['epoch'])}"

                    if incident_id not in self.reported_incidents:
                        self.reported_incidents.add(incident_id)
                        return {
                            'type':        "Anomalous Traffic - External NetBIOS",
                            'timestamp':   entry['timestamp'],
                            'src_ip':      entry['src_ip'],
                            'dst_ip':      entry['dst_ip'],
                            'protocol':    entry['protocol'],
                            'description': "NetBIOS traffic received from an external IP address",
                            'details':     "Legacy protocol exposed at the network perimeter",
                        }
            except ValueError:
                pass  # Invalid IP address — skip silently
        return None

    def analyze_smb(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detects potential SMB exploitation attempts (e.g. EternalBlue) from external sources.

        SMB (port 445) should never be reachable from the internet.

        Args:
            entry: Parsed log entry dictionary.

        Returns:
            Incident dictionary if suspicious, otherwise None.
        """
        msg_lower = entry['message'].lower()

        # Match on SMB keyword in message OR direct connection to port 445
        if (("smb" in msg_lower or entry['dst_port'] == '445') and
                entry['action'] == 'DENY'):
            try:
                src_ip_obj = ipaddress.ip_address(entry['src_ip'])

                if not src_ip_obj.is_private:
                    incident_id = f"SMB_{entry['src_ip']}_{int(entry['epoch'])}"

                    if incident_id not in self.reported_incidents:
                        self.reported_incidents.add(incident_id)
                        return {
                            'type':        "SMB Exploitation Attempt",
                            'timestamp':   entry['timestamp'],
                            'src_ip':      entry['src_ip'],
                            'dst_ip':      entry['dst_ip'],
                            'protocol':    entry['protocol'],
                            'description': "External connection attempt to SMB port 445",
                            'details':     "Possible exploitation of Windows vulnerabilities",
                        }
            except ValueError:
                pass
        return None

    def analyze_icmp_sweep(self, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detects ICMP sweep (ping sweep) used for network reconnaissance.

        Aggregates multiple ICMP targets from the same source into a single
        incident once the icmp_threshold is reached within the time window.

        NOTE: Reports the incident only once per source IP (deduplication).

        Args:
            entry: Parsed log entry dictionary.

        Returns:
            Incident dictionary when threshold is first exceeded, otherwise None.
        """
        msg_lower = entry['message'].lower()

        if "icmp sweep" in msg_lower or ("icmp" in entry['protocol'] and "sweep" in msg_lower):
            src_ip = entry['src_ip']
            dst_ip = entry['dst_ip']
            current_time = entry['epoch']

            # Record (time, target_ip) pair
            self.icmp_sweep_attempts[src_ip].append((current_time, dst_ip))

            # Slide the window
            self.icmp_sweep_attempts[src_ip] = [
                (ts, target) for ts, target in self.icmp_sweep_attempts[src_ip]
                if current_time - ts <= self.time_window
            ]

            # Count unique targets within the window
            unique_targets = set(target for _, target in self.icmp_sweep_attempts[src_ip])

            if len(unique_targets) >= self.icmp_threshold:
                incident_id = f"ICMPSweep_{src_ip}"

                # Report only once — when the threshold is first crossed
                if incident_id not in self.reported_incidents:
                    self.reported_incidents.add(incident_id)
                    targets_list = sorted(unique_targets)
                    return {
                        'type':        "ICMP Sweep - Network Mapping",
                        'timestamp':   entry['timestamp'],
                        'src_ip':      src_ip,
                        'dst_ip':      ', '.join(targets_list[:5]),  # Show up to 5 targets
                        'protocol':    entry['protocol'],
                        'description': "ICMP sweep detected — network reconnaissance phase",
                        'details':     (f"Reconnaissance: {len(unique_targets)} "
                                        f"unique targets identified"),
                    }
        return None

    # ------------------------------------------------------------------
    # Entry-level dispatcher
    # ------------------------------------------------------------------

    def analyze_entry(self, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs all detection rules against a single parsed log entry.

        Args:
            entry: Structured log entry dictionary from parse_line().

        Returns:
            List of incident dictionaries (empty if nothing detected).
        """
        incidents = []

        # Chain of responsibility: each analyser is tried in sequence
        analyzers = [
            self.analyze_ssh_bruteforce,
            self.analyze_port_scan,
            self.analyze_netbios,
            self.analyze_smb,
            self.analyze_icmp_sweep,
        ]

        for analyzer in analyzers:
            result = analyzer(entry)
            if result:
                incidents.append(result)

        return incidents

    # ------------------------------------------------------------------
    # Full analysis pipeline
    # ------------------------------------------------------------------

    def parse_and_analyze(self, content: str) -> List[Dict[str, Any]]:
        """
        Parses and analyses all log lines in the provided content string.

        Resets internal state first, so the same LogAnalyzer object can be
        reused across multiple analysis runs.

        Args:
            content: Full contents of a firewall log file.

        Returns:
            List of all detected incidents.
        """
        # Reset all state to allow reuse of this object
        self.parsed_logs = []
        self.incidents = []
        self.reported_incidents = set()
        self._incident_counter = 0
        self.brute_force_attempts = defaultdict(list)
        self.port_scan_attempts = defaultdict(list)
        self.icmp_sweep_attempts = defaultdict(list)

        print("[*] Analysing security logs...")

        lines = content.strip().split('\n')
        incident_count = 0

        for line in lines:
            if not line.strip():
                continue  # Skip blank lines

            entry = self.parse_line(line)
            if not entry:
                continue  # Skip malformed lines

            self.parsed_logs.append(entry)

            # Run detection rules and store any new incidents
            new_incidents = self.analyze_entry(entry)
            for inc in new_incidents:
                self._add_incident(inc)
                incident_count += 1

        print(f"[*] Analysis complete: {len(self.parsed_logs)} lines processed, "
              f"{incident_count} incident(s) detected.")
        return self.incidents

    # ------------------------------------------------------------------
    # Incident storage
    # ------------------------------------------------------------------

    def _add_incident(self, incident_data: Dict[str, Any]):
        """
        Enriches a raw incident dict with an ID and mitigation guidance,
        then appends it to the incidents list.

        Args:
            incident_data: Basic incident fields from a detection rule.
        """
        self._incident_counter += 1
        inc_type = incident_data['type']

        # Look up mitigation guidance; fall back to generic advice if type is unknown
        mitigation = self.mitigation_methods.get(inc_type, {
            "prevention": ["Principle of least privilege"],
            "detection":  ["Continuous monitoring"],
            "response":   ["Forensic analysis"],
        })

        incident = {
            # Unique ID: type + source IP + zero-padded counter
            'id':                    (f"{inc_type.replace(' ', '_')}_"
                                      f"{incident_data['src_ip']}_"
                                      f"{self._incident_counter:04d}"),
            'timestamp':             incident_data.get('timestamp',
                                         datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'type':                  inc_type,
            'src_ip':                incident_data['src_ip'],
            'dst_ip':                incident_data['dst_ip'],
            'protocol':              incident_data['protocol'].upper(),
            'description':           incident_data['description'],
            'details':               incident_data['details'],
            'mitigation_prevention': ', '.join(mitigation['prevention']),
            'mitigation_detection':  ', '.join(mitigation['detection']),
            'mitigation_response':   ', '.join(mitigation['response']),
        }

        self.incidents.append(incident)
        print(f"   [ALERT] {inc_type} detected from {incident_data['src_ip']}!")

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def save_csv(self, filename: str = "reports/security_incidents.csv"):
        """
        Exports all detected incidents to a CSV file.

        Creates the output directory if it does not already exist.

        Args:
            filename: Destination path for the CSV file.
        """
        output_dir = os.path.dirname(os.path.abspath(filename))
        os.makedirs(output_dir, exist_ok=True)

        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header row
            writer.writerow([
                'ID', 'Timestamp', 'Type', 'Source IP', 'Destination IP',
                'Protocol', 'Description', 'Details',
                'Prevention', 'Detection', 'Response',
            ])

            for inc in self.incidents:
                writer.writerow([
                    inc['id'],
                    inc['timestamp'],
                    inc['type'],
                    inc['src_ip'],
                    inc['dst_ip'],
                    inc['protocol'],
                    inc['description'],
                    inc['details'],
                    inc['mitigation_prevention'],
                    inc['mitigation_detection'],
                    inc['mitigation_response'],
                ])

        print(f"[*] Incidents exported to {filename}")

    def print_summary(self):
        """Prints a formatted summary of all detected incidents to stdout."""
        print("\n" + "=" * 80)
        print("SECURITY INCIDENT REPORT")
        print("=" * 80)

        if not self.incidents:
            print("No incidents detected.")
            return

        # Count incidents per type
        type_counts = defaultdict(int)
        for inc in self.incidents:
            type_counts[inc['type']] += 1

        print(f"\n  Statistics:")
        print(f"    Total log lines analysed : {len(self.parsed_logs)}")
        print(f"    Total incidents detected  : {len(self.incidents)}")

        print(f"\n  Incidents by type:")
        for inc_type, count in type_counts.items():
            print(f"    {inc_type}: {count}")

        print(f"\n  Incident details:")
        for i, inc in enumerate(self.incidents, 1):
            print(f"\n    #{i} [{inc['timestamp']}] {inc['type']}")
            print(f"       Source: {inc['src_ip']}  ->  Destination: {inc['dst_ip']}")
            print(f"       Description : {inc['description']}")
            print(f"       Details     : {inc['details']}")