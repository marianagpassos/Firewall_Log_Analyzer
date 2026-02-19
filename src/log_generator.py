#!/usr/bin/env python3
"""
Realistic firewall log generator for testing purposes.

Produces a mix of normal network traffic and simulated attack patterns,
allowing the LogAnalyzer to be tested against known scenarios without
requiring access to a live firewall.
"""

import os
import random
from datetime import datetime, timedelta
from typing import List, Optional


class LogGenerator:
    """
    Generates realistic firewall logs containing both benign traffic
    and a variety of simulated attack sequences.

    Supported attack types:
      - SSH Brute Force
      - Port Scan
      - NetBIOS anomaly
      - SMB exploitation
      - ICMP sweep
      - Telnet / RDP attempts
    """

    def __init__(self):
        # --- Network address pools ---

        # Internal IP addresses (RFC 1918 ranges)
        self.internal_ips = [
            "10.0.0.5", "10.0.0.6", "10.0.0.7", "10.0.0.8", "10.0.0.10",
            "10.0.0.20", "10.0.0.50", "192.168.1.10", "192.168.1.50",
            "192.168.1.100", "192.168.1.200",
        ]

        # External IP addresses (TEST-NET ranges, safe to use in examples)
        self.external_ips = [
            "203.0.113.10", "203.0.113.15", "198.51.100.20", "198.51.100.25",
            "45.33.22.11", "45.33.22.15", "185.130.5.10", "185.130.5.20",
        ]

        # The firewall's own IP — appears in every log line
        self.firewall_ip = "192.168.1.1"

        # --- Log line templates (normal traffic) ---
        # Each tuple: (action, protocol, src_template, dst_template, message_template)
        self.normal_logs = [
            ("allow", "tcp",  "{src}:{src_port}", "{dst}:{dst_port}", "Normal {protocol} traffic"),
            ("allow", "udp",  "{src}:{src_port}", "{dst}:{dst_port}", "DNS query (normal)"),
            ("allow", "tcp",  "{src}:{src_port}", "{dst}:443",        "HTTPS traffic to internal server"),
            ("allow", "tcp",  "{src}:{src_port}", "{dst}:80",         "HTTP web traffic"),
        ]

        # --- Log line templates (attack traffic) ---
        self.attack_logs = [
            # SSH Brute Force — repeated failed logins to port 22
            ("deny", "tcp", "{src}:{src_port}", "{dst}:22",
             "Failed password for {user} (SSH Brute Force)"),

            # Port Scan — sequential destination ports
            ("deny", "tcp", "{src}:{src_port}", "{dst}:{dst_port}",
             "Port Scan detected: Sequential ports"),

            # Anomalous NetBIOS — from an external (public) IP to a broadcast address
            ("deny", "udp", "{src}:{src_port}", "{dst}:137",
             "NetBIOS Name Query broadcast - Suspicious external source"),

            # SMB Exploitation — targeting Windows file-sharing port
            ("deny", "tcp", "{src}:{src_port}", "{dst}:445",
             "Possible SMB exploitation attempt"),

            # ICMP Sweep — pinging many hosts to map the network
            ("deny", "icmp", "{src}:0", "{dst}:0",
             "ICMP Sweep detected"),

            # Telnet — insecure remote access protocol
            ("deny", "tcp", "{src}:{src_port}", "{dst}:23",
             "Telnet access attempt - Protocol insecure"),

            # RDP — Remote Desktop from an external source
            ("deny", "tcp", "{src}:{src_port}", "{dst}:3389",
             "RDP Connection Attempt"),
        ]

        # Common usernames tried during brute-force attacks
        self.users = ["root", "admin", "user", "administrator", "guest"]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _random_port(self) -> int:
        """Returns a random ephemeral port number (1024–65535)."""
        return random.randint(1024, 65535)

    def _generate_timestamp(self, base_time: Optional[datetime] = None) -> str:
        """
        Formats a datetime object as a log timestamp string.

        Args:
            base_time: The datetime to format (uses now() if None).

        Returns:
            Timestamp string in 'YYYY-MM-DD HH:MM:SS' format.
        """
        if base_time is None:
            base_time = datetime.now()
        return base_time.strftime('%Y-%m-%d %H:%M:%S')

    # ------------------------------------------------------------------
    # Individual log-line generators
    # ------------------------------------------------------------------

    def generate_normal_log(self, timestamp: datetime) -> str:
        """
        Generates a single benign traffic log line.

        70 % of the time traffic stays internal; 30 % goes to an external IP.

        Args:
            timestamp: The datetime to stamp on the log line.

        Returns:
            A formatted log line string.
        """
        template = random.choice(self.normal_logs)
        action, protocol, src_template, dst_template, message = template

        # Choose source and destination IPs
        if random.random() < 0.7:
            # Internal-to-internal traffic
            src_ip = random.choice(self.internal_ips)
            dst_ip = random.choice(self.internal_ips)
        else:
            # Internal-to-external traffic
            src_ip = random.choice(self.internal_ips)
            dst_ip = random.choice(self.external_ips)

        src_port = self._random_port()
        # If template hard-codes port 80 on the destination, respect that
        dst_port = 80 if protocol == "tcp" and "80" in dst_template else self._random_port()

        # Render templates
        src = src_template.format(src=src_ip, src_port=src_port)
        dst = dst_template.format(dst=dst_ip, dst_port=dst_port)
        msg = message.format(protocol=protocol.upper())

        return (f"{self._generate_timestamp(timestamp)} | {self.firewall_ip} | "
                f"{action} | {protocol} | {src} | {dst} | {msg}")

    def generate_ssh_bruteforce(self, timestamp: datetime, src_ip: str,
                                dst_ip: str, count: int) -> List[str]:
        """
        Generates a sequence of SSH brute-force log lines.

        Each line is timestamped one second apart and uses a random
        username from the common username list.

        Args:
            timestamp: Start time for the first attempt.
            src_ip:    IP address of the attacker.
            dst_ip:    IP address of the SSH server being targeted.
            count:     Number of failed attempts to generate.

        Returns:
            List of formatted log line strings.
        """
        logs = []
        for i in range(count):
            ts       = timestamp + timedelta(seconds=i)
            src_port = self._random_port()
            user     = random.choice(self.users)

            log = (f"{self._generate_timestamp(ts)} | {self.firewall_ip} | deny | tcp | "
                   f"{src_ip}:{src_port} | {dst_ip}:22 | "
                   f"Failed password for {user} (SSH Brute Force)")
            logs.append(log)

        return logs

    def generate_port_scan(self, timestamp: datetime, src_ip: str,
                           dst_ip: str, ports: List[int]) -> List[str]:
        """
        Generates a port-scan sequence against a list of target ports.

        Each connection attempt is timestamped one second after the previous.

        Args:
            timestamp: Start time for the first probe.
            src_ip:    IP address of the scanner.
            dst_ip:    IP address of the scanned host.
            ports:     Ordered list of destination port numbers to scan.

        Returns:
            List of formatted log line strings.
        """
        logs = []
        for i, port in enumerate(ports):
            ts       = timestamp + timedelta(seconds=i)
            src_port = self._random_port()

            log = (f"{self._generate_timestamp(ts)} | {self.firewall_ip} | deny | tcp | "
                   f"{src_ip}:{src_port} | {dst_ip}:{port} | "
                   f"Port Scan detected: Sequential ports")
            logs.append(log)

        return logs

    def generate_icmp_sweep(self, timestamp: datetime, src_ip: str,
                            targets: List[str]) -> List[str]:
        """
        Generates an ICMP sweep (ping sweep) sequence.

        One ICMP packet is simulated per target host, one second apart.

        Args:
            timestamp: Start time for the sweep.
            src_ip:    IP address of the scanning host.
            targets:   List of target IP addresses to ping.

        Returns:
            List of formatted log line strings.
        """
        logs = []
        for i, target in enumerate(targets):
            ts = timestamp + timedelta(seconds=i)

            log = (f"{self._generate_timestamp(ts)} | {self.firewall_ip} | deny | icmp | "
                   f"{src_ip}:0 | {target}:0 | ICMP Sweep detected")
            logs.append(log)

        return logs

    # ------------------------------------------------------------------
    # Full sample dataset generator
    # ------------------------------------------------------------------

    def generate_sample_logs(self, output_file: str = "data/firewall_logs.txt",
                             num_logs: int = 50):
        """
        Generates a complete sample log file containing a realistic mix of
        normal traffic and known attack patterns.

        Breakdown:
          - 70 % normal traffic (randomised)
          - SSH brute force from 203.0.113.10 against 10.0.0.5
          - Port scan from 198.51.100.20 against 10.0.0.6
          - Single NetBIOS anomaly
          - Single SMB exploitation attempt
          - ICMP sweep from 45.33.22.20
          - Single Telnet access attempt

        Args:
            output_file: Destination path for the generated log file.
            num_logs:    Approximate total number of log lines to generate
                         (only normal-traffic lines count toward this limit).
        """
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        logs: List[str] = []
        # Base time anchored to 09:30:00 for reproducible-looking output
        base_time = datetime.now().replace(hour=9, minute=30, second=0)

        # --- Normal traffic (70 % of num_logs) ---
        normal_count = int(num_logs * 0.7)
        for i in range(normal_count):
            ts = base_time + timedelta(seconds=i * 2)  # 2-second intervals
            logs.append(self.generate_normal_log(ts))

        # --- Attack: SSH Brute Force (first wave — 5 attempts) ---
        logs.extend(self.generate_ssh_bruteforce(
            base_time + timedelta(seconds=15),
            src_ip="203.0.113.10", dst_ip="10.0.0.5", count=5,
        ))

        # --- Attack: SSH Brute Force (second wave — 3 attempts, same source) ---
        logs.extend(self.generate_ssh_bruteforce(
            base_time + timedelta(seconds=30),
            src_ip="203.0.113.10", dst_ip="10.0.0.5", count=3,
        ))

        # --- Attack: Port Scan (5 ports) ---
        logs.extend(self.generate_port_scan(
            base_time + timedelta(seconds=60),
            src_ip="198.51.100.20", dst_ip="10.0.0.6",
            ports=[79, 80, 81, 22, 443],
        ))

        # --- Attack: Anomalous NetBIOS from external IP ---
        ts = base_time + timedelta(seconds=90)
        logs.append(
            f"{self._generate_timestamp(ts)} | {self.firewall_ip} | deny | udp | "
            f"45.33.22.11:11111 | 192.168.1.255:137 | "
            f"NetBIOS Name Query broadcast - Suspicious external source"
        )

        # --- Attack: SMB Exploitation Attempt ---
        ts = base_time + timedelta(seconds=120)
        logs.append(
            f"{self._generate_timestamp(ts)} | {self.firewall_ip} | deny | tcp | "
            f"185.130.5.10:45000 | 10.0.0.7:445 | Possible SMB exploitation attempt"
        )

        # --- Attack: ICMP Sweep (5 targets) ---
        logs.extend(self.generate_icmp_sweep(
            base_time + timedelta(seconds=150),
            src_ip="45.33.22.20",
            targets=["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"],
        ))

        # --- Attack: Telnet access attempt ---
        ts = base_time + timedelta(seconds=180)
        logs.append(
            f"{self._generate_timestamp(ts)} | {self.firewall_ip} | deny | tcp | "
            f"45.33.22.15:40000 | 192.168.1.50:23 | Telnet access attempt - Protocol insecure"
        )

        # Sort all lines chronologically before writing
        logs.sort()

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(logs))

        # Print summary to console
        attack_count = len(logs) - normal_count
        print(f"[OK] Generated {len(logs)} sample log lines in {output_file}")
        print(f"     Normal traffic  : {normal_count} lines")
        print(f"     Malicious traffic: {attack_count} lines")