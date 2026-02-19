"""
Unit tests for the LogAnalyzer class.

Covers:
  - Detecting SSH brute-force attacks
  - Detecting port scanning
  - Detecting anomalous NetBIOS traffic
  - Detecting SMB exploitation attempts
  - Detecting ICMP sweeps
  - Loading a log file from disk
  - Exporting detected incidents to CSV

Run with:
    python -m unittest tests/test_analyzer.py
"""

import os
import unittest
from datetime import datetime, timedelta

import sys
# Allow imports from the project root (e.g. 'from src.log_analyzer import ...')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.log_analyzer import LogAnalyzer

# Fixed directory for all files created during testing.
# Using a dedicated folder keeps test artefacts separate from production data.
TEST_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'test_output')


class TestLogAnalyzer(unittest.TestCase):
    """Test suite for the LogAnalyzer class."""

    def setUp(self):
        """
        Runs before every test method.

        Creates a LogAnalyzer with low thresholds (3) so that small log
        snippets are enough to trigger detection, and ensures the output
        directory exists before any test tries to write to it.
        """
        self.analyzer = LogAnalyzer(
            time_window=60,
            brute_threshold=3,
            port_threshold=3,
            icmp_threshold=3,
        )
        os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _make_log_line(self, timestamp: str, action: str, protocol: str,
                       src: str, dst: str, message: str) -> str:
        """
        Builds a properly formatted log line string.

        Args:
            timestamp: 'YYYY-MM-DD HH:MM:SS' string.
            action:    'allow' or 'deny'.
            protocol:  'tcp', 'udp', or 'icmp'.
            src:       Source address as 'ip:port'.
            dst:       Destination address as 'ip:port'.
            message:   Free-text description field.

        Returns:
            Pipe-separated log line matching the expected format.
        """
        return f"{timestamp} | 192.168.1.1 | {action} | {protocol} | {src} | {dst} | {message}"

    # ------------------------------------------------------------------
    # Detection tests
    # ------------------------------------------------------------------

    def test_detect_ssh_bruteforce(self):
        """
        Verifies that three or more failed SSH attempts from the same source
        IP within the time window triggers an SSH Brute Force incident.
        """
        # Build three failed SSH log lines, each one second apart
        base = datetime(2024, 5, 27, 9, 30, 0)
        log_lines = "\n".join([
            self._make_log_line(
                (base + timedelta(seconds=i)).strftime('%Y-%m-%d %H:%M:%S'),
                "deny", "tcp",
                "203.0.113.10:5000", "10.0.0.5:22",
                "Failed password for root (SSH Brute Force)",
            )
            for i in range(3)
        ])

        incidents = self.analyzer.parse_and_analyze(log_lines)

        # Exactly one incident should be raised
        self.assertEqual(len(incidents), 1,
                         f"Expected 1 incident, got {len(incidents)}.")
        self.assertEqual(incidents[0]['type'], "SSH Brute Force Attack",
                         f"Wrong incident type: {incidents[0]['type']}")
        self.assertEqual(incidents[0]['src_ip'], "203.0.113.10")

    def test_detect_port_scan(self):
        """
        Verifies that connections to three or more distinct ports from the
        same source IP within the time window triggers a Port Scanning incident.
        """
        base = datetime(2024, 5, 27, 9, 30, 0)
        ports = [79, 80, 443]
        log_lines = "\n".join([
            self._make_log_line(
                (base + timedelta(seconds=i)).strftime('%Y-%m-%d %H:%M:%S'),
                "deny", "tcp",
                f"198.51.100.20:{5000 + i}", f"10.0.0.6:{port}",
                "Port Scan detected: Sequential ports",
            )
            for i, port in enumerate(ports)
        ])

        incidents = self.analyzer.parse_and_analyze(log_lines)

        self.assertEqual(len(incidents), 1,
                         f"Expected 1 incident, got {len(incidents)}.")
        self.assertEqual(incidents[0]['type'], "Port Scanning")
        self.assertEqual(incidents[0]['src_ip'], "198.51.100.20")

    def test_detect_netbios_anomaly(self):
        """
        Verifies that a single denied UDP NetBIOS packet from a public
        (non-private) IP triggers an Anomalous NetBIOS incident.
        """
        log_line = self._make_log_line(
            "2024-05-27 09:30:00",
            "deny", "udp",
            "45.33.22.11:11111", "192.168.1.255:137",
            "NetBIOS Name Query broadcast - Suspicious external source",
        )

        incidents = self.analyzer.parse_and_analyze(log_line)

        self.assertEqual(len(incidents), 1,
                         f"Expected 1 incident, got {len(incidents)}.")
        self.assertIn("NetBIOS", incidents[0]['type'])

    def test_detect_smb_exploitation(self):
        """
        Verifies that a denied connection to port 445 from a public IP
        triggers an SMB Exploitation Attempt incident.
        """
        log_line = self._make_log_line(
            "2024-05-27 09:30:00",
            "deny", "tcp",
            "185.130.5.10:45000", "10.0.0.7:445",
            "Possible SMB exploitation attempt",
        )

        incidents = self.analyzer.parse_and_analyze(log_line)

        self.assertEqual(len(incidents), 1,
                         f"Expected 1 incident, got {len(incidents)}.")
        self.assertIn("SMB", incidents[0]['type'])

    def test_detect_icmp_sweep(self):
        """
        Verifies that ICMP packets from the same source to three or more
        distinct hosts within the time window trigger an ICMP Sweep incident.
        """
        base = datetime(2024, 5, 27, 9, 30, 0)
        targets = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        log_lines = "\n".join([
            self._make_log_line(
                (base + timedelta(seconds=i)).strftime('%Y-%m-%d %H:%M:%S'),
                "deny", "icmp",
                "45.33.22.20:0", f"{target}:0",
                "ICMP Sweep detected",
            )
            for i, target in enumerate(targets)
        ])

        incidents = self.analyzer.parse_and_analyze(log_lines)

        self.assertEqual(len(incidents), 1,
                         f"Expected 1 incident, got {len(incidents)}.")
        self.assertIn("ICMP", incidents[0]['type'])

    def test_no_incident_on_normal_traffic(self):
        """
        Verifies that a single allowed HTTPS connection does not produce
        any security incidents.
        """
        log_line = self._make_log_line(
            "2024-05-27 09:30:00",
            "allow", "tcp",
            "192.168.1.100:50000", "10.0.0.5:443",
            "HTTPS traffic to internal server",
        )

        incidents = self.analyzer.parse_and_analyze(log_line)

        self.assertEqual(len(incidents), 0,
                         f"Expected 0 incidents for normal traffic, got {len(incidents)}.")

    def test_below_threshold_no_incident(self):
        """
        Verifies that fewer failed SSH attempts than the threshold (3)
        do not trigger an alert — i.e. two attempts should produce nothing.
        """
        base = datetime(2024, 5, 27, 9, 30, 0)
        log_lines = "\n".join([
            self._make_log_line(
                (base + timedelta(seconds=i)).strftime('%Y-%m-%d %H:%M:%S'),
                "deny", "tcp",
                "203.0.113.10:5000", "10.0.0.5:22",
                "Failed password for root (SSH Brute Force)",
            )
            for i in range(2)  # Only 2 attempts — below the threshold of 3
        ])

        incidents = self.analyzer.parse_and_analyze(log_lines)

        self.assertEqual(len(incidents), 0,
                         "Expected 0 incidents when below brute-force threshold.")

    # ------------------------------------------------------------------
    # File I/O tests
    # ------------------------------------------------------------------

    def test_load_logs(self):
        """
        Verifies that load_logs() can read a file and return its contents.

        Creates a minimal one-line log file in the test output directory,
        calls load_logs(), and checks that the content is returned and
        contains the expected string.
        """
        log_file = os.path.join(TEST_OUTPUT_DIR, 'test_log.txt')

        # Write a minimal, valid log line
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write(
                "2024-05-27 09:30:15 | 192.168.1.1 | deny | tcp | "
                "10.0.0.5:54321 | 203.0.113.10:22 | Test log\n"
            )

        content = self.analyzer.load_logs(log_file)

        self.assertIsNotNone(content,
                             "load_logs() returned None — file may not have been read.")
        self.assertIn("Test log", content,
                      "Expected log message not found in loaded content.")

        print(f"\n[INFO] Log file written to: {log_file}")

    def test_csv_export(self):
        """
        Verifies that save_csv() produces a valid CSV file containing
        the incidents that were added to the analyzer.

        Manually injects a synthetic incident (bypassing parsing), exports
        to CSV, then checks that the file exists and contains the expected values.
        """
        # Inject a synthetic incident directly
        self.analyzer._add_incident({
            'type':        "SSH Brute Force Attack",
            'src_ip':      "203.0.113.10",
            'dst_ip':      "10.0.0.5",
            'protocol':    "tcp",
            'description': "Test description",
            'details':     "3 attempts",
        })

        csv_file = os.path.join(TEST_OUTPUT_DIR, 'test_incidents.csv')
        self.analyzer.save_csv(csv_file)

        # File must exist after export
        self.assertTrue(os.path.exists(csv_file),
                        f"CSV file was not created at {csv_file}.")

        # CSV must contain both the incident type and the source IP
        with open(csv_file, 'r', encoding='utf-8') as f:
            content = f.read()

        self.assertIn("SSH Brute Force Attack", content,
                      "Incident type not found in CSV output.")
        self.assertIn("203.0.113.10", content,
                      "Source IP not found in CSV output.")

        print(f"\n[INFO] CSV file written to: {csv_file}")


if __name__ == '__main__':
    unittest.main()