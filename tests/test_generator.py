"""
Unit tests for the LogGenerator class.

Covers:
  - Generating a single normal traffic log line
  - Generating an SSH brute-force sequence
  - Generating a port-scan sequence
  - Generating an ICMP sweep sequence
  - Generating a complete sample log file

Run with:
    python -m unittest tests/test_generator.py
"""

import unittest
import os
import tempfile
from datetime import datetime, timedelta

import sys
# Allow imports from the project root (e.g. 'from src.log_generator import ...')
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.log_generator import LogGenerator


class TestLogGenerator(unittest.TestCase):
    """Test suite for the LogGenerator class."""

    def setUp(self):
        """
        Runs before every test method.

        Creates a fresh LogGenerator instance and fixes a base timestamp
        (10:00:00) so that generated timestamps are predictable in assertions.
        """
        self.generator = LogGenerator()
        self.base_time = datetime.now().replace(hour=10, minute=0, second=0)

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_generate_normal_log(self):
        """
        Verifies that a single normal traffic log line has the correct format.

        Checks:
          - Exactly 7 pipe-separated fields are present.
          - The timestamp in the line matches the datetime passed in.
        """
        log = self.generator.generate_normal_log(self.base_time)

        # A valid log line must have exactly 7 fields when split on ' | '
        parts = log.split(' | ')
        self.assertEqual(len(parts), 7,
                         f"Expected 7 fields, got {len(parts)}: {log}")

        # The date/hour portion of the timestamp must appear in the line
        self.assertIn(self.base_time.strftime('%Y-%m-%d %H:%M'), log,
                      "Timestamp not found in generated log line.")

    def test_generate_ssh_bruteforce(self):
        """
        Verifies that generate_ssh_bruteforce() produces the correct number
        of log lines with the right content.

        Checks per line:
          - Each line is stamped one second after the previous one.
          - Action is 'deny', protocol is 'tcp'.
          - Source IP and destination (target:22) are correct.
          - Message contains 'Failed password'.
        """
        logs = self.generator.generate_ssh_bruteforce(
            self.base_time,
            src_ip="203.0.113.10",
            dst_ip="10.0.0.5",
            count=5,
        )

        # Must produce exactly as many lines as requested
        self.assertEqual(len(logs), 5,
                         f"Expected 5 log lines, got {len(logs)}.")

        for i, log in enumerate(logs):
            # Each line should be one second later than the base time
            expected_time = self.base_time + timedelta(seconds=i)
            self.assertIn(expected_time.strftime('%H:%M:%S'), log,
                          f"Incorrect timestamp on line {i}: {log}")

            # Verify required fields
            self.assertIn("deny",            log, f"Line {i} missing 'deny'.")
            self.assertIn("tcp",             log, f"Line {i} missing 'tcp'.")
            self.assertIn("203.0.113.10",    log, f"Line {i} missing source IP.")
            self.assertIn("10.0.0.5:22",     log, f"Line {i} missing destination 'ip:22'.")
            self.assertIn("Failed password", log, f"Line {i} missing 'Failed password'.")

    def test_generate_port_scan(self):
        """
        Verifies that generate_port_scan() produces one log line per port,
        each containing the correct destination port number and the
        'Port Scan detected' message.
        """
        ports = [79, 80, 81, 22, 443]
        logs = self.generator.generate_port_scan(
            self.base_time,
            src_ip="198.51.100.20",
            dst_ip="10.0.0.6",
            ports=ports,
        )

        # One log line per port
        self.assertEqual(len(logs), len(ports),
                         f"Expected {len(ports)} lines, got {len(logs)}.")

        for i, log in enumerate(logs):
            # Each line must reference the correct destination port
            self.assertIn(f":{ports[i]}", log,
                          f"Line {i} missing port ':{ports[i]}'.")
            # Each line must carry the port scan signature
            self.assertIn("Port Scan detected", log,
                          f"Line {i} missing 'Port Scan detected'.")

    def test_generate_icmp_sweep(self):
        """
        Verifies that generate_icmp_sweep() produces one log line per target,
        each containing the correct target IP, the 'ICMP Sweep' message,
        and the 'icmp' protocol field.
        """
        targets = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        logs = self.generator.generate_icmp_sweep(
            self.base_time,
            src_ip="45.33.22.20",
            targets=targets,
        )

        # One log line per target host
        self.assertEqual(len(logs), len(targets),
                         f"Expected {len(targets)} lines, got {len(logs)}.")

        for i, log in enumerate(logs):
            # Each line must reference the correct target IP
            self.assertIn(targets[i], log,
                          f"Line {i} missing target IP '{targets[i]}'.")
            self.assertIn("ICMP Sweep", log,
                          f"Line {i} missing 'ICMP Sweep'.")
            self.assertIn("icmp", log,
                          f"Line {i} missing 'icmp' protocol.")

    def test_generate_sample_logs(self):
        """
        End-to-end test: verifies that generate_sample_logs() writes a
        properly structured file containing both normal and attack traffic.

        Uses a temporary file so no permanent artefacts are left on disk.

        Checks:
          - The output file is created.
          - At least 15 log lines are written.
          - The file contains SSH Brute Force entries.
          - The file contains Port Scan entries.
        """
        # Create a temporary file; delete=False so we can pass the path to the generator
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            temp_file = f.name

        try:
            # Generate a small dataset (20 normal lines + fixed attack sequences)
            self.generator.generate_sample_logs(temp_file, num_logs=20)

            # --- Assertion 1: file was created ---
            self.assertTrue(os.path.exists(temp_file),
                            f"Log file was not created at {temp_file}.")

            with open(temp_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                content = ''.join(lines)

            # --- Assertion 2: sufficient line count ---
            self.assertGreaterEqual(len(lines), 15,
                                    f"Expected at least 15 lines, got {len(lines)}.")

            # --- Assertion 3: attack patterns present ---
            self.assertIn("SSH Brute Force", content,
                          "SSH Brute Force pattern not found in generated logs.")
            self.assertIn("Port Scan", content,
                          "Port Scan pattern not found in generated logs.")

        finally:
            # Always clean up the temporary file, even if an assertion fails
            if os.path.exists(temp_file):
                os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main()