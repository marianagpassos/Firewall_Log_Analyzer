#!/usr/bin/env python3
"""
Firewall Log Analyzer — Main Entry Point

A command-line tool for analysing firewall logs and detecting security threats.

Usage examples:
    python main.py --analyze                        # Analyse the default log file
    python main.py --analyze --file logs.txt        # Analyse a specific log file
    python main.py --generate                       # Generate a sample log file
    python main.py --generate --num 100             # Generate 100 log lines
    python main.py --help                           # Show all options
"""

import argparse
import sys
import os

# Prevent Python from writing .pyc bytecode files into the source tree
sys.dont_write_bytecode = True

# Make the project root importable so 'from src.xxx import ...' works
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.log_analyzer import LogAnalyzer
from src.log_generator import LogGenerator
from src.html_report import HTMLReportGenerator


# Absolute path of the project root (directory containing this file)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Global configuration ---
# These values control detection thresholds and default file paths.
# In a production tool these would typically come from a config file (YAML/JSON).
CONFIG = {
    'time_window':    60,   # Seconds — sliding window used for event correlation
    'brute_threshold': 3,   # Failed SSH attempts before alerting
    'port_threshold':  3,   # Distinct ports before flagging a port scan
    'icmp_threshold':  3,   # ICMP targets before flagging a sweep
    'default_log':   os.path.join(BASE_DIR, 'data', 'firewall_logs.txt'),
    'csv_output':    os.path.join(BASE_DIR, 'reports', 'security_incidents.csv'),
    'html_output':   os.path.join(BASE_DIR, 'reports', 'security_report.html'),
}


# ------------------------------------------------------------------
# UI helpers
# ------------------------------------------------------------------

def print_banner():
    """Prints the ASCII art banner shown at program startup."""
    banner = """
    +----------------------------------------------------------+
    |      FIREWALL LOG ANALYZER - Python Security Tool        |
    |         Real-Time Threat Detection                        |
    +----------------------------------------------------------+
    """
    print(banner)


# ------------------------------------------------------------------
# Core workflow functions
# ------------------------------------------------------------------

def analyze_logs(filepath: str, generate_report: bool = True) -> bool:
    """
    Loads a firewall log file, runs threat detection, and outputs reports.

    Steps:
      1. Instantiate LogAnalyzer with CONFIG thresholds.
      2. Load the log file from disk.
      3. Parse every line and run all detection rules.
      4. Print a human-readable summary to stdout.
      5. Save incidents to a CSV file.
      6. Optionally generate an HTML report.

    Args:
        filepath:        Path to the firewall log file to analyse.
        generate_report: Whether to produce the HTML report (default True).

    Returns:
        True on success, False if the log file could not be loaded.
    """
    print(f"\n[*] Mode     : ANALYSIS")
    print(f"[*] File     : {filepath}")
    print(f"[*] Settings :")
    print(f"      Time window        : {CONFIG['time_window']}s")
    print(f"      Brute-force threshold: {CONFIG['brute_threshold']}")
    print(f"      Port-scan threshold  : {CONFIG['port_threshold']}")

    # Create the analyzer with the configured thresholds
    analyzer = LogAnalyzer(
        time_window=CONFIG['time_window'],
        brute_threshold=CONFIG['brute_threshold'],
        port_threshold=CONFIG['port_threshold'],
        icmp_threshold=CONFIG.get('icmp_threshold', 3),
    )

    # Load the log file
    log_data = analyzer.load_logs(filepath)
    if not log_data:
        print("[!] Could not load logs. Aborting.")
        return False

    # Parse and analyse all lines
    incidents = analyzer.parse_and_analyze(log_data)

    # Print summary table to stdout
    analyzer.print_summary()

    # Export incidents to CSV
    analyzer.save_csv(CONFIG['csv_output'])

    # Optionally generate the styled HTML report
    if generate_report:
        html_gen = HTMLReportGenerator()
        html_gen.generate(incidents, CONFIG['html_output'])

    return True


def generate_logs(output_file: str, num_logs: int = 50) -> bool:
    """
    Generates a sample firewall log file for testing purposes.

    The file will contain a mix of normal traffic and known attack
    patterns so that the analyzer can be validated.

    Args:
        output_file: Destination path for the generated log file.
        num_logs:    Total number of normal-traffic lines to generate
                     (attack lines are added on top of this count).

    Returns:
        True (generation always succeeds unless an OS error occurs).
    """
    print(f"\n[*] Mode    : LOG GENERATION")
    print(f"[*] Output  : {output_file}")
    print(f"[*] Log lines: {num_logs}")

    generator = LogGenerator()
    generator.generate_sample_logs(output_file, num_logs)

    return True


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------

def main():
    """
    Parses command-line arguments and dispatches to the appropriate
    workflow function.

    If no action flag is provided, the help text is printed.
    """
    parser = argparse.ArgumentParser(
        description='Firewall Log Analyzer — Security log analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --analyze
  python main.py --analyze --file data/my_logs.txt
  python main.py --generate
  python main.py --generate --num 100
        """,
    )

    # --- Action flags (mutually exclusive in practice) ---
    parser.add_argument('--analyze',  action='store_true',
                        help='Analyse a firewall log file for threats')
    parser.add_argument('--generate', action='store_true',
                        help='Generate a sample log file for testing')

    # --- Options ---
    parser.add_argument('--file', type=str, default=CONFIG['default_log'],
                        help=f'Log file path (default: {CONFIG["default_log"]})')
    parser.add_argument('--num',  type=int, default=50,
                        help='Number of log lines to generate (default: 50)')
    parser.add_argument('--no-html', action='store_true',
                        help='Skip HTML report generation during analysis')

    args = parser.parse_args()

    # If the user supplied no action flag, show help and exit
    if not (args.analyze or args.generate):
        parser.print_help()
        return

    print_banner()

    # Ensure required directories exist before any file operations
    os.makedirs(os.path.join(BASE_DIR, 'data'),    exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, 'reports'), exist_ok=True)

    # Dispatch to the selected workflow
    if args.generate:
        generate_logs(args.file, args.num)
    elif args.analyze:
        analyze_logs(args.file, not args.no_html)

    print("\n" + "=" * 60)
    print("[OK] Operation completed successfully.")
    print("=" * 60)


if __name__ == "__main__":
    main()