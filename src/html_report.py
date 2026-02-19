#!/usr/bin/env python3
"""
HTML Report Generator for Security Incidents.

Converts the incidents list (produced by LogAnalyzer) into a
styled, self-contained HTML report file.
"""

import os
from datetime import datetime
from typing import List, Dict, Any


class HTMLReportGenerator:
    """
    Generates a styled HTML report from the list of detected security incidents.

    The report includes:
      - A branded header with generation timestamp
      - Summary statistics (total incidents, attack types, offending IPs)
      - Incidents grouped by type, each with source/destination details
        and recommended mitigation steps
    """

    def __init__(self):
        # Inline CSS — kept here so the report is fully self-contained (no external stylesheets)
        self.css = """
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }
            h1 {
                color: #d32f2f;
                border-bottom: 3px solid #d32f2f;
                padding-bottom: 10px;
            }
            h2 {
                color: #1976d2;
                margin-top: 30px;
            }

            /* ---- Header banner ---- */
            .header {
                background: linear-gradient(135deg, #1e2b4f 0%, #2a3f6e 50%, #c41e3a 100%);
                color: white;
                padding: 20px 30px;
                border-radius: 20px;
                margin-bottom: 30px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                position: relative;
                overflow: hidden;
            }
            .header-content {
                display: flex;
                align-items: center;
                gap: 30px;
                position: relative;
                z-index: 2;
            }
            .header-logo {
                background: white;
                border-radius: 15px;
                padding: 10px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            }
            .header-logo img {
                height: 70px;
                width: auto;
                display: block;
            }
            .header-text { flex: 1; }
            .header h1 {
                margin: 0 0 10px 0;
                border: none;
                color: white;
                font-size: 2.2em;
                line-height: 1.2;
            }
            .header-title-main {
                display: block;
                font-weight: 300;
                font-size: 0.8em;
                opacity: 0.9;
            }
            .header-title-sub {
                display: block;
                font-weight: 700;
                font-size: 1.2em;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            .header-meta {
                display: flex;
                gap: 20px;
                margin-top: 15px;
            }
            .meta-item {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                background: rgba(255,255,255,0.15);
                padding: 8px 15px;
                border-radius: 30px;
                font-size: 0.9em;
                backdrop-filter: blur(5px);
                border: 1px solid rgba(255,255,255,0.1);
                flex-wrap: wrap;
            }
            .meta-credit {
                font-size: 0.75em;
                opacity: 0.8;
                margin-left: 4px;
                padding-left: 8px;
                border-left: 1px solid rgba(255,255,255,0.2);
            }
            .meta-icon { opacity: 0.9; }

            /* Decorative background circles on the header */
            .header-decoration {
                position: absolute;
                top: 0; right: 0; bottom: 0; left: 0;
                pointer-events: none;
                z-index: 1;
            }
            .decoration-circle {
                position: absolute;
                background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0) 70%);
                border-radius: 50%;
            }
            .decoration-circle:nth-child(1) { width:300px; height:300px; top:-150px; right:-50px; }
            .decoration-circle:nth-child(2) {
                width:200px; height:200px; bottom:-100px; left:10%;
                background: radial-gradient(circle, rgba(196,30,58,0.2) 0%, rgba(196,30,58,0) 70%);
            }
            .decoration-circle:nth-child(3) {
                width:150px; height:150px; top:20px; left:40%;
                background: radial-gradient(circle, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0) 70%);
            }

            /* ---- Statistics grid ---- */
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .stat-card {
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                text-align: center;
            }
            .stat-number { font-size: 36px; font-weight: bold; color: #1976d2; }
            .stat-label  { color: #666; font-size: 14px; text-transform: uppercase; }

            /* ---- Individual incident cards ---- */
            .incident {
                background: white;
                border-left: 5px solid;   /* colour set by severity class below */
                margin: 20px 0;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            /* Severity colour coding */
            .incident.critical { border-left-color: #d32f2f; }
            .incident.high     { border-left-color: #f57c00; }
            .incident.medium   { border-left-color: #fbc02d; }
            .incident.low      { border-left-color: #388e3c; }

            .incident-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
            }
            .incident-type { font-size: 18px; font-weight: bold; color: #333; }
            .incident-time { color: #999; font-size: 14px; }

            .incident-details {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin: 15px 0;
                padding: 15px;
                background: #f8f9fa;
                border-radius: 5px;
            }
            .detail-item   { margin: 5px 0; }
            .detail-label  { font-weight: bold; color: #555; }

            /* Mitigation box */
            .mitigation {
                margin-top: 15px;
                padding: 15px;
                background: #e8f5e8;
                border-radius: 5px;
            }
            .mitigation h4  { margin-top: 0; color: #2e7d32; }
            .mitigation ul  { margin: 5px 0; padding-left: 20px; }

            .footer {
                margin-top: 40px;
                text-align: center;
                color: #999;
                font-size: 12px;
            }

            /* ---- Incident-type badges ---- */
            .badge {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 12px;
                font-weight: bold;
                color: white;
            }
            .badge.ssh     { background: #d32f2f; }
            .badge.scan    { background: #f57c00; }
            .badge.netbios { background: #7b1fa2; }
            .badge.smb     { background: #0288d1; }
            .badge.icmp    { background: #388e3c; }
        </style>
        """

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    def _get_severity(self, incident_type: str) -> str:
        """
        Maps an incident type string to a CSS severity class.

        Returns one of: 'critical', 'high', 'medium', 'low'.
        """
        critical_keywords = ["SSH Brute Force", "SMB", "Exploitation"]
        high_keywords = ["Port Scanning", "ICMP Sweep"]

        if any(k in incident_type for k in critical_keywords):
            return "critical"
        elif any(k in incident_type for k in high_keywords):
            return "high"
        else:
            return "medium"

    def _get_badge_class(self, incident_type: str) -> str:
        """
        Returns the CSS class name for the count badge next to the incident
        type heading, based on the attack category.
        """
        if "SSH" in incident_type:
            return "ssh"
        elif "Scan" in incident_type:
            return "scan"
        elif "NetBIOS" in incident_type:
            return "netbios"
        elif "SMB" in incident_type:
            return "smb"
        elif "ICMP" in incident_type:
            return "icmp"
        return ""  # No badge colour for unrecognised types

    # ------------------------------------------------------------------
    # Main generation method
    # ------------------------------------------------------------------

    def generate(self, incidents: List[Dict[str, Any]],
                 output_file: str = "reports/security_report.html"):
        """
        Generates a styled HTML report from the provided incident list.

        Args:
            incidents:   List of incident dictionaries (from LogAnalyzer).
            output_file: Destination path for the HTML file.
        """
        # Ensure the output directory exists
        output_dir = os.path.dirname(os.path.abspath(output_file))
        os.makedirs(output_dir, exist_ok=True)

        # --- Compute summary statistics ---
        total_incidents = len(incidents)
        unique_types   = set(inc['type']   for inc in incidents)
        unique_sources = set(inc['src_ip'] for inc in incidents)

        # Group incidents by type for sectioned rendering
        by_type: Dict[str, List[Dict[str, Any]]] = {}
        for inc in incidents:
            by_type.setdefault(inc['type'], []).append(inc)

        # --- Build HTML string ---
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - Firewall Log Analyzer</title>
    {self.css}
</head>
<body>

    <!-- ===== Header banner ===== -->
    <div class="header">
        <div class="header-content">
            <div class="header-logo">
                <img src="../images/Logo_Log_Analyzer.jpg" alt="Firewall Log Analyzer Logo">
            </div>
            <div class="header-text">
                <h1>
                    <span class="header-title-main">Security Incident</span>
                    <span class="header-title-sub">Report</span>
                </h1>
                <div class="header-meta">
                    <div class="meta-item">
                        <!-- Clock icon -->
                        <svg class="meta-icon" viewBox="0 0 24 24" width="18" height="18">
                            <path fill="currentColor" d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10
                             10-4.5 10-10S17.5 2 12 2zm0 18c-4.4 0-8-3.6-8-8s3.6-8
                             8-8 8 3.6 8 8-3.6 8-8 8zm.5-13H11v6l5.2 3.1.8-1.2-4.5-2.7V7z"/>
                        </svg>
                        <span>{datetime.now().strftime('%d/%m/%Y · %H:%M:%S')}</span>
                        <span class="meta-credit">developed by Mariana Passos</span>
                    </div>
                </div>
            </div>
        </div>
        <!-- Purely decorative background shapes -->
        <div class="header-decoration">
            <div class="decoration-circle"></div>
            <div class="decoration-circle"></div>
            <div class="decoration-circle"></div>
        </div>
    </div>

    <!-- ===== Summary statistics cards ===== -->
    <div class="stats">
        <div class="stat-card">
            <div class="stat-number">{total_incidents}</div>
            <div class="stat-label">Total Incidents</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{len(unique_types)}</div>
            <div class="stat-label">Attack Types</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{len(unique_sources)}</div>
            <div class="stat-label">Offending IPs</div>
        </div>
    </div>

    <h2>Detected Incidents</h2>
"""

        # --- Render incidents grouped by type ---
        for inc_type, type_incidents in by_type.items():
            severity    = self._get_severity(inc_type)
            badge_class = self._get_badge_class(inc_type)

            # Section heading with a count badge
            html += f"""
    <h3>{inc_type} <span class="badge {badge_class}">{len(type_incidents)}</span></h3>
"""
            # One card per incident
            for inc in type_incidents:
                html += f"""
    <div class="incident {severity}">
        <div class="incident-header">
            <span class="incident-type">{inc['type']}</span>
            <span class="incident-time">{inc['timestamp']}</span>
        </div>

        <!-- Key fields displayed in a responsive grid -->
        <div class="incident-details">
            <div class="detail-item">
                <span class="detail-label">Source IP:</span> {inc['src_ip']}
            </div>
            <div class="detail-item">
                <span class="detail-label">Destination IP:</span> {inc['dst_ip']}
            </div>
            <div class="detail-item">
                <span class="detail-label">Protocol:</span> {inc['protocol']}
            </div>
            <div class="detail-item">
                <span class="detail-label">Description:</span> {inc['description']}
            </div>
            <div class="detail-item">
                <span class="detail-label">Details:</span> {inc['details']}
            </div>
        </div>

        <!-- Recommended mitigation steps -->
        <div class="mitigation">
            <h4>Mitigation Methodology</h4>
            <ul>
                <li><strong>Prevention:</strong> {inc['mitigation_prevention']}</li>
                <li><strong>Detection:</strong>  {inc['mitigation_detection']}</li>
                <li><strong>Response:</strong>   {inc['mitigation_response']}</li>
            </ul>
        </div>
    </div>
"""

        # --- Footer ---
        html += f"""
    <div class="footer">
        <p>Report generated by Firewall Log Analyzer — Python Cybersecurity Project</p>
        <p>This report contains {total_incidents} incident(s) detected during analysis.</p>
        <p>Developed by Mariana Passos.</p>
    </div>

</body>
</html>
"""

        # Write to disk
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

        print(f"[OK] HTML report generated: {output_file}")
        return output_file